import time
import logging
from collections import defaultdict
from django.conf import settings
from django.http import HttpResponse, JsonResponse
from .features import extract_features
from .predictor import MLPredictor

logger = logging.getLogger('waf_core')

_rate_store = defaultdict(list)
_predictor = MLPredictor()


class WAFMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        cfg = settings.WAF_CONFIG
        self.enabled = cfg['ENABLED']
        self.block_mode = cfg['BLOCK_MODE']
        self.threshold = cfg['ML_THRESHOLD']
        self.rate_limit = cfg['RATE_LIMIT_REQUESTS']
        self.rate_window = cfg['RATE_LIMIT_WINDOW']
        self.whitelist = set(cfg['WHITELIST_IPS'])
        self.excluded = cfg['EXCLUDED_PATHS']

    def __call__(self, request):
        if not self.enabled:
            return self.get_response(request)

        for exc in self.excluded:
            if request.path.startswith(exc):
                return self.get_response(request)

        ip = self._get_ip(request)
        ua = request.META.get('HTTP_USER_AGENT', '')

        if ip in self.whitelist:
            return self.get_response(request)

        from . import exceptions_cache as ec
        if ec.is_ip_whitelisted(ip):
            return self.get_response(request)
        if ec.is_path_whitelisted(request.path):
            return self.get_response(request)
        if ua and ec.is_ua_whitelisted(ua):
            return self.get_response(request)

        t0 = time.time()
        reason, score = self._inspect(request, ip, ua)
        ms = (time.time() - t0) * 1000

        if reason and self.block_mode:
            req_obj = self._save_request(request, ip, True, reason, ms)
            if reason.startswith('ml_'):
                attack_code = reason[3:]
                self._save_attack(req_obj, attack_code, score, request)
                from .alerts import check_and_fire
                check_and_fire(ip, attack_code, req_obj)
            return self._block_response(request, reason)

        resp = self.get_response(request)
        self._save_request(request, ip, False, '', ms, resp.status_code)
        return resp

    def _inspect(self, request, ip, ua):
        count = self._rate_count(ip)
        if count > self.rate_limit:
            from .alerts import create_rate_limit_alert
            create_rate_limit_alert(ip, count)
            return 'rate_limit', 1.0

        from . import exceptions_cache as ec
        if ec.is_ip_blacklisted(ip):
            return 'ip_blacklist', 1.0
        if ec.is_path_blacklisted(request.path):
            return 'path_blacklist', 1.0
        if ua and ec.is_ua_blacklisted(ua):
            return 'ua_blacklist', 1.0

        from .models import IPReputation
        try:
            if IPReputation.objects.get(ip_address=ip).status == 'blocked':
                return 'ip_reputation', 1.0
        except IPReputation.DoesNotExist:
            pass

        try:
            body = request.body.decode('utf-8', errors='ignore')
        except Exception:
            body = ''

        headers = {k: v for k, v in request.META.items() if k.startswith('HTTP_') or k == 'CONTENT_TYPE'}
        feats = extract_features(
            method=request.method,
            path=request.path,
            query_string=request.META.get('QUERY_STRING', ''),
            headers=headers,
            body=body,
            client_ip=ip,
        )

        try:
            scores = _predictor.predict(feats)
            best_type, best_score = None, 0.0
            for atype, s in scores.items():
                if s >= self.threshold and s > best_score:
                    best_score = s
                    best_type = atype
            if best_type:
                logger.warning(f'ML [{best_type}] score={best_score:.3f} ip={ip} path={request.path}')
                return f'ml_{best_type}', best_score
        except Exception as e:
            logger.error(f'Prediction error: {e}')

        return None, 0.0

    def _rate_count(self, ip):
        now = time.time()
        cutoff = now - self.rate_window
        _rate_store[ip] = [t for t in _rate_store[ip] if t > cutoff]
        _rate_store[ip].append(now)
        return len(_rate_store[ip])

    def _get_ip(self, request):
        xff = request.META.get('HTTP_X_FORWARDED_FOR')
        if xff:
            return xff.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '0.0.0.0')

    def _block_response(self, request, reason):
        if 'application/json' in request.META.get('HTTP_ACCEPT', ''):
            return JsonResponse({'error': 'Forbidden', 'reason': reason}, status=403)
        return HttpResponse(
            f'<html><body><h1>403 Forbidden</h1><p>WAF заблокував запит: {reason}</p></body></html>',
            status=403,
            content_type='text/html',
        )

    def _save_attack(self, req_obj, attack_code, score, request):
        from .models import DetectedAttack, AttackType
        try:
            atype = AttackType.objects.get(code=attack_code)
            payload = request.META.get('QUERY_STRING', '')
            if request.method == 'POST':
                try:
                    payload = request.body.decode('utf-8', errors='ignore')
                except Exception:
                    pass
            DetectedAttack.objects.create(
                request=req_obj,
                attack_type=atype,
                confidence_score=score,
                detected_payload=payload[:1000] or request.path[:1000],
                detection_method='Machine Learning',
            )
        except Exception as e:
            logger.error(f'Failed to save DetectedAttack: {e}')

    def _save_request(self, request, ip, blocked, reason, ms, status_code=None):
        from .models import HTTPRequest, IPReputation
        try:
            body = request.body.decode('utf-8', errors='ignore')[:2000]
        except Exception:
            body = ''
        headers = dict(list({k: v for k, v in request.META.items() if k.startswith('HTTP_')}.items())[:20])
        req_obj = HTTPRequest.objects.create(
            method=request.method,
            path=request.path[:500],
            query_string=request.META.get('QUERY_STRING', '')[:1000],
            headers=headers,
            body=body,
            client_ip=ip,
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
            content_type=request.META.get('CONTENT_TYPE', '')[:200],
            content_length=request.META.get('CONTENT_LENGTH') or 0,
            is_blocked=blocked,
            block_reason=reason[:100] if reason else '',
            response_status=status_code,
            processing_time_ms=ms,
        )
        rep, _ = IPReputation.objects.get_or_create(ip_address=ip)
        rep.request_count += 1
        if blocked:
            rep.attack_count += 1
            if rep.attack_count >= 10:
                rep.status = 'blocked'
            elif rep.attack_count >= 3:
                rep.status = 'suspicious'
        rep.save()
        return req_obj
