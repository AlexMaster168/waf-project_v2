import logging
from collections import defaultdict
from datetime import timedelta
from django.conf import settings
from django.utils import timezone
from django.core.mail import send_mail

logger = logging.getLogger('waf_core')

_alert_window = defaultdict(list)


def check_and_fire(ip, attack_type_code, request_obj=None):
    cfg = settings.WAF_CONFIG
    if not cfg.get('ALERT_ON_ATTACK', True):
        return

    window_sec = cfg.get('ALERT_WINDOW_SECONDS', 300)
    threshold = cfg.get('ALERT_THRESHOLD_COUNT', 5)

    now = timezone.now()
    key = f'{ip}:{attack_type_code}'
    cutoff = now.timestamp() - window_sec
    _alert_window[key] = [t for t in _alert_window[key] if t > cutoff]
    _alert_window[key].append(now.timestamp())
    count = len(_alert_window[key])

    _create_single_alert(ip, attack_type_code, request_obj)

    if count == threshold:
        _create_burst_alert(ip, attack_type_code, count, window_sec, request_obj)


def _create_single_alert(ip, attack_type_code, request_obj=None):
    from .models import Alert, AttackType
    try:
        atype = AttackType.objects.filter(code=attack_type_code).first()
        severity_map = {'critical': 'critical', 'high': 'warning', 'medium': 'warning', 'low': 'info'}
        level = severity_map.get(atype.severity if atype else 'high', 'warning')
        title = f'Виявлено атаку {attack_type_code.upper()} з IP {ip}'
        message = (
            f'WAF заблокував запит від {ip}.\n'
            f'Тип атаки: {attack_type_code.upper()}\n'
            f'Час: {timezone.now().strftime("%Y-%m-%d %H:%M:%S")}'
        )
        alert = Alert.objects.create(
            level=level,
            title=title,
            message=message,
            client_ip=ip,
            attack_type=atype,
            request=request_obj,
        )
        logger.info(f'Alert created: {title}')
        return alert
    except Exception as e:
        logger.error(f'Failed to create alert: {e}')
        return None


def _create_burst_alert(ip, attack_type_code, count, window_sec, request_obj=None):
    from .models import Alert, AttackType
    try:
        atype = AttackType.objects.filter(code=attack_type_code).first()
        title = f'BURST: {count} атак {attack_type_code.upper()} з IP {ip} за {window_sec}с'
        message = (
            f'Виявлено серію атак!\n'
            f'IP: {ip}\n'
            f'Тип: {attack_type_code.upper()}\n'
            f'Кількість: {count} за {window_sec} секунд\n'
            f'Час: {timezone.now().strftime("%Y-%m-%d %H:%M:%S")}\n'
            f'Рекомендація: заблокувати IP автоматично.'
        )
        alert = Alert.objects.create(
            level='critical',
            title=title,
            message=message,
            client_ip=ip,
            attack_type=atype,
            request=request_obj,
            attack_count=count,
        )
        _send_email_alert(alert)
        return alert
    except Exception as e:
        logger.error(f'Failed to create burst alert: {e}')
        return None


def _send_email_alert(alert):
    to_email = settings.ALERT_EMAIL_TO
    if not to_email or not settings.EMAIL_HOST_USER:
        return
    try:
        send_mail(
            subject=f'[WAF ALERT] {alert.title}',
            message=alert.message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[to_email],
            fail_silently=True,
        )
        alert.email_sent = True
        alert.save(update_fields=['email_sent'])
        logger.info(f'Alert email sent to {to_email}')
    except Exception as e:
        logger.error(f'Failed to send alert email: {e}')


def create_rate_limit_alert(ip, count):
    from .models import Alert
    try:
        title = f'Rate limit перевищено: {ip} ({count} req/min)'
        message = (
            f'IP {ip} перевищив ліміт запитів.\n'
            f'Кількість: {count} за хвилину.\n'
            f'Час: {timezone.now().strftime("%Y-%m-%d %H:%M:%S")}'
        )
        Alert.objects.create(
            level='warning',
            title=title,
            message=message,
            client_ip=ip,
            attack_count=count,
        )
    except Exception as e:
        logger.error(f'Failed to create rate limit alert: {e}')
