from django.db.models import Count, Avg
from django.utils import timezone
from datetime import timedelta
from rest_framework import viewsets, status
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response

from waf_core.models import (
    HTTPRequest, DetectedAttack, FirewallException, Alert,
    WAFRule, IPReputation, MLModelMetrics,
)
from .serializers import (
    HTTPRequestSerializer, DetectedAttackSerializer,
    FirewallExceptionSerializer, AlertSerializer,
    WAFRuleSerializer, IPReputationSerializer, MLModelMetricsSerializer,
)


class HTTPRequestViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = HTTPRequest.objects.all()
    serializer_class = HTTPRequestSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        p = self.request.query_params
        if p.get('is_blocked') is not None:
            qs = qs.filter(is_blocked=p['is_blocked'].lower() == 'true')
        if p.get('ip'):
            qs = qs.filter(client_ip=p['ip'])
        if p.get('since'):
            qs = qs.filter(timestamp__gte=p['since'])
        return qs


class DetectedAttackViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = DetectedAttack.objects.select_related('request', 'attack_type').all()
    serializer_class = DetectedAttackSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        if self.request.query_params.get('type'):
            qs = qs.filter(attack_type__code=self.request.query_params['type'])
        return qs


class FirewallExceptionViewSet(viewsets.ModelViewSet):
    queryset = FirewallException.objects.all()
    serializer_class = FirewallExceptionSerializer

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)
        from waf_core import exceptions_cache
        exceptions_cache.reload()

    def perform_update(self, serializer):
        serializer.save()
        from waf_core import exceptions_cache
        exceptions_cache.reload()

    def perform_destroy(self, instance):
        instance.delete()
        from waf_core import exceptions_cache
        exceptions_cache.reload()

    @action(detail=True, methods=['post'])
    def toggle(self, request, pk=None):
        exc = self.get_object()
        exc.is_active = not exc.is_active
        exc.save()
        from waf_core import exceptions_cache
        exceptions_cache.reload()
        return Response({'is_active': exc.is_active})

    @action(detail=False, methods=['post'])
    def reload_cache(self, request):
        from waf_core import exceptions_cache
        exceptions_cache.reload()
        return Response({'status': 'cache_reloaded'})


class AlertViewSet(viewsets.ModelViewSet):
    queryset = Alert.objects.all()
    serializer_class = AlertSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        p = self.request.query_params
        if p.get('status'):
            qs = qs.filter(status=p['status'])
        if p.get('level'):
            qs = qs.filter(level=p['level'])
        return qs

    @action(detail=False, methods=['get'])
    def unread_count(self, request):
        count = Alert.objects.filter(status='new').count()
        return Response({'count': count})

    @action(detail=True, methods=['post'])
    def acknowledge(self, request, pk=None):
        alert = self.get_object()
        alert.status = 'acknowledged'
        alert.acknowledged_at = timezone.now()
        alert.acknowledged_by = request.user
        alert.save()
        return Response({'status': 'acknowledged'})

    @action(detail=True, methods=['post'])
    def resolve(self, request, pk=None):
        alert = self.get_object()
        alert.status = 'resolved'
        alert.acknowledged_at = timezone.now()
        alert.acknowledged_by = request.user
        alert.save()
        return Response({'status': 'resolved'})

    @action(detail=False, methods=['post'])
    def acknowledge_all(self, request):
        updated = Alert.objects.filter(status='new').update(
            status='acknowledged',
            acknowledged_at=timezone.now(),
            acknowledged_by=request.user,
        )
        return Response({'updated': updated})


class WAFRuleViewSet(viewsets.ModelViewSet):
    queryset = WAFRule.objects.all()
    serializer_class = WAFRuleSerializer

    @action(detail=True, methods=['post'])
    def toggle(self, request, pk=None):
        rule = self.get_object()
        rule.is_active = not rule.is_active
        rule.save()
        return Response({'is_active': rule.is_active})


class IPReputationViewSet(viewsets.ModelViewSet):
    queryset = IPReputation.objects.all()
    serializer_class = IPReputationSerializer

    @action(detail=False, methods=['get'])
    def top_attackers(self, request):
        top = self.queryset.filter(attack_count__gt=0).order_by('-attack_count')[:20]
        return Response(self.get_serializer(top, many=True).data)

    @action(detail=True, methods=['post'])
    def block(self, request, pk=None):
        obj = self.get_object()
        obj.status = 'blocked'
        obj.save()
        FirewallException.objects.get_or_create(
            exception_type='ip_blacklist', value=obj.ip_address,
            defaults={'description': f'Auto-blocked via IP reputation', 'is_active': True},
        )
        from waf_core import exceptions_cache
        exceptions_cache.reload()
        return Response({'status': 'blocked'})

    @action(detail=True, methods=['post'])
    def unblock(self, request, pk=None):
        obj = self.get_object()
        obj.status = 'clean'
        obj.save()
        FirewallException.objects.filter(
            exception_type='ip_blacklist', value=obj.ip_address
        ).update(is_active=False)
        from waf_core import exceptions_cache
        exceptions_cache.reload()
        return Response({'status': 'clean'})

    @action(detail=True, methods=['post'])
    def whitelist(self, request, pk=None):
        obj = self.get_object()
        obj.status = 'whitelisted'
        obj.save()
        FirewallException.objects.get_or_create(
            exception_type='ip_whitelist', value=obj.ip_address,
            defaults={'description': 'Whitelisted via IP reputation', 'is_active': True},
        )
        from waf_core import exceptions_cache
        exceptions_cache.reload()
        return Response({'status': 'whitelisted'})


class MLModelMetricsViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = MLModelMetrics.objects.all()
    serializer_class = MLModelMetricsSerializer

    @action(detail=False, methods=['get'])
    def best(self, request):
        attack_types = MLModelMetrics.objects.values_list('attack_type', flat=True).distinct()
        best_list = [
            MLModelMetrics.objects.filter(attack_type=at).order_by('-f1_score').first()
            for at in attack_types
        ]
        return Response(self.get_serializer([m for m in best_list if m], many=True).data)

    @action(detail=False, methods=['post'])
    def retrain(self, request):
        from django.core.management import call_command
        try:
            call_command('train_models')
            return Response({'status': 'ok'})
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def stats(request):
    now = timezone.now()
    h24 = now - timedelta(hours=24)
    h1  = now - timedelta(hours=1)

    total_24h   = HTTPRequest.objects.filter(timestamp__gte=h24).count()
    blocked_24h = HTTPRequest.objects.filter(timestamp__gte=h24, is_blocked=True).count()
    total_1h    = HTTPRequest.objects.filter(timestamp__gte=h1).count()
    blocked_1h  = HTTPRequest.objects.filter(timestamp__gte=h1, is_blocked=True).count()
    avg_ms      = HTTPRequest.objects.filter(timestamp__gte=h24).aggregate(v=Avg('processing_time_ms'))['v'] or 0

    attack_dist = list(
        DetectedAttack.objects.filter(timestamp__gte=h24)
        .values('attack_type__code', 'attack_type__name')
        .annotate(count=Count('id')).order_by('-count')
    )

    top_ips = list(
        IPReputation.objects.filter(attack_count__gt=0)
        .order_by('-attack_count')[:10]
        .values('ip_address', 'attack_count', 'status', 'country_code')
    )

    hourly = []
    for i in range(24):
        end   = now - timedelta(hours=i)
        start = now - timedelta(hours=i + 1)
        t = HTTPRequest.objects.filter(timestamp__range=(start, end)).count()
        b = HTTPRequest.objects.filter(timestamp__range=(start, end), is_blocked=True).count()
        hourly.append({'hour': start.strftime('%H:00'), 'total': t, 'blocked': b})
    hourly.reverse()

    new_alerts = Alert.objects.filter(status='new').count()

    return Response({
        'summary': {
            'total_24h': total_24h,
            'blocked_24h': blocked_24h,
            'block_rate_24h': round(blocked_24h / total_24h * 100, 2) if total_24h else 0,
            'total_1h': total_1h,
            'blocked_1h': blocked_1h,
            'avg_ms': round(avg_ms, 2),
            'new_alerts': new_alerts,
        },
        'attack_distribution': attack_dist,
        'top_attackers': top_ips,
        'hourly_traffic': hourly,
    })


@api_view(['POST'])
@permission_classes([AllowAny])
def analyze(request):
    from waf_core.features import extract_features
    from waf_core.predictor import MLPredictor
    d = request.data
    feats = extract_features(
        method=d.get('method', 'GET'),
        path=d.get('path', '/'),
        query_string=d.get('query_string', ''),
        headers=d.get('headers', {}),
        body=d.get('body', ''),
        client_ip=d.get('client_ip', '127.0.0.1'),
    )
    predictor = MLPredictor()
    scores = predictor.predict(feats)
    highest = max(scores.items(), key=lambda x: x[1]) if scores else ('none', 0.0)
    return Response({
        'is_attack': any(v >= 0.72 for v in scores.values()),
        'scores': scores,
        'highest': {'type': highest[0], 'score': highest[1]},
    })
