from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count

from waf_core.models import (
    HTTPRequest, DetectedAttack, FirewallException,
    Alert, IPReputation, MLModelMetrics, AttackType,
)


@login_required
def index(request):
    now = timezone.now()
    h24 = now - timedelta(hours=24)
    new_alerts = Alert.objects.filter(status='new').order_by('-created_at')[:5]
    context = {
        'total_requests': HTTPRequest.objects.filter(timestamp__gte=h24).count(),
        'blocked_requests': HTTPRequest.objects.filter(timestamp__gte=h24, is_blocked=True).count(),
        'total_attacks': DetectedAttack.objects.filter(timestamp__gte=h24).count(),
        'unique_attackers': IPReputation.objects.filter(attack_count__gt=0).count(),
        'new_alerts_count': Alert.objects.filter(status='new').count(),
        'recent_attacks': DetectedAttack.objects.select_related('request', 'attack_type').order_by('-timestamp')[:10],
        'top_ips': IPReputation.objects.order_by('-attack_count')[:5],
        'ml_models': MLModelMetrics.objects.filter(is_active=True).order_by('attack_type'),
        'new_alerts': new_alerts,
    }
    return render(request, 'dashboard/index.html', context)


@login_required
def requests_view(request):
    if request.method == 'POST':
        if request.POST.get('action') == 'clear':
            HTTPRequest.objects.all().delete()
            messages.success(request, 'Всі HTTP запити очищено.')
            return redirect(request.path)

    qs = HTTPRequest.objects.order_by('-timestamp')
    f = request.GET.get('is_blocked')
    if f == 'true':
        qs = qs.filter(is_blocked=True)
    elif f == 'false':
        qs = qs.filter(is_blocked=False)
    return render(request, 'dashboard/requests.html', {'requests': qs[:200], 'filter': f})


@login_required
def attacks_view(request):
    if request.method == 'POST':
        if request.POST.get('action') == 'clear':
            DetectedAttack.objects.all().delete()
            messages.success(request, 'Всі атаки очищено.')
            return redirect(request.path)

    qs = DetectedAttack.objects.select_related('request', 'attack_type').order_by('-timestamp')
    sel = request.GET.get('type')
    if sel:
        qs = qs.filter(attack_type__code=sel)
    return render(request, 'dashboard/attacks.html', {
        'attacks': qs[:200],
        'attack_types': AttackType.objects.all(),
        'selected': sel,
    })


@login_required
def ml_view(request):
    if request.method == 'POST':
        if request.POST.get('action') == 'clear':
            MLModelMetrics.objects.all().delete()
            messages.success(request, 'Метрики моделей очищено.')
            return redirect(request.path)

    return render(request, 'dashboard/ml.html', {
        'metrics': MLModelMetrics.objects.all().order_by('attack_type', '-f1_score'),
    })


@login_required
def ip_view(request):
    if request.method == 'POST':
        if request.POST.get('action') == 'clear':
            IPReputation.objects.all().delete()
            messages.success(request, 'IP репутацію очищено.')
            return redirect(request.path)

    return render(request, 'dashboard/ip.html', {
        'ips': IPReputation.objects.order_by('-attack_count'),
    })


@login_required
def exceptions_view(request):
    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'clear':
            FirewallException.objects.all().delete()
            from waf_core import exceptions_cache
            exceptions_cache.reload()
            messages.success(request, 'Всі винятки очищено.')
            return redirect(request.path)

        elif action == 'create':
            exc_type = request.POST.get('exception_type')
            value = request.POST.get('value', '').strip()
            desc = request.POST.get('description', '').strip()
            expires_raw = request.POST.get('expires_at', '').strip()
            if not exc_type or not value:
                messages.error(request, 'Тип та значення обовʼязкові.')
            else:
                expires_at = None
                if expires_raw:
                    try:
                        from datetime import datetime
                        expires_at = timezone.make_aware(datetime.strptime(expires_raw, '%Y-%m-%dT%H:%M'))
                    except ValueError:
                        messages.warning(request, 'Некоректний формат дати. Виняток створено без терміну дії.')
                FirewallException.objects.create(
                    exception_type=exc_type,
                    value=value,
                    description=desc,
                    is_active=True,
                    created_by=request.user,
                    expires_at=expires_at,
                )
                from waf_core import exceptions_cache
                exceptions_cache.reload()
                messages.success(request, f'Виняток "{value}" ({exc_type}) створено.')
            return redirect('exceptions')

        elif action == 'delete':
            exc_id = request.POST.get('exc_id')
            exc = get_object_or_404(FirewallException, id=exc_id)
            exc.delete()
            from waf_core import exceptions_cache
            exceptions_cache.reload()
            messages.success(request, 'Виняток видалено.')
            return redirect('exceptions')

        elif action == 'toggle':
            exc_id = request.POST.get('exc_id')
            exc = get_object_or_404(FirewallException, id=exc_id)
            exc.is_active = not exc.is_active
            exc.save()
            from waf_core import exceptions_cache
            exceptions_cache.reload()
            return redirect('exceptions')

    TYPE_CHOICES = FirewallException.TYPE_CHOICES
    exc_filter = request.GET.get('type', '')
    qs = FirewallException.objects.all()
    if exc_filter:
        qs = qs.filter(exception_type=exc_filter)
    return render(request, 'dashboard/exceptions.html', {
        'exceptions': qs.order_by('-created_at'),
        'type_choices': TYPE_CHOICES,
        'exc_filter': exc_filter,
    })


@login_required
def alerts_view(request):
    if request.method == 'POST':
        action = request.POST.get('action')
        alert_id = request.POST.get('alert_id')

        if action == 'clear':
            Alert.objects.all().delete()
            messages.success(request, 'Всі алерти очищено.')
            return redirect(request.path)

        elif action == 'acknowledge' and alert_id:
            alert = get_object_or_404(Alert, id=alert_id)
            alert.status = 'acknowledged'
            alert.acknowledged_at = timezone.now()
            alert.acknowledged_by = request.user
            alert.save()
            messages.success(request, 'Алерт позначено як прочитаний.')
        elif action == 'resolve' and alert_id:
            alert = get_object_or_404(Alert, id=alert_id)
            alert.status = 'resolved'
            alert.acknowledged_at = timezone.now()
            alert.acknowledged_by = request.user
            alert.save()
            messages.success(request, 'Алерт вирішено.')
        elif action == 'acknowledge_all':
            Alert.objects.filter(status='new').update(
                status='acknowledged',
                acknowledged_at=timezone.now(),
                acknowledged_by=request.user,
            )
            messages.success(request, 'Всі алерти позначено як прочитані.')
        return redirect('alerts')

    status_filter = request.GET.get('status', '')
    level_filter = request.GET.get('level', '')
    qs = Alert.objects.select_related('attack_type').order_by('-created_at')
    if status_filter:
        qs = qs.filter(status=status_filter)
    if level_filter:
        qs = qs.filter(level=level_filter)
    return render(request, 'dashboard/alerts.html', {
        'alerts': qs[:200],
        'status_filter': status_filter,
        'level_filter': level_filter,
        'new_count': Alert.objects.filter(status='new').count(),
    })
