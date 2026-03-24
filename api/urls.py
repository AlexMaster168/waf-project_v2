from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    HTTPRequestViewSet, DetectedAttackViewSet, FirewallExceptionViewSet,
    AlertViewSet, WAFRuleViewSet, IPReputationViewSet, MLModelMetricsViewSet,
    stats, analyze,
)

router = DefaultRouter()
router.register('requests',    HTTPRequestViewSet)
router.register('attacks',     DetectedAttackViewSet)
router.register('exceptions',  FirewallExceptionViewSet)
router.register('alerts',      AlertViewSet)
router.register('rules',       WAFRuleViewSet)
router.register('ip',          IPReputationViewSet)
router.register('ml-models',   MLModelMetricsViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('stats/', stats,   name='api-stats'),
    path('analyze/', analyze, name='api-analyze'),
    path('auth/', include('rest_framework.urls')),
]
