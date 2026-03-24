from django.contrib import admin
from django.utils.html import format_html
from django.utils import timezone
from .models import AttackType, HTTPRequest, DetectedAttack, FirewallException, Alert, WAFRule, IPReputation, MLModelMetrics


@admin.register(AttackType)
class AttackTypeAdmin(admin.ModelAdmin):
    list_display = ['code', 'name', 'severity']
    list_filter = ['severity']
    search_fields = ['code', 'name']


@admin.register(HTTPRequest)
class HTTPRequestAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'method', 'short_path', 'client_ip', 'status_badge', 'processing_time_ms']
    list_filter = ['method', 'is_blocked', 'timestamp']
    search_fields = ['path', 'client_ip']
    readonly_fields = ['timestamp', 'headers', 'body']
    date_hierarchy = 'timestamp'

    @admin.display(description='Path')
    def short_path(self, obj):
        return obj.path[:70] + '...' if len(obj.path) > 70 else obj.path

    @admin.display(description='Status')
    def status_badge(self, obj):
        if obj.is_blocked:
            return format_html('<span style="color:red;font-weight:bold">⛔ BLOCKED</span>')
        return format_html('<span style="color:green">✓ OK</span>')


@admin.register(DetectedAttack)
class DetectedAttackAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'attack_type', 'score_col', 'detection_method', 'request_ip']
    list_filter = ['attack_type', 'detection_method', 'timestamp']
    date_hierarchy = 'timestamp'

    @admin.display(description='Score')
    def score_col(self, obj):
        c = '#c00' if obj.confidence_score >= 0.8 else '#c70' if obj.confidence_score >= 0.6 else '#080'
        return format_html('<span style="color:{};font-weight:bold">{:.1%}</span>', c, obj.confidence_score)

    @admin.display(description='IP')
    def request_ip(self, obj):
        return obj.request.client_ip


@admin.register(FirewallException)
class FirewallExceptionAdmin(admin.ModelAdmin):
    list_display = ['exception_type', 'value', 'is_active', 'hit_count', 'created_at', 'expires_at', 'created_by']
    list_filter = ['exception_type', 'is_active']
    search_fields = ['value', 'description']
    list_editable = ['is_active']
    readonly_fields = ['hit_count', 'created_at', 'updated_at']
    actions = ['activate', 'deactivate']

    @admin.action(description='Активувати')
    def activate(self, request, queryset):
        queryset.update(is_active=True)

    @admin.action(description='Деактивувати')
    def deactivate(self, request, queryset):
        queryset.update(is_active=False)


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ['created_at', 'level_badge', 'title', 'client_ip', 'status', 'email_sent', 'attack_count']
    list_filter = ['level', 'status', 'email_sent', 'created_at']
    search_fields = ['title', 'client_ip', 'message']
    readonly_fields = ['created_at', 'acknowledged_at']
    actions = ['mark_acknowledged', 'mark_resolved']

    @admin.display(description='Level')
    def level_badge(self, obj):
        colors = {'critical': '#c00', 'warning': '#c70', 'info': '#36f'}
        c = colors.get(obj.level, '#999')
        return format_html('<span style="color:{};font-weight:bold">● {}</span>', c, obj.get_level_display())

    @admin.action(description='Позначити як прочитані')
    def mark_acknowledged(self, request, queryset):
        queryset.update(status='acknowledged', acknowledged_at=timezone.now(), acknowledged_by=request.user)

    @admin.action(description='Позначити як вирішені')
    def mark_resolved(self, request, queryset):
        queryset.update(status='resolved', acknowledged_at=timezone.now(), acknowledged_by=request.user)


@admin.register(WAFRule)
class WAFRuleAdmin(admin.ModelAdmin):
    list_display = ['name', 'rule_type', 'attack_type', 'priority', 'is_active']
    list_filter = ['rule_type', 'is_active', 'attack_type']
    list_editable = ['priority', 'is_active']
    search_fields = ['name', 'pattern']


@admin.register(IPReputation)
class IPReputationAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'status_badge', 'request_count', 'attack_count', 'last_seen']
    list_filter = ['status']
    search_fields = ['ip_address']
    readonly_fields = ['first_seen', 'last_seen']
    actions = ['block_ips', 'unblock_ips', 'whitelist_ips']

    @admin.display(description='Status')
    def status_badge(self, obj):
        colors = {'blocked': '#c00', 'suspicious': '#c70', 'clean': '#080', 'whitelisted': '#36f'}
        c = colors.get(obj.status, '#999')
        return format_html('<span style="color:{};font-weight:bold">● {}</span>', c, obj.get_status_display())

    @admin.action(description='Заблокувати')
    def block_ips(self, request, queryset):
        queryset.update(status='blocked')

    @admin.action(description='Розблокувати')
    def unblock_ips(self, request, queryset):
        queryset.update(status='clean')

    @admin.action(description='Додати до whitelist')
    def whitelist_ips(self, request, queryset):
        queryset.update(status='whitelisted')


@admin.register(MLModelMetrics)
class MLModelMetricsAdmin(admin.ModelAdmin):
    list_display = ['model_name', 'attack_type', 'version', 'f1_score', 'auc_roc', 'accuracy', 'is_active', 'trained_at']
    list_filter = ['attack_type', 'model_name', 'is_active']
    readonly_fields = ['trained_at', 'confusion_matrix', 'feature_importance']
