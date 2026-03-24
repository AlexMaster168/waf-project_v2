from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class AttackType(models.Model):
    SEVERITY_CHOICES = [
        ('low', 'Низька'), ('medium', 'Середня'),
        ('high', 'Висока'), ('critical', 'Критична'),
    ]
    code = models.CharField(max_length=50, unique=True)
    name = models.CharField(max_length=100)
    description = models.TextField()
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    cve_references = models.JSONField(default=list)

    class Meta:
        verbose_name = 'Тип атаки'
        verbose_name_plural = 'Типи атак'

    def __str__(self):
        return f'{self.code} ({self.severity})'


class HTTPRequest(models.Model):
    METHOD_CHOICES = [
        ('GET', 'GET'), ('POST', 'POST'), ('PUT', 'PUT'),
        ('DELETE', 'DELETE'), ('PATCH', 'PATCH'),
        ('HEAD', 'HEAD'), ('OPTIONS', 'OPTIONS'),
    ]
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    method = models.CharField(max_length=10, choices=METHOD_CHOICES)
    path = models.TextField()
    query_string = models.TextField(blank=True)
    headers = models.JSONField(default=dict)
    body = models.TextField(blank=True)
    client_ip = models.GenericIPAddressField(db_index=True)
    user_agent = models.TextField(blank=True)
    content_type = models.CharField(max_length=255, blank=True)
    content_length = models.IntegerField(default=0)
    is_blocked = models.BooleanField(default=False, db_index=True)
    block_reason = models.CharField(max_length=100, blank=True)
    response_status = models.IntegerField(null=True, blank=True)
    processing_time_ms = models.FloatField(default=0)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'HTTP запит'
        verbose_name_plural = 'HTTP запити'
        indexes = [
            models.Index(fields=['-timestamp', 'is_blocked']),
            models.Index(fields=['client_ip', '-timestamp']),
        ]

    def __str__(self):
        return f'{self.method} {self.path[:50]} [{self.client_ip}] {"BLOCKED" if self.is_blocked else "OK"}'


class DetectedAttack(models.Model):
    request = models.ForeignKey(HTTPRequest, on_delete=models.CASCADE, related_name='attacks')
    attack_type = models.ForeignKey(AttackType, on_delete=models.CASCADE)
    confidence_score = models.FloatField()
    detected_payload = models.TextField()
    detection_method = models.CharField(max_length=50)
    timestamp = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Виявлена атака'
        verbose_name_plural = 'Виявлені атаки'
        indexes = [models.Index(fields=['-timestamp', 'attack_type'])]

    def __str__(self):
        return f'{self.attack_type.code} @ {self.request.path[:40]} score={self.confidence_score:.2f}'


class FirewallException(models.Model):
    TYPE_CHOICES = [
        ('ip_whitelist', 'Дозволений IP'),
        ('ip_blacklist', 'Заблокований IP'),
        ('path_whitelist', 'Дозволений шлях'),
        ('path_blacklist', 'Заблокований шлях'),
        ('ua_whitelist', 'Дозволений User-Agent'),
        ('ua_blacklist', 'Заблокований User-Agent'),
        ('cidr_whitelist', 'Дозволена підмережа CIDR'),
        ('cidr_blacklist', 'Заблокована підмережа CIDR'),
    ]
    exception_type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    value = models.CharField(max_length=500)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    hit_count = models.IntegerField(default=0)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Виняток файрволу'
        verbose_name_plural = 'Винятки файрволу'

    def __str__(self):
        return f'{self.get_exception_type_display()}: {self.value}'

    def is_expired(self):
        if self.expires_at:
            return timezone.now() > self.expires_at
        return False


class Alert(models.Model):
    LEVEL_CHOICES = [
        ('info', 'Інформація'),
        ('warning', 'Попередження'),
        ('critical', 'Критичний'),
    ]
    STATUS_CHOICES = [
        ('new', 'Нове'),
        ('acknowledged', 'Прочитано'),
        ('resolved', 'Вирішено'),
    ]
    level = models.CharField(max_length=10, choices=LEVEL_CHOICES, default='warning')
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='new')
    title = models.CharField(max_length=200)
    message = models.TextField()
    client_ip = models.GenericIPAddressField(null=True, blank=True)
    attack_type = models.ForeignKey(AttackType, on_delete=models.SET_NULL, null=True, blank=True)
    request = models.ForeignKey(HTTPRequest, on_delete=models.SET_NULL, null=True, blank=True)
    attack_count = models.IntegerField(default=1)
    email_sent = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    acknowledged_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Алерт'
        verbose_name_plural = 'Алерти'
        indexes = [models.Index(fields=['-created_at', 'status'])]

    def __str__(self):
        return f'[{self.level.upper()}] {self.title}'


class WAFRule(models.Model):
    RULE_TYPE_CHOICES = [
        ('regex', 'Регулярний вираз'),
        ('ml', 'Машинне навчання'),
        ('ip_blacklist', 'Чорний список IP'),
        ('rate_limit', 'Обмеження швидкості'),
        ('signature', 'Сигнатура'),
    ]
    name = models.CharField(max_length=100)
    rule_type = models.CharField(max_length=20, choices=RULE_TYPE_CHOICES)
    attack_type = models.ForeignKey(AttackType, on_delete=models.SET_NULL, null=True, blank=True)
    pattern = models.TextField()
    priority = models.IntegerField(default=100)
    is_active = models.BooleanField(default=True)
    false_positive_rate = models.FloatField(default=0.0)
    true_positive_rate = models.FloatField(default=0.0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['priority']
        verbose_name = 'Правило WAF'
        verbose_name_plural = 'Правила WAF'

    def __str__(self):
        return f'{self.name} ({self.rule_type})'


class IPReputation(models.Model):
    STATUS_CHOICES = [
        ('clean', 'Чистий'), ('suspicious', 'Підозрілий'),
        ('blocked', 'Заблокований'), ('whitelisted', 'Дозволений'),
    ]
    ip_address = models.GenericIPAddressField(unique=True, db_index=True)
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='clean')
    request_count = models.IntegerField(default=0)
    attack_count = models.IntegerField(default=0)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    country_code = models.CharField(max_length=2, blank=True)
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ['-attack_count']
        verbose_name = 'IP репутація'
        verbose_name_plural = 'IP репутація'

    def __str__(self):
        return f'{self.ip_address} [{self.status}] attacks={self.attack_count}'


class MLModelMetrics(models.Model):
    model_name = models.CharField(max_length=100)
    version = models.CharField(max_length=20)
    attack_type = models.CharField(max_length=50)
    accuracy = models.FloatField()
    precision = models.FloatField()
    recall = models.FloatField()
    f1_score = models.FloatField()
    auc_roc = models.FloatField()
    training_samples = models.IntegerField()
    test_samples = models.IntegerField()
    trained_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=False)
    model_path = models.CharField(max_length=255)
    hyperparameters = models.JSONField(default=dict)
    confusion_matrix = models.JSONField(default=dict)
    feature_importance = models.JSONField(default=dict)

    class Meta:
        ordering = ['-trained_at']
        verbose_name = 'Метрики ML моделі'
        verbose_name_plural = 'Метрики ML моделей'
        unique_together = ['model_name', 'version', 'attack_type']

    def __str__(self):
        return f'{self.model_name} [{self.attack_type}] F1={self.f1_score:.3f}'
