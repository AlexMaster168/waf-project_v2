from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AttackType',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('code', models.CharField(max_length=50, unique=True)),
                ('name', models.CharField(max_length=100)),
                ('description', models.TextField()),
                ('severity', models.CharField(choices=[('low', 'Низька'), ('medium', 'Середня'), ('high', 'Висока'), ('critical', 'Критична')], max_length=10)),
                ('cve_references', models.JSONField(default=list)),
            ],
            options={'verbose_name': 'Тип атаки', 'verbose_name_plural': 'Типи атак'},
        ),
        migrations.CreateModel(
            name='HTTPRequest',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ('method', models.CharField(choices=[('GET', 'GET'), ('POST', 'POST'), ('PUT', 'PUT'), ('DELETE', 'DELETE'), ('PATCH', 'PATCH'), ('HEAD', 'HEAD'), ('OPTIONS', 'OPTIONS')], max_length=10)),
                ('path', models.TextField()),
                ('query_string', models.TextField(blank=True)),
                ('headers', models.JSONField(default=dict)),
                ('body', models.TextField(blank=True)),
                ('client_ip', models.GenericIPAddressField(db_index=True)),
                ('user_agent', models.TextField(blank=True)),
                ('content_type', models.CharField(blank=True, max_length=255)),
                ('content_length', models.IntegerField(default=0)),
                ('is_blocked', models.BooleanField(db_index=True, default=False)),
                ('block_reason', models.CharField(blank=True, max_length=100)),
                ('response_status', models.IntegerField(blank=True, null=True)),
                ('processing_time_ms', models.FloatField(default=0)),
            ],
            options={'ordering': ['-timestamp'], 'verbose_name': 'HTTP запит', 'verbose_name_plural': 'HTTP запити'},
        ),
        migrations.CreateModel(
            name='IPReputation',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip_address', models.GenericIPAddressField(db_index=True, unique=True)),
                ('status', models.CharField(choices=[('clean', 'Чистий'), ('suspicious', 'Підозрілий'), ('blocked', 'Заблокований'), ('whitelisted', 'Дозволений')], default='clean', max_length=15)),
                ('request_count', models.IntegerField(default=0)),
                ('attack_count', models.IntegerField(default=0)),
                ('first_seen', models.DateTimeField(auto_now_add=True)),
                ('last_seen', models.DateTimeField(auto_now=True)),
                ('country_code', models.CharField(blank=True, max_length=2)),
                ('notes', models.TextField(blank=True)),
            ],
            options={'ordering': ['-attack_count'], 'verbose_name': 'IP репутація', 'verbose_name_plural': 'IP репутація'},
        ),
        migrations.CreateModel(
            name='MLModelMetrics',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('model_name', models.CharField(max_length=100)),
                ('version', models.CharField(max_length=20)),
                ('attack_type', models.CharField(max_length=50)),
                ('accuracy', models.FloatField()),
                ('precision', models.FloatField()),
                ('recall', models.FloatField()),
                ('f1_score', models.FloatField()),
                ('auc_roc', models.FloatField()),
                ('training_samples', models.IntegerField()),
                ('test_samples', models.IntegerField()),
                ('trained_at', models.DateTimeField(auto_now_add=True)),
                ('is_active', models.BooleanField(default=False)),
                ('model_path', models.CharField(max_length=255)),
                ('hyperparameters', models.JSONField(default=dict)),
                ('confusion_matrix', models.JSONField(default=dict)),
                ('feature_importance', models.JSONField(default=dict)),
            ],
            options={'ordering': ['-trained_at'], 'verbose_name': 'Метрики ML моделі', 'verbose_name_plural': 'Метрики ML моделей'},
        ),
        migrations.CreateModel(
            name='WAFRule',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('rule_type', models.CharField(choices=[('regex', 'Регулярний вираз'), ('ml', 'Машинне навчання'), ('ip_blacklist', 'Чорний список IP'), ('rate_limit', 'Обмеження швидкості'), ('signature', 'Сигнатура')], max_length=20)),
                ('pattern', models.TextField()),
                ('priority', models.IntegerField(default=100)),
                ('is_active', models.BooleanField(default=True)),
                ('false_positive_rate', models.FloatField(default=0.0)),
                ('true_positive_rate', models.FloatField(default=0.0)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('attack_type', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='waf_core.attacktype')),
            ],
            options={'ordering': ['priority'], 'verbose_name': 'Правило WAF', 'verbose_name_plural': 'Правила WAF'},
        ),
        migrations.CreateModel(
            name='FirewallException',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('exception_type', models.CharField(choices=[('ip_whitelist', 'Дозволений IP'), ('ip_blacklist', 'Заблокований IP'), ('path_whitelist', 'Дозволений шлях'), ('path_blacklist', 'Заблокований шлях'), ('ua_whitelist', 'Дозволений User-Agent'), ('ua_blacklist', 'Заблокований User-Agent'), ('cidr_whitelist', 'Дозволена підмережа CIDR'), ('cidr_blacklist', 'Заблокована підмережа CIDR')], max_length=20)),
                ('value', models.CharField(max_length=500)),
                ('description', models.TextField(blank=True)),
                ('is_active', models.BooleanField(default=True)),
                ('expires_at', models.DateTimeField(blank=True, null=True)),
                ('hit_count', models.IntegerField(default=0)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
            options={'ordering': ['-created_at'], 'verbose_name': 'Виняток файрволу', 'verbose_name_plural': 'Винятки файрволу'},
        ),
        migrations.CreateModel(
            name='DetectedAttack',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('confidence_score', models.FloatField()),
                ('detected_payload', models.TextField()),
                ('detection_method', models.CharField(max_length=50)),
                ('timestamp', models.DateTimeField(default=django.utils.timezone.now)),
                ('attack_type', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='waf_core.attacktype')),
                ('request', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='attacks', to='waf_core.httprequest')),
            ],
            options={'ordering': ['-timestamp'], 'verbose_name': 'Виявлена атака', 'verbose_name_plural': 'Виявлені атаки'},
        ),
        migrations.CreateModel(
            name='Alert',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('level', models.CharField(choices=[('info', 'Інформація'), ('warning', 'Попередження'), ('critical', 'Критичний')], default='warning', max_length=10)),
                ('status', models.CharField(choices=[('new', 'Нове'), ('acknowledged', 'Прочитано'), ('resolved', 'Вирішено')], default='new', max_length=15)),
                ('title', models.CharField(max_length=200)),
                ('message', models.TextField()),
                ('client_ip', models.GenericIPAddressField(blank=True, null=True)),
                ('attack_count', models.IntegerField(default=1)),
                ('email_sent', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('acknowledged_at', models.DateTimeField(blank=True, null=True)),
                ('attack_type', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='waf_core.attacktype')),
                ('request', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='waf_core.httprequest')),
                ('acknowledged_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='acknowledged_alerts', to=settings.AUTH_USER_MODEL)),
            ],
            options={'ordering': ['-created_at'], 'verbose_name': 'Алерт', 'verbose_name_plural': 'Алерти'},
        ),
        migrations.AddIndex(
            model_name='httprequest',
            index=models.Index(fields=['-timestamp', 'is_blocked'], name='waf_core_ht_timesta_idx'),
        ),
        migrations.AddIndex(
            model_name='httprequest',
            index=models.Index(fields=['client_ip', '-timestamp'], name='waf_core_ht_client__idx'),
        ),
        migrations.AddIndex(
            model_name='detectedattack',
            index=models.Index(fields=['-timestamp', 'attack_type'], name='waf_core_de_timesta_idx'),
        ),
        migrations.AddIndex(
            model_name='alert',
            index=models.Index(fields=['-created_at', 'status'], name='waf_core_al_created_idx'),
        ),
        migrations.AlterUniqueTogether(
            name='mlmodelmetrics',
            unique_together={('model_name', 'version', 'attack_type')},
        ),
    ]
