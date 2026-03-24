import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('waf_core', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.RunSQL(
            "ALTER INDEX IF EXISTS waf_core_al_created_idx RENAME TO waf_core_al_created_755561_idx;",
            state_operations=[
                migrations.RenameIndex(
                    model_name='alert',
                    new_name='waf_core_al_created_755561_idx',
                    old_name='waf_core_al_created_idx',
                ),
            ]
        ),
        migrations.RunSQL(
            "ALTER INDEX IF EXISTS waf_core_de_timesta_idx RENAME TO waf_core_de_timesta_30ae19_idx;",
            state_operations=[
                migrations.RenameIndex(
                    model_name='detectedattack',
                    new_name='waf_core_de_timesta_30ae19_idx',
                    old_name='waf_core_de_timesta_idx',
                ),
            ]
        ),
        migrations.RunSQL(
            "ALTER INDEX IF EXISTS waf_core_ht_timesta_idx RENAME TO waf_core_ht_timesta_0856c4_idx;",
            state_operations=[
                migrations.RenameIndex(
                    model_name='httprequest',
                    new_name='waf_core_ht_timesta_0856c4_idx',
                    old_name='waf_core_ht_timesta_idx',
                ),
            ]
        ),
        migrations.RunSQL(
            "ALTER INDEX IF EXISTS waf_core_ht_client__idx RENAME TO waf_core_ht_client__7c10a2_idx;",
            state_operations=[
                migrations.RenameIndex(
                    model_name='httprequest',
                    new_name='waf_core_ht_client__7c10a2_idx',
                    old_name='waf_core_ht_client__idx',
                ),
            ]
        ),
        migrations.AlterField(
            model_name='alert',
            name='acknowledged_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                                    to=settings.AUTH_USER_MODEL),
        ),
    ]
