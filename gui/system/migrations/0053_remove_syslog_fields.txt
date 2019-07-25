from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('system', '0052_move_syslog_from_settings_model_to_advanced_model'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='settings',
            name='stg_sysloglevel',
        ),
        migrations.RemoveField(
            model_name='settings',
            name='stg_syslogserver',
        ),
    ]
