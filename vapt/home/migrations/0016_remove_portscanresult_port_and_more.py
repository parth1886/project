# Generated by Django 4.1.7 on 2023-04-01 03:05

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0015_portscanresult_delete_scanresult'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='portscanresult',
            name='port',
        ),
        migrations.RemoveField(
            model_name='portscanresult',
            name='protocol',
        ),
        migrations.RemoveField(
            model_name='portscanresult',
            name='status',
        ),
        migrations.RemoveField(
            model_name='portscanresult',
            name='website',
        ),
        migrations.AddField(
            model_name='portscanresult',
            name='open_ports',
            field=models.TextField(default=''),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='portscanresult',
            name='scan_time',
            field=models.DateTimeField(auto_now_add=True, default=django.utils.timezone.now),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='portscanresult',
            name='target_host',
            field=models.CharField(default='', max_length=255),
            preserve_default=False,
        ),
    ]
