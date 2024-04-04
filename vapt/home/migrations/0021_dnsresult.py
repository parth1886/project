# Generated by Django 4.1.7 on 2023-04-25 02:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0020_remove_websiteinfo_asn_remove_websiteinfo_country_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='DNSResult',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('target_domain', models.CharField(max_length=255)),
                ('dns_servers', models.TextField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]
