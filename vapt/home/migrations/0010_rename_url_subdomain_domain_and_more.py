# Generated by Django 4.1.7 on 2023-03-31 05:02

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0009_rename_domain_subdomain_url_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='subdomain',
            old_name='url',
            new_name='domain',
        ),
        migrations.RemoveField(
            model_name='subdomain',
            name='subdomains',
        ),
        migrations.AddField(
            model_name='subdomain',
            name='subdomain',
            field=models.CharField(default='', max_length=255),
            preserve_default=False,
        ),
    ]
