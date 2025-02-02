# Generated by Django 4.1.7 on 2023-03-31 04:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0006_subdomain'),
    ]

    operations = [
        migrations.CreateModel(
            name='MyModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('my_field', models.CharField(default='my default value', max_length=50)),
            ],
        ),
        migrations.RenameField(
            model_name='subdomain',
            old_name='subdomain',
            new_name='domain',
        ),
        migrations.RemoveField(
            model_name='subdomain',
            name='url',
        ),
        migrations.AddField(
            model_name='subdomain',
            name='subdomains',
            field=models.CharField(default='', max_length=255),
            preserve_default=False,
        ),
    ]
