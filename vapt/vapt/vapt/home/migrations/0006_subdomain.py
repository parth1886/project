# Generated by Django 4.1.7 on 2023-03-31 03:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0005_scanresult_delete_portscanresult'),
    ]

    operations = [
        migrations.CreateModel(
            name='Subdomain',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('url', models.URLField()),
                ('subdomain', models.CharField(max_length=255)),
            ],
        ),
    ]
