# Generated by Django 5.0.3 on 2024-03-31 07:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0004_deviceport'),
    ]

    operations = [
        migrations.AddField(
            model_name='device',
            name='scan_key',
            field=models.CharField(default='', max_length=255),
        ),
    ]