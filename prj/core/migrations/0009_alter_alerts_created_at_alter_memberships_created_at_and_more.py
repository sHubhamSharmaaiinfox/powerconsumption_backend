# Generated by Django 5.1.4 on 2024-12-24 07:47

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0008_alerts_created_at_alter_memberships_created_at_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='alerts',
            name='created_at',
            field=models.DateTimeField(default=datetime.datetime(2024, 12, 24, 13, 16, 59, 494174)),
        ),
        migrations.AlterField(
            model_name='memberships',
            name='created_at',
            field=models.CharField(default=datetime.datetime(2024, 12, 24, 7, 46, 59, 492171), max_length=200),
        ),
        migrations.AlterField(
            model_name='memberships',
            name='updated_at',
            field=models.CharField(default=datetime.datetime(2024, 12, 24, 7, 46, 59, 492171), max_length=200),
        ),
        migrations.AlterField(
            model_name='payment',
            name='created_at',
            field=models.CharField(default=datetime.datetime(2024, 12, 24, 13, 16, 59, 496176), max_length=255),
        ),
        migrations.AlterField(
            model_name='transactions',
            name='date',
            field=models.CharField(default=datetime.datetime(2024, 12, 24, 7, 46, 59, 494174), max_length=200),
        ),
        migrations.AlterField(
            model_name='user',
            name='created_at',
            field=models.CharField(default=datetime.datetime(2024, 12, 24, 7, 46, 59, 492171), max_length=200),
        ),
        migrations.AlterField(
            model_name='user',
            name='updated_at',
            field=models.CharField(default=datetime.datetime(2024, 12, 24, 7, 46, 59, 492171), max_length=200),
        ),
        migrations.AlterField(
            model_name='usermemberships',
            name='date',
            field=models.CharField(default=datetime.datetime(2024, 12, 24, 7, 46, 59, 492171), max_length=200),
        ),
        migrations.AlterField(
            model_name='usermeterreadings',
            name='datetime',
            field=models.DateTimeField(default=datetime.datetime(2024, 12, 24, 13, 16, 59, 494174)),
        ),
        migrations.AlterField(
            model_name='usermeters',
            name='created_at',
            field=models.CharField(default=datetime.datetime(2024, 12, 24, 7, 46, 59, 494174), max_length=200),
        ),
    ]