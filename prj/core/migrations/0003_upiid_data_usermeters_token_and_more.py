# Generated by Django 5.1.4 on 2024-12-20 04:50

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0002_usermemberships_amount_alter_memberships_created_at_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='UPIID_data',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('Merchant_name', models.CharField(default='', max_length=255)),
                ('upi_id', models.CharField(default='', max_length=255)),
            ],
            options={
                'db_table': 'UPIID_data',
            },
        ),
        migrations.AddField(
            model_name='usermeters',
            name='token',
            field=models.TextField(default=''),
        ),
        migrations.AlterField(
            model_name='memberships',
            name='created_at',
            field=models.CharField(default=datetime.datetime(2024, 12, 20, 4, 50, 51, 806891), max_length=200),
        ),
        migrations.AlterField(
            model_name='memberships',
            name='updated_at',
            field=models.CharField(default=datetime.datetime(2024, 12, 20, 4, 50, 51, 806891), max_length=200),
        ),
        migrations.AlterField(
            model_name='payment',
            name='created_at',
            field=models.CharField(default=datetime.datetime(2024, 12, 20, 10, 20, 51, 806891), max_length=255),
        ),
        migrations.AlterField(
            model_name='transactions',
            name='date',
            field=models.CharField(default=datetime.datetime(2024, 12, 20, 4, 50, 51, 806891), max_length=200),
        ),
        migrations.AlterField(
            model_name='user',
            name='created_at',
            field=models.CharField(default=datetime.datetime(2024, 12, 20, 4, 50, 51, 806891), max_length=200),
        ),
        migrations.AlterField(
            model_name='user',
            name='updated_at',
            field=models.CharField(default=datetime.datetime(2024, 12, 20, 4, 50, 51, 806891), max_length=200),
        ),
        migrations.AlterField(
            model_name='usermemberships',
            name='date',
            field=models.CharField(default=datetime.datetime(2024, 12, 20, 4, 50, 51, 806891), max_length=200),
        ),
        migrations.AlterField(
            model_name='usermeterreadings',
            name='datetime',
            field=models.DateTimeField(default=datetime.datetime(2024, 12, 20, 10, 20, 51, 806891)),
        ),
        migrations.AlterField(
            model_name='usermeters',
            name='created_at',
            field=models.CharField(default=datetime.datetime(2024, 12, 20, 4, 50, 51, 806891), max_length=200),
        ),
    ]