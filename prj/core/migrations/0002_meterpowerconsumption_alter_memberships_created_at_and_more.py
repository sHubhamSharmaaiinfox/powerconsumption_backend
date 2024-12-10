# Generated by Django 5.0.7 on 2024-12-04 04:49

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="MeterPowerConsumption",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("meter_id", models.CharField(max_length=250)),
                ("datetime", models.CharField(max_length=250)),
                ("power", models.CharField(max_length=250)),
                ("status", models.CharField(default="1", max_length=200)),
            ],
            options={
                "db_table": "meterpowerconsumption",
            },
        ),
        migrations.AlterField(
            model_name="memberships",
            name="created_at",
            field=models.CharField(
                default=datetime.datetime(2024, 12, 4, 4, 49, 4, 236615), max_length=200
            ),
        ),
        migrations.AlterField(
            model_name="memberships",
            name="updated_at",
            field=models.CharField(
                default=datetime.datetime(2024, 12, 4, 4, 49, 4, 236615), max_length=200
            ),
        ),
        migrations.AlterField(
            model_name="user",
            name="created_at",
            field=models.CharField(
                default=datetime.datetime(2024, 12, 4, 4, 49, 4, 234615), max_length=200
            ),
        ),
        migrations.AlterField(
            model_name="user",
            name="updated_at",
            field=models.CharField(
                default=datetime.datetime(2024, 12, 4, 4, 49, 4, 234615), max_length=200
            ),
        ),
        migrations.AlterField(
            model_name="usermemberships",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2024, 12, 4, 4, 49, 4, 237614), max_length=200
            ),
        ),
    ]