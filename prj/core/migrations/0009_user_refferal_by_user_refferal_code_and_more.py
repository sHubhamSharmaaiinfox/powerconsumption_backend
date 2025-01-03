# Generated by Django 5.0.7 on 2024-12-30 05:44

import datetime
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0008_alerts_created_at_alter_memberships_created_at_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="user",
            name="refferal_by",
            field=models.CharField(default="", max_length=200),
        ),
        migrations.AddField(
            model_name="user",
            name="refferal_code",
            field=models.CharField(default="", max_length=200),
        ),
        migrations.AlterField(
            model_name="alerts",
            name="created_at",
            field=models.DateTimeField(
                default=datetime.datetime(2024, 12, 30, 11, 14, 31, 306795)
            ),
        ),
        migrations.AlterField(
            model_name="memberships",
            name="created_at",
            field=models.CharField(
                default=datetime.datetime(2024, 12, 30, 5, 44, 31, 304718),
                max_length=200,
            ),
        ),
        migrations.AlterField(
            model_name="memberships",
            name="updated_at",
            field=models.CharField(
                default=datetime.datetime(2024, 12, 30, 5, 44, 31, 304718),
                max_length=200,
            ),
        ),
        migrations.AlterField(
            model_name="payment",
            name="created_at",
            field=models.CharField(
                default=datetime.datetime(2024, 12, 30, 11, 14, 31, 307798),
                max_length=255,
            ),
        ),
        migrations.AlterField(
            model_name="transactions",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2024, 12, 30, 5, 44, 31, 306795),
                max_length=200,
            ),
        ),
        migrations.AlterField(
            model_name="user",
            name="created_at",
            field=models.CharField(
                default=datetime.datetime(2024, 12, 30, 5, 44, 31, 303707),
                max_length=200,
            ),
        ),
        migrations.AlterField(
            model_name="user",
            name="updated_at",
            field=models.CharField(
                default=datetime.datetime(2024, 12, 30, 5, 44, 31, 303707),
                max_length=200,
            ),
        ),
        migrations.AlterField(
            model_name="usermemberships",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2024, 12, 30, 5, 44, 31, 304718),
                max_length=200,
            ),
        ),
        migrations.AlterField(
            model_name="usermeterreadings",
            name="datetime",
            field=models.DateTimeField(
                default=datetime.datetime(2024, 12, 30, 11, 14, 31, 305798)
            ),
        ),
        migrations.AlterField(
            model_name="usermeters",
            name="created_at",
            field=models.CharField(
                default=datetime.datetime(2024, 12, 30, 5, 44, 31, 305798),
                max_length=200,
            ),
        ),
        migrations.CreateModel(
            name="Feedback",
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
                ("feedback", models.TextField(verbose_name="Feedback")),
                (
                    "created_at",
                    models.DateTimeField(
                        auto_now_add=True, verbose_name="Submitted At"
                    ),
                ),
                (
                    "user_id",
                    models.ForeignKey(
                        db_column="user_id",
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "db_table": "feedback",
            },
        ),
    ]
