# Generated by Django 5.0.7 on 2024-12-05 07:58

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0004_alter_memberships_created_at_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="usermeterreadings",
            name="Amphere",
            field=models.CharField(default="1", max_length=250),
        ),
        migrations.AddField(
            model_name="usermeterreadings",
            name="volt",
            field=models.CharField(default="1", max_length=250),
        ),
        migrations.AlterField(
            model_name="memberships",
            name="created_at",
            field=models.CharField(
                default=datetime.datetime(2024, 12, 5, 7, 58, 40, 418888),
                max_length=200,
            ),
        ),
        migrations.AlterField(
            model_name="memberships",
            name="updated_at",
            field=models.CharField(
                default=datetime.datetime(2024, 12, 5, 7, 58, 40, 418888),
                max_length=200,
            ),
        ),
        migrations.AlterField(
            model_name="transactions",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2024, 12, 5, 7, 58, 40, 420891),
                max_length=200,
            ),
        ),
        migrations.AlterField(
            model_name="user",
            name="created_at",
            field=models.CharField(
                default=datetime.datetime(2024, 12, 5, 7, 58, 40, 416889),
                max_length=200,
            ),
        ),
        migrations.AlterField(
            model_name="user",
            name="updated_at",
            field=models.CharField(
                default=datetime.datetime(2024, 12, 5, 7, 58, 40, 416889),
                max_length=200,
            ),
        ),
        migrations.AlterField(
            model_name="usermemberships",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2024, 12, 5, 7, 58, 40, 419890),
                max_length=200,
            ),
        ),
        migrations.AlterField(
            model_name="usermeterreadings",
            name="datetime",
            field=models.CharField(
                default=datetime.datetime(2024, 12, 5, 7, 58, 40, 420891),
                max_length=200,
            ),
        ),
        migrations.AlterField(
            model_name="usermeters",
            name="created_at",
            field=models.CharField(
                default=datetime.datetime(2024, 12, 5, 7, 58, 40, 419890),
                max_length=200,
            ),
        ),
    ]
