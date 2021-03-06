# Generated by Django 2.2.7 on 2019-11-12 14:48

import django.contrib.postgres.fields
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oauth", "0001_squashed_0008_auto_20191112_1440"),
    ]

    operations = [
        migrations.AlterField(
            model_name="client", name="name", field=models.CharField(max_length=128),
        ),
        migrations.AlterField(
            model_name="client",
            name="redirect_uris",
            field=django.contrib.postgres.fields.ArrayField(
                base_field=models.URLField(), size=None
            ),
        ),
        migrations.AlterField(
            model_name="session",
            name="code_challenge_method",
            field=models.TextField(
                blank=True, choices=[("S256", "S256"), ("plain", "plain")], max_length=5
            ),
        ),
    ]
