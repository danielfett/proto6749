# Generated by Django 2.2.7 on 2019-11-12 14:47

from django.conf import settings
import django.contrib.postgres.fields
import django.contrib.postgres.fields.jsonb
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    replaces = [
        ("oauth", "0001_initial"),
        ("oauth", "0002_auto_20191111_1211"),
        ("oauth", "0003_session_user"),
        ("oauth", "0004_auto_20191111_1616"),
        ("oauth", "0005_session_claims"),
        ("oauth", "0006_auto_20191112_0943"),
        ("oauth", "0007_session_depends_on"),
        ("oauth", "0008_auto_20191112_1440"),
    ]

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Client",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        db_index=True,
                        default=uuid.uuid4,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("client_tls_certificate", models.TextField()),
                (
                    "redirect_uris",
                    django.contrib.postgres.fields.ArrayField(
                        base_field=models.URLField(),
                        default=["https://example.com"],
                        size=None,
                    ),
                ),
                ("name", models.CharField(default="Demo", max_length=128)),
            ],
        ),
        migrations.CreateModel(
            name="Server",
            fields=[
                (
                    "id",
                    models.SlugField(max_length=32, primary_key=True, serialize=False),
                ),
                ("pkce_required", models.BooleanField(default=True)),
            ],
        ),
        migrations.CreateModel(
            name="Session",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("code_challenge", models.CharField(blank=True, max_length=1024)),
                (
                    "code_challenge_method",
                    models.TextField(
                        choices=[("S256", "S256"), ("plain", "plain")], max_length=5
                    ),
                ),
                ("redirect_uri", models.URLField(blank=True, default=None, null=True)),
                (
                    "response_type",
                    models.CharField(
                        choices=[("code", "code")],
                        default=None,
                        max_length=24,
                        null=True,
                    ),
                ),
                ("state", models.CharField(blank=True, max_length=1024)),
                (
                    "access_token",
                    models.CharField(
                        blank=True, db_index=True, max_length=32, null=True, unique=True
                    ),
                ),
                (
                    "refresh_token",
                    models.CharField(
                        blank=True, db_index=True, max_length=32, null=True, unique=True
                    ),
                ),
                (
                    "authorization_code",
                    models.CharField(
                        blank=True, db_index=True, max_length=24, null=True, unique=True
                    ),
                ),
                ("authorized", models.BooleanField(default=False)),
                ("scope", models.CharField(blank=True, max_length=1024)),
                (
                    "authorization_details",
                    django.contrib.postgres.fields.jsonb.JSONField(
                        blank=True, default=list
                    ),
                ),
                (
                    "request_uri",
                    models.CharField(
                        blank=True,
                        db_index=True,
                        max_length=1024,
                        null=True,
                        unique=True,
                    ),
                ),
                ("created", models.DateTimeField(auto_now_add=True)),
                (
                    "client",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="oauth.Client"
                    ),
                ),
                (
                    "server",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="oauth.Server"
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "claims",
                    django.contrib.postgres.fields.jsonb.JSONField(
                        blank=True, default=dict
                    ),
                ),
                (
                    "depends_on",
                    models.ForeignKey(
                        default=None,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="dependent_sessions",
                        to="oauth.Session",
                    ),
                ),
            ],
        ),
    ]
