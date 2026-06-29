"""Minimal settings to exercise the Authentik IdP guard in isolation.

Mirrors tests/test_referrals/settings.py. The IdP module (``django_users.idp``)
only depends on ``django.conf.settings`` and ``httpx`` — no models, no GIS — so
these tests run without the host app's custom user model or GDAL.

Deliberately defines neither ``AUTHENTIK`` nor ``USE_KEYCLOAK`` at the base
level so the default state is "Authentik not configured"; individual tests use
``override_settings`` to switch states.
"""

SECRET_KEY = "test-secret-key"

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

MIDDLEWARE = []

USE_TZ = True

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
