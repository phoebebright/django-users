"""Minimal settings to exercise provider resolution and the IdP adapters in
isolation (mirrors tests/test_authentik/settings.py).

Deliberately defines none of AUTH_PROVIDER / USE_KEYCLOAK / AUTHENTIK /
KEYCLOAK_CLIENTS at the base level so the default state is "plain Django
auth"; individual tests use ``override_settings`` to switch states.
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
