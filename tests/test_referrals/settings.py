"""Minimal Django settings for running the referrals test suite in isolation.

    python -m tests.test_referrals.runtests

from the repo root. Intentionally does NOT enable the main django_users app
— we only need the referrals sub-package plus a test app with concretes.
"""

SECRET_KEY = "insecure-test-key"
DEBUG = False

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    },
}

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django_users.referrals.apps.ReferralsConfig",
    "tests.test_referrals.test_app.apps.TestAppConfig",
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django_users.referrals.middleware.ReferralAttributionMiddleware",
]

USE_TZ = True
TIME_ZONE = "UTC"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

AUTH_USER_MODEL = "auth.User"

# Referrals — no policy configured by default; individual tests override.
REFERRALS_HOLD_PERIOD_DAYS = 1
REFERRALS_CREDITS_GRANT_CALLABLE = "tests.test_referrals.test_app.handlers.grant_credits"
