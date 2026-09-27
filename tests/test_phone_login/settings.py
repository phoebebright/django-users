"""Minimal settings for the phone-login tests.

Only the two phone-login views are mounted (tests/test_phone_login/urls.py),
under a `users` namespace as the hosts mount them, and `django_users` itself is
not an installed app: the flow must work without the rest of the package.
The package's real templates render, over a stand-in narrow base.
"""
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent

SECRET_KEY = "test-secret-key"
INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
]
MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
]
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
ROOT_URLCONF = "tests.test_phone_login.urls"
TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    # The stand-in base first, then the package's own templates.
    "DIRS": [HERE / "templates", REPO / "django_users" / "templates"],
    "OPTIONS": {"context_processors": [
        "django.template.context_processors.request",
        "django.contrib.auth.context_processors.auth",
    ]},
}]
CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
LOGIN_URL = "/login/"
USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
DJANGO_USERS_PHONE_LOGIN_DEFAULT_NEXT = "/landing/"
DJANGO_USERS_PHONE_LOGIN_SESSION_KEYS = ("selected_org",)
