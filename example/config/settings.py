import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = "test-secret-key"
DEBUG = True
ALLOWED_HOSTS = []

# ---------------------------------------------------------------------
# Core Django setup
# ---------------------------------------------------------------------
INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.admin",
    "django.contrib.staticfiles",
    "django.contrib.sites",
    "django_users.apps.DjangoUsersConfig",
    # Third-party apps your models depend on
    "django_countries",
    "yamlfield",
    "rest_framework_api_key",
    "example_app.apps.ExampleConfig",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

# ---------------------------------------------------------------------
# Database – simple SQLite for tests
# ---------------------------------------------------------------------
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

# Faster hashing for tests
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.MD5PasswordHasher",
]

# ---------------------------------------------------------------------
# Internationalisation
# ---------------------------------------------------------------------
LANGUAGE_CODE = "en-gb"
TIME_ZONE = "Europe/Dublin"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ---------------------------------------------------------------------
# Auth model
# ---------------------------------------------------------------------
# NOTE: app label is "users" from ExampleConfig.label
AUTH_USER_MODEL = "users.CustomUser"

# ---------------------------------------------------------------------
# Settings referenced by your models
# ---------------------------------------------------------------------

# You can point these at real modules in your project,
# for now you can create tiny stubs so imports work in tests.
MODEL_ROLES_PATH = "config.roles_and_disciplines.ModelRoles"
DISCIPLINES_PATH = "config.roles_and_disciplines.Disciplines"

CHANNEL_TYPES = ["email", "sms", "whatsapp"]

USE_KEYCLOAK = False

# Used in VerificationCode TTL helpers
VERIFICATION_CODE_EXPIRY_MINUTES = 20
VERIFICATION_MAX_ATTEMPTS = 5

# Used in CustomUserBaseBasic.save to decide old vs new users
# It is unpacked into datetime(*USER_COMMS_MIGRATION_DATE)
USER_COMMS_MIGRATION_DATE = (2023, 1, 1, 0, 0, 0)

# Used in email / templates in VerificationCodeBase.send_verification
LOGIN_TERM = "login"
REGISTER_TERM = "register"

SITE_URL = "https://example.test"
SITE_NAME = "Example Test Site"

DEFAULT_FROM_EMAIL = "noreply@example.test"
SUPPORT_EMAIL = "support@example.test"
NOTIFY_NEW_USER_EMAILS = []  # list of admin addresses if you want

# Newsletter test stub (used in CustomUser.is_subscribed2newsletter)
NEWSLETTER_GENERAL_PK = "general-newsletter"

# Used in Organisation.decrypt_settings_data – for tests you won’t typically
# call this, but it needs to exist.
SETTINGS_KEY = "0" * 32  # any 32-byte hex string; not used for real crypto in tests

# ---------------------------------------------------------------------
# Email backend for tests
# ---------------------------------------------------------------------
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"

KEYCLOAK_CLIENTS = {
    "DEFAULT": {
        "URL": 'https://x.y.ie',
        "REALM": "x",
        "CLIENT_ID": "x",
        "CLIENT_SECRET": "xyz",
    },
    "USERS": {
        "URL": 'https://x.y.ie',
        "REALM": "x",
        "CLIENT_ID": "x",
        "CLIENT_SECRET": "xyz",
    },
}

USE_CURRENT_ORGANISATION = True   # on login users are attached to a default organisation if there are any in the Roles
