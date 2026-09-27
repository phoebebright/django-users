"""A reference plain-Django host, shaped like BuiltAir (decision 003).

- AUTH_PROVIDER = 'django'
- `django_users` is NOT an installed app: the host subclasses its abstract
  models and views but provides its own templates.
- generic roles only (roles.py)
- the concrete user model is built on CustomUserBaseBasic and tracks field
  changes (users/models.py).
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
# The package imports the host's app as a top-level `users` module
# (`from users.models import Person, Role, Organisation` in serializers.py), so
# the host app must be importable as `users`, as BuiltAir's is.
sys.path.insert(0, str(HERE))

SECRET_KEY = "test-secret-key"
INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.sites",       # django_users.models needs Site ...
    "django.contrib.flatpages",   # ... and FlatPage installed
    "django_countries",
    "rest_framework",
    "rest_framework_api_key",     # django_users.urls -> api imports APIKey
    "users",
]
MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
ROOT_URLCONF = "tests.test_plain_host.urls"
TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "DIRS": [HERE / "templates"],
    "OPTIONS": {"context_processors": [
        "django.template.context_processors.request",
        "django.contrib.auth.context_processors.auth",
        "django.contrib.messages.context_processors.messages",
    ]},
}]
AUTH_USER_MODEL = "users.CustomUser"
AUTH_PROVIDER = "django"
USE_KEYCLOAK = False
MODEL_ROLES_PATH = "tests.test_plain_host.roles.ModelRoles"
DISCIPLINES_PATH = "tests.test_plain_host.roles.Disciplines"
LOGIN_URL = "/users/login/"
LOGIN_REDIRECT_URL = "/"
SITE_URL = "http://testserver"
SITE_NAME = "Plain host"
DEFAULT_FROM_EMAIL = "test@example.com"
VERIFICATION_CODE_EXPIRY_MINUTES = 20
USE_TZ = True
SITE_ID = 1
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
