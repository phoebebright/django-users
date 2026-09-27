"""A non-skorie host: generic roles only (tests/test_boundary/roles.py)."""
SECRET_KEY = "test-secret-key"
INSTALLED_APPS = ["django.contrib.contenttypes", "django.contrib.auth"]
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
MODEL_ROLES_PATH = "tests.test_boundary.roles.ModelRoles"
DISCIPLINES_PATH = "tests.test_boundary.roles.Disciplines"
