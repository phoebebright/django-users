import os
import django
from django.conf import settings
from django.test.utils import get_runner

if not settings.configured:
    settings.configure(
        DEBUG=True,
        DATABASES={
            'default': {
                'ENGINE': 'django.db.backends.sqlite3',
                'NAME': ':memory:',
            }
        },
        INSTALLED_APPS=[
            'django.contrib.auth',
            'django.contrib.contenttypes',
            'django.contrib.sessions',
            'django.contrib.messages',
            'django.contrib.sites',
            'django.contrib.flatpages',
            'django_countries',
            'django_users',
        ],
        MIDDLEWARE=[
            'django.contrib.sessions.middleware.SessionMiddleware',
            'django.middleware.common.CommonMiddleware',
            'django.middleware.csrf.CsrfViewMiddleware',
            'django.contrib.auth.middleware.AuthenticationMiddleware',
            'django.contrib.messages.middleware.MessageMiddleware',
        ],
        ROOT_URLCONF='django_users.urls',
        TEMPLATES=[
            {
                'BACKEND': 'django.template.backends.django.DjangoTemplates',
                'DIRS': [],
                'APP_DIRS': True,
                'OPTIONS': {
                    'context_processors': [
                        'django.template.context_processors.debug',
                        'django.template.context_processors.request',
                        'django.contrib.auth.context_processors.auth',
                        'django.contrib.messages.context_processors.messages',
                    ],
                },
            },
        ],
        AUTH_USER_MODEL='django_users.CustomUserBase',
        SECRET_KEY='fake-key',
        USE_TZ=True,
        USE_KEYCLOAK=False,
        VERIFICATION_CODE_EXPIRY_MINUTES=60,
        SITE_URL='http://testserver',
        LOGIN_URL='/users/login/',
        REGISTER_URL='/users/register/',
        LOGIN_TERM='Login',
        REGISTER_TERM='Register',
        SITE_NAME='Test Site',
        LOGO_URL='',
        COPYRIGHT='',
        MODEL_ROLES_PATH='default_roles_and_disciplines.ModelRoles',
        DISCIPLINES_PATH='default_roles_and_disciplines.Disciplines',
    )

def runtests():
    django.setup()
    TestRunner = get_runner(settings)
    test_runner = TestRunner(verbosity=1, interactive=True, failfast=False)
    # We only run tests that don't depend on external 'users' or 'web' apps for now
    failures = test_runner.run_tests(['django_users.tests'])
    import sys
    sys.exit(bool(failures))

if __name__ == "__main__":
    runtests()
