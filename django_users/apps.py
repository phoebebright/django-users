from django.apps import AppConfig


class DjangoUsersConfig(AppConfig):
    name = "django_users"
    verbose_name = "Django Users"

    def ready(self):
        from . import checks
