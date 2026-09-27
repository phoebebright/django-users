from django.apps import AppConfig


class UsersConfig(AppConfig):
    name = "users"
    label = "users"   # the package's bases refer to users.Person etc. by name
    default_auto_field = "django.db.models.BigAutoField"
