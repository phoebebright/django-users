from django.apps import AppConfig


class ReferralsConfig(AppConfig):
    name = "django_users.referrals"
    label = "django_users_referrals"
    verbose_name = "Django Users — Referrals"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self):
        from . import rewards  # noqa: F401  registers default handlers
