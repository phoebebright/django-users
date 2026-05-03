from django.apps import AppConfig


class TestAppConfig(AppConfig):
    name = "tests.test_referrals.test_app"
    label = "test_referrals_app"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self):
        from django_users.referrals.registry import register_models
        from .models import ReferralCode, Referral, ReferralBonus, RewardGrant

        register_models(
            code=ReferralCode,
            referral=Referral,
            bonus=ReferralBonus,
            grant=RewardGrant,
        )
