from django.db import models

from django_users.referrals.models import (
    AbstractReferral,
    AbstractReferralBonus,
    AbstractReferralCode,
    AbstractRewardGrant,
)


class ReferralCode(AbstractReferralCode):
    pass


class Referral(AbstractReferral):
    pass


class ReferralBonus(AbstractReferralBonus):
    referral = models.ForeignKey(
        Referral, on_delete=models.CASCADE, related_name="bonuses"
    )

    class Meta(AbstractReferralBonus.Meta):
        abstract = False
        constraints = [
            models.UniqueConstraint(
                fields=["referral", "event_ref", "recipient_role"],
                name="uniq_bonus_per_event_role_testapp",
            ),
        ]


class RewardGrant(AbstractRewardGrant):
    bonus = models.ForeignKey(
        ReferralBonus,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="grants",
    )
