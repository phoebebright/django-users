from django.conf import settings
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class ReferralStatus(models.TextChoices):
    ACTIVE = "active", _("Active")
    FLAGGED = "flagged", _("Flagged for review")
    DISABLED = "disabled", _("Disabled")


class BonusStatus(models.TextChoices):
    ACCRUED = "accrued", _("Accrued — in hold period")
    HELD_FOR_REVIEW = "held_for_review", _("Held for admin review")
    PAID = "paid", _("Paid out")
    CLAWED_BACK = "clawed_back", _("Clawed back")
    REJECTED = "rejected", _("Rejected")


class ReferralSource(models.TextChoices):
    URL = "url", _("Shared link")
    EMAIL = "email", _("Email invite")
    MANUAL = "manual", _("Manually recorded")


class AbstractReferralCode(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="referral_code",
    )
    code = models.CharField(max_length=32, unique=True, db_index=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        abstract = True

    def __str__(self):
        return self.code


class AbstractReferral(models.Model):
    referrer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="referrals_made",
    )
    referee = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="referred_by_record",
    )
    source = models.CharField(
        max_length=16,
        choices=ReferralSource.choices,
        default=ReferralSource.URL,
    )
    status = models.CharField(
        max_length=16,
        choices=ReferralStatus.choices,
        default=ReferralStatus.ACTIVE,
        db_index=True,
    )
    flag_reason = models.CharField(max_length=255, blank=True, default="")
    attributed_at = models.DateTimeField(default=timezone.now)

    class Meta:
        abstract = True

    def __str__(self):
        return f"{self.referrer_id} -> {self.referee_id}"

    @property
    def is_earning(self) -> bool:
        return self.status == ReferralStatus.ACTIVE


class AbstractReferralBonus(models.Model):
    # Cannot declare FK to the concrete referral here because it's abstract.
    # Host concretes must define `referral` as a FK to their concrete Referral.
    # We leave it to the concrete to declare; the services layer treats
    # `bonus.referral` as opaque.
    event_name = models.CharField(max_length=64, db_index=True)
    event_ref = models.CharField(max_length=128, db_index=True)
    reward_kind = models.CharField(max_length=32)
    amount = models.DecimalField(max_digits=14, decimal_places=4, default=0)
    metadata = models.JSONField(default=dict, blank=True)
    status = models.CharField(
        max_length=20,
        choices=BonusStatus.choices,
        default=BonusStatus.ACCRUED,
        db_index=True,
    )
    recipient = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="referral_bonuses_received",
    )
    recipient_role = models.CharField(
        max_length=16,
        choices=[("referrer", "Referrer"), ("referee", "Referee")],
    )
    created_at = models.DateTimeField(default=timezone.now)
    payout_at = models.DateTimeField(db_index=True)
    paid_at = models.DateTimeField(null=True, blank=True)
    review_reason = models.CharField(max_length=255, blank=True, default="")

    class Meta:
        abstract = True
        # Concretes should add:
        # constraints = [
        #     models.UniqueConstraint(
        #         fields=["referral", "event_ref", "recipient_role"],
        #         name="uniq_bonus_per_event_role",
        #     ),
        # ]

    def __str__(self):
        return f"{self.event_name}:{self.event_ref} {self.reward_kind} {self.amount} ({self.status})"

    @property
    def is_payable(self) -> bool:
        return (
            self.status == BonusStatus.ACCRUED
            and self.payout_at <= timezone.now()
        )


class AbstractRewardGrant(models.Model):
    """Records a reward actually applied to a user's account.

    Separate from ReferralBonus so non-referral rewards can reuse this later.
    A ReferralBonus points at its RewardGrant via the concrete's FK.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="reward_grants",
    )
    kind = models.CharField(max_length=32)
    amount = models.DecimalField(max_digits=14, decimal_places=4, default=0)
    metadata = models.JSONField(default=dict, blank=True)
    granted_at = models.DateTimeField(default=timezone.now)
    reversed_at = models.DateTimeField(null=True, blank=True)
    reversal_reason = models.CharField(max_length=255, blank=True, default="")

    class Meta:
        abstract = True

    def __str__(self):
        sign = "-" if self.reversed_at else "+"
        return f"{sign}{self.amount} {self.kind} -> user {self.user_id}"

    @property
    def is_active(self) -> bool:
        return self.reversed_at is None
