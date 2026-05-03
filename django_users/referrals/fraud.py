import logging
from datetime import timedelta
from typing import Any, Callable, Optional

from django.utils import timezone
from django.utils.module_loading import import_string

from . import conf

logger = logging.getLogger(__name__)


class FraudCheckResult:
    __slots__ = ("blocked", "flagged", "reason")

    def __init__(self, blocked: bool = False, flagged: bool = False, reason: str = ""):
        self.blocked = blocked
        self.flagged = flagged
        self.reason = reason

    @classmethod
    def ok(cls):
        return cls()

    @classmethod
    def block(cls, reason: str):
        return cls(blocked=True, reason=reason)

    @classmethod
    def flag(cls, reason: str):
        return cls(flagged=True, reason=reason)


def check_self_referral(referrer, referee) -> FraudCheckResult:
    """Refuse if referrer and referee are the same user."""
    if referrer is None or referee is None:
        return FraudCheckResult.ok()
    if getattr(referrer, "pk", None) == getattr(referee, "pk", None):
        return FraudCheckResult.block("self-referral by user id")
    return FraudCheckResult.ok()


def check_email_overlap(referrer, referee, email_history_fn: Optional[Callable] = None) -> FraudCheckResult:
    """If referee's email has ever been associated with the referrer, block.

    Host app may register an email_history_fn that returns a set of lowercased
    emails ever used by the given user. If not provided, we compare only the
    current email attributes.
    """
    ref_email = (getattr(referee, "email", "") or "").lower()
    if not ref_email:
        return FraudCheckResult.ok()
    referrer_email = (getattr(referrer, "email", "") or "").lower()
    if referrer_email and referrer_email == ref_email:
        return FraudCheckResult.block("shared current email")
    if email_history_fn is not None:
        history = email_history_fn(referrer) or set()
        if ref_email in {e.lower() for e in history}:
            return FraudCheckResult.block("email appears in referrer history")
    return FraudCheckResult.ok()


def _get_payment_fingerprint_fn():
    path = conf.payment_fingerprint_lookup_path()
    if not path:
        return None
    return import_string(path)


def check_payment_fingerprint(referrer, referee, event_data: dict) -> FraudCheckResult:
    """Block if the payment fingerprint on the triggering event matches any
    fingerprint ever used by the referrer.

    Relies on host-provided lookup via REFERRALS_PAYMENT_FINGERPRINT_LOOKUP.
    If the lookup isn't configured we log a warning and pass — hosts using
    payment triggers MUST wire this up.
    """
    fp = event_data.get("payment_fingerprint")
    if not fp:
        return FraudCheckResult.ok()
    fn = _get_payment_fingerprint_fn()
    if fn is None:
        logger.warning(
            "REFERRALS_PAYMENT_FINGERPRINT_LOOKUP is not configured — "
            "payment-based fraud check is disabled. Hosts using payment "
            "triggers should configure this."
        )
        return FraudCheckResult.ok()
    referrer_fps = fn(referrer) or set()
    if fp in referrer_fps:
        return FraudCheckResult.block("payment method shared with referrer")
    return FraudCheckResult.ok()


def check_velocity(bonus_model, referrer) -> FraudCheckResult:
    """Flag if the referrer has exceeded the per-day or per-month cap of
    bonuses recorded against them (any status).

    Takes the concrete bonus model class so it can run the query without
    needing host-specific imports.
    """
    now = timezone.now()
    day_ago = now - timedelta(hours=24)
    month_ago = now - timedelta(days=30)

    qs = bonus_model._default_manager.filter(
        recipient=referrer, recipient_role="referrer"
    )
    per_day = qs.filter(created_at__gte=day_ago).count()
    if per_day >= conf.velocity_per_day():
        return FraudCheckResult.flag(
            f"referrer velocity {per_day} in 24h exceeds cap {conf.velocity_per_day()}"
        )
    per_month = qs.filter(created_at__gte=month_ago).count()
    if per_month >= conf.velocity_per_month():
        return FraudCheckResult.flag(
            f"referrer velocity {per_month} in 30d exceeds cap {conf.velocity_per_month()}"
        )
    return FraudCheckResult.ok()


def check_established_user(referrer) -> FraudCheckResult:
    """If REFERRALS_ESTABLISHED_USER_PREDICATE is configured, use it to decide
    whether the referrer is eligible to earn at all."""
    path = conf.established_user_predicate_path()
    if not path:
        return FraudCheckResult.ok()
    fn = import_string(path)
    if not fn(referrer):
        return FraudCheckResult.flag("referrer not yet established")
    return FraudCheckResult.ok()
