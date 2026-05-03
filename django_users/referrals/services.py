"""Services — the integration surface for host apps.

Public API:
  * get_or_create_code(user) -> code string
  * resolve_code(code) -> referrer user or None
  * attribute(referee, code, source="url") -> Referral or None
  * dispatch(event_name, referee, event_ref, event_data=None) -> list of bonus records
  * process_due_payouts() -> int paid out
"""

import logging
import secrets
from typing import Any, Iterable, Optional

from django.db import IntegrityError, transaction
from django.utils import timezone

from . import conf, fraud
from .models import (
    BonusStatus,
    ReferralSource,
    ReferralStatus,
)
from .policies import get_active_policy
from .registry import (
    get_bonus_model,
    get_code_model,
    get_grant_model,
    get_referral_model,
)
from .rewards import RewardBundle, get_handler

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Code generation & resolution
# ---------------------------------------------------------------------------


def _generate_code() -> str:
    alphabet = conf.code_alphabet()
    length = conf.code_length()
    return "".join(secrets.choice(alphabet) for _ in range(length))


def get_or_create_code(user) -> str:
    Code = get_code_model()
    existing = Code._default_manager.filter(user=user).first()
    if existing:
        return existing.code
    for _ in range(10):
        try:
            return Code._default_manager.create(user=user, code=_generate_code()).code
        except IntegrityError:
            continue
    raise RuntimeError("Could not allocate a unique referral code after 10 attempts")


def resolve_code(code: str):
    if not code:
        return None
    Code = get_code_model()
    row = Code._default_manager.filter(code__iexact=code.strip()).select_related("user").first()
    return row.user if row else None


# ---------------------------------------------------------------------------
# Attribution
# ---------------------------------------------------------------------------


def attribute(referee, code: str, source: str = ReferralSource.URL):
    """Record a Referral. First-touch wins — if referee already has a
    Referral row, do nothing. Runs hard fraud checks (self-referral,
    email overlap). Returns the Referral row or None."""
    referrer = resolve_code(code)
    if referrer is None:
        return None

    Referral = get_referral_model()
    existing = Referral._default_manager.filter(referee=referee).first()
    if existing:
        return existing

    self_check = fraud.check_self_referral(referrer, referee)
    if self_check.blocked:
        logger.info("referral blocked at attribution: %s", self_check.reason)
        return None

    email_check = fraud.check_email_overlap(referrer, referee)
    if email_check.blocked:
        logger.info("referral blocked at attribution: %s", email_check.reason)
        return None

    return Referral._default_manager.create(
        referrer=referrer,
        referee=referee,
        source=source,
        status=ReferralStatus.ACTIVE,
    )


def get_referral_for(referee):
    Referral = get_referral_model()
    return Referral._default_manager.filter(referee=referee).first()


# ---------------------------------------------------------------------------
# Event dispatch
# ---------------------------------------------------------------------------


def dispatch(
    event_name: str,
    referee,
    event_ref: str,
    event_data: Optional[dict] = None,
) -> list:
    """Host app calls this when something bonus-worthy has happened to a user.

    Looks up the referee's Referral, asks the policy for a RewardBundle, runs
    fraud checks, and records ReferralBonus rows (idempotent per event_ref +
    recipient_role). Returns the list of bonus rows created.
    """
    event_data = event_data or {}
    referral = get_referral_for(referee)
    if referral is None:
        return []
    if referral.status == ReferralStatus.DISABLED:
        return []

    policy = get_active_policy()
    if policy.declared_events and event_name not in policy.declared_events:
        logger.warning(
            "referrals.dispatch: event_name=%r not in policy.declared_events — "
            "check for typos",
            event_name,
        )

    bundle = policy.calculate_bonus(referral, event_name, event_data)
    if bundle is None or bundle.is_empty():
        return []

    referrer = referral.referrer
    pay_check = fraud.check_payment_fingerprint(referrer, referee, event_data)
    if pay_check.blocked:
        _flag_referral(referral, pay_check.reason)
        return []

    established = fraud.check_established_user(referrer)
    velocity = fraud.check_velocity(get_bonus_model(), referrer)

    initial_status = BonusStatus.ACCRUED
    review_reason = ""
    if established.flagged or velocity.flagged:
        initial_status = BonusStatus.HELD_FOR_REVIEW
        review_reason = "; ".join(
            r for r in [established.reason, velocity.reason] if r
        )

    created = []
    if bundle.referrer_reward is not None:
        row = _record_bonus(
            referral=referral,
            recipient=referrer,
            recipient_role="referrer",
            reward=bundle.referrer_reward,
            event_name=event_name,
            event_ref=event_ref,
            status=initial_status,
            review_reason=review_reason,
        )
        if row is not None:
            created.append(row)

    if bundle.referee_reward is not None:
        row = _record_bonus(
            referral=referral,
            recipient=referee,
            recipient_role="referee",
            reward=bundle.referee_reward,
            event_name=event_name,
            event_ref=event_ref,
            status=initial_status,
            review_reason=review_reason,
        )
        if row is not None:
            created.append(row)

    return created


def _record_bonus(*, referral, recipient, recipient_role, reward, event_name, event_ref, status, review_reason):
    Bonus = get_bonus_model()
    payout_at = timezone.now() + timezone.timedelta(days=conf.hold_period_days())
    try:
        with transaction.atomic():
            return Bonus._default_manager.create(
                referral=referral,
                recipient=recipient,
                recipient_role=recipient_role,
                event_name=event_name,
                event_ref=event_ref,
                reward_kind=reward.kind,
                amount=reward.amount,
                metadata=reward.metadata,
                status=status,
                payout_at=payout_at,
                review_reason=review_reason,
            )
    except IntegrityError:
        logger.info(
            "referrals.dispatch: duplicate bonus suppressed event_ref=%s role=%s",
            event_ref,
            recipient_role,
        )
        return None


def _flag_referral(referral, reason: str) -> None:
    referral.status = ReferralStatus.FLAGGED
    referral.flag_reason = (reason or "")[:255]
    referral.save(update_fields=["status", "flag_reason"])


# ---------------------------------------------------------------------------
# Hold-period payout
# ---------------------------------------------------------------------------


def process_due_payouts() -> int:
    """Pay out any ACCRUED bonus whose payout_at has passed and whose
    referral is still ACTIVE. Returns count paid."""
    Bonus = get_bonus_model()
    Grant = get_grant_model()
    now = timezone.now()
    due: Iterable = (
        Bonus._default_manager
        .filter(status=BonusStatus.ACCRUED, payout_at__lte=now)
        .select_related("referral", "recipient")
    )
    paid = 0
    for bonus in due:
        if bonus.referral.status != ReferralStatus.ACTIVE:
            continue
        try:
            _apply_bonus(bonus, Grant)
            paid += 1
        except Exception:
            logger.exception("failed to apply bonus id=%s", bonus.pk)
    return paid


def _apply_bonus(bonus, Grant) -> None:
    handler = get_handler(bonus.reward_kind)
    from .rewards import Reward
    reward = Reward(
        kind=bonus.reward_kind,
        amount=bonus.amount,
        metadata=bonus.metadata,
    )
    with transaction.atomic():
        grant = Grant._default_manager.create(
            user=bonus.recipient,
            kind=bonus.reward_kind,
            amount=bonus.amount,
            metadata=bonus.metadata,
        )
        handler(bonus.recipient, reward, grant)
        bonus.status = BonusStatus.PAID
        bonus.paid_at = timezone.now()
        bonus.save(update_fields=["status", "paid_at"])


def clawback(bonus, reason: str, Grant=None):
    """Admin-confirmed clawback. Creates a reversal RewardGrant and sets
    bonus status to CLAWED_BACK."""
    if bonus.status != BonusStatus.PAID:
        raise ValueError("can only claw back a PAID bonus")
    Grant = Grant or get_grant_model()
    handler = get_handler(bonus.reward_kind)
    from .rewards import Reward
    reward = Reward(
        kind=bonus.reward_kind,
        amount=-bonus.amount,
        metadata={**(bonus.metadata or {}), "clawback": True, "reason": reason},
    )
    with transaction.atomic():
        grant = Grant._default_manager.create(
            user=bonus.recipient,
            kind=bonus.reward_kind,
            amount=-bonus.amount,
            metadata=reward.metadata,
            reversed_at=timezone.now(),
            reversal_reason=reason[:255],
        )
        handler(bonus.recipient, reward, grant)
        bonus.status = BonusStatus.CLAWED_BACK
        bonus.save(update_fields=["status"])
