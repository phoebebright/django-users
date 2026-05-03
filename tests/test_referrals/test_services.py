from decimal import Decimal

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from django_users.referrals import services
from django_users.referrals.models import BonusStatus, ReferralStatus
from django_users.referrals.policies import reset_policy_cache

from tests.test_referrals.test_app.handlers import pop_credits_log
from tests.test_referrals.test_app.models import ReferralBonus, ReferralCode, Referral

User = get_user_model()


POLICY = "tests.test_referrals.test_app.policies.SimpleTestPolicy"


@override_settings(REFERRALS_BONUS_POLICY=POLICY)
class CodeGenerationTests(TestCase):
    def setUp(self):
        reset_policy_cache()
        self.user = User.objects.create(username="alice")

    def test_get_or_create_code_is_idempotent(self):
        code1 = services.get_or_create_code(self.user)
        code2 = services.get_or_create_code(self.user)
        self.assertEqual(code1, code2)
        self.assertEqual(ReferralCode.objects.count(), 1)

    def test_resolve_code_is_case_insensitive(self):
        code = services.get_or_create_code(self.user)
        self.assertEqual(services.resolve_code(code.upper()), self.user)
        self.assertEqual(services.resolve_code(code.lower()), self.user)

    def test_resolve_code_unknown_returns_none(self):
        self.assertIsNone(services.resolve_code("does-not-exist"))
        self.assertIsNone(services.resolve_code(""))
        self.assertIsNone(services.resolve_code(None))


@override_settings(REFERRALS_BONUS_POLICY=POLICY)
class AttributionTests(TestCase):
    def setUp(self):
        reset_policy_cache()
        self.referrer = User.objects.create(username="ref", email="ref@example.com")
        self.referee = User.objects.create(username="new", email="new@example.com")
        self.code = services.get_or_create_code(self.referrer)

    def test_attribute_creates_referral(self):
        r = services.attribute(self.referee, self.code)
        self.assertIsNotNone(r)
        self.assertEqual(r.referrer, self.referrer)
        self.assertEqual(r.referee, self.referee)
        self.assertEqual(r.status, ReferralStatus.ACTIVE)

    def test_first_touch_wins(self):
        r1 = services.attribute(self.referee, self.code)
        other = User.objects.create(username="other")
        other_code = services.get_or_create_code(other)
        r2 = services.attribute(self.referee, other_code)
        self.assertEqual(r1.pk, r2.pk)
        self.assertEqual(Referral.objects.count(), 1)

    def test_self_referral_blocked(self):
        r = services.attribute(self.referrer, self.code)
        self.assertIsNone(r)
        self.assertEqual(Referral.objects.count(), 0)

    def test_shared_email_blocked(self):
        referee = User.objects.create(username="dup", email="ref@example.com")
        r = services.attribute(referee, self.code)
        self.assertIsNone(r)

    def test_unknown_code_returns_none(self):
        self.assertIsNone(services.attribute(self.referee, "nonexistent"))


@override_settings(REFERRALS_BONUS_POLICY=POLICY, REFERRALS_HOLD_PERIOD_DAYS=7)
class DispatchTests(TestCase):
    def setUp(self):
        reset_policy_cache()
        pop_credits_log()
        self.referrer = User.objects.create(username="ref", email="ref@example.com")
        self.referee = User.objects.create(username="new", email="new@example.com")
        services.attribute(
            self.referee, services.get_or_create_code(self.referrer)
        )

    def test_dispatch_test_score_bonus_referrer_only(self):
        created = services.dispatch(
            "referee_scored_test", self.referee, event_ref="test-1"
        )
        self.assertEqual(len(created), 1)
        bonus = created[0]
        self.assertEqual(bonus.recipient, self.referrer)
        self.assertEqual(bonus.recipient_role, "referrer")
        self.assertEqual(bonus.amount, Decimal("5"))
        self.assertEqual(bonus.status, BonusStatus.ACCRUED)
        self.assertGreater(bonus.payout_at, timezone.now())

    def test_dispatch_two_sided_purchase_bonus(self):
        created = services.dispatch(
            "referee_purchased", self.referee, event_ref="order-42"
        )
        self.assertEqual(len(created), 2)
        roles = {b.recipient_role for b in created}
        self.assertEqual(roles, {"referrer", "referee"})

    def test_dispatch_is_idempotent_per_event_ref_and_role(self):
        services.dispatch("referee_scored_test", self.referee, event_ref="t1")
        again = services.dispatch("referee_scored_test", self.referee, event_ref="t1")
        self.assertEqual(again, [])
        self.assertEqual(ReferralBonus.objects.count(), 1)

    def test_dispatch_without_referral_is_noop(self):
        stranger = User.objects.create(username="nobody")
        created = services.dispatch("referee_scored_test", stranger, event_ref="x")
        self.assertEqual(created, [])

    def test_dispatch_skips_flagged_referral(self):
        referral = Referral.objects.get(referee=self.referee)
        referral.status = ReferralStatus.DISABLED
        referral.save()
        created = services.dispatch("referee_scored_test", self.referee, event_ref="t1")
        self.assertEqual(created, [])

    def test_payment_fingerprint_match_flags_referral(self):
        with override_settings(
            REFERRALS_PAYMENT_FINGERPRINT_LOOKUP=(
                "tests.test_referrals.test_services.fake_fingerprints"
            )
        ):
            services.dispatch(
                "referee_purchased",
                self.referee,
                event_ref="order-1",
                event_data={"payment_fingerprint": "FP_SHARED"},
            )
        referral = Referral.objects.get(referee=self.referee)
        self.assertEqual(referral.status, ReferralStatus.FLAGGED)
        self.assertIn("payment method", referral.flag_reason)
        self.assertEqual(ReferralBonus.objects.count(), 0)


def fake_fingerprints(user):
    return {"FP_SHARED"}


@override_settings(REFERRALS_BONUS_POLICY=POLICY)
class PayoutTests(TestCase):
    def setUp(self):
        reset_policy_cache()
        pop_credits_log()
        self.referrer = User.objects.create(username="ref", email="ref@example.com")
        self.referee = User.objects.create(username="new", email="new@example.com")
        services.attribute(
            self.referee, services.get_or_create_code(self.referrer)
        )

    def test_process_due_payouts_pays_out_and_moves_to_paid(self):
        services.dispatch("referee_scored_test", self.referee, event_ref="t1")
        bonus = ReferralBonus.objects.get()
        # Force the bonus past its hold period.
        bonus.payout_at = timezone.now() - timezone.timedelta(minutes=1)
        bonus.save(update_fields=["payout_at"])

        paid = services.process_due_payouts()
        self.assertEqual(paid, 1)

        bonus.refresh_from_db()
        self.assertEqual(bonus.status, BonusStatus.PAID)
        self.assertIsNotNone(bonus.paid_at)

        log = pop_credits_log()
        self.assertEqual(len(log), 1)
        user_pk, amount, _metadata = log[0]
        self.assertEqual(user_pk, self.referrer.pk)
        self.assertEqual(amount, Decimal("5"))

    def test_payout_skips_bonuses_still_in_hold(self):
        services.dispatch("referee_scored_test", self.referee, event_ref="t1")
        paid = services.process_due_payouts()
        self.assertEqual(paid, 0)

    def test_clawback_creates_reversal_and_marks_bonus(self):
        services.dispatch("referee_scored_test", self.referee, event_ref="t1")
        bonus = ReferralBonus.objects.get()
        bonus.payout_at = timezone.now() - timezone.timedelta(minutes=1)
        bonus.save(update_fields=["payout_at"])
        services.process_due_payouts()
        pop_credits_log()

        bonus.refresh_from_db()
        services.clawback(bonus, reason="refund")
        bonus.refresh_from_db()
        self.assertEqual(bonus.status, BonusStatus.CLAWED_BACK)
        log = pop_credits_log()
        self.assertEqual(len(log), 1)
        _user_pk, amount, metadata = log[0]
        self.assertEqual(amount, Decimal("-5"))
        self.assertTrue(metadata.get("clawback"))
