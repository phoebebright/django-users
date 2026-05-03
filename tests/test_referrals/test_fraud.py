from unittest.mock import MagicMock

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from django_users.referrals import fraud

User = get_user_model()


class FraudCheckTests(TestCase):
    def test_self_referral_blocks_when_same_pk(self):
        u = User.objects.create(username="a")
        result = fraud.check_self_referral(u, u)
        self.assertTrue(result.blocked)

    def test_self_referral_passes_for_different_users(self):
        u1 = User.objects.create(username="a")
        u2 = User.objects.create(username="b")
        self.assertFalse(fraud.check_self_referral(u1, u2).blocked)

    def test_email_overlap_blocks_on_current_email_match(self):
        u1 = MagicMock(email="same@example.com")
        u2 = MagicMock(email="SAME@example.com")
        result = fraud.check_email_overlap(u1, u2)
        self.assertTrue(result.blocked)

    def test_email_overlap_with_history_fn(self):
        u1 = MagicMock(email="primary@example.com")
        u2 = MagicMock(email="old@example.com")
        result = fraud.check_email_overlap(
            u1, u2, email_history_fn=lambda u: {"old@example.com"}
        )
        self.assertTrue(result.blocked)

    def test_payment_fingerprint_no_fp_in_event_passes(self):
        result = fraud.check_payment_fingerprint(None, None, {})
        self.assertFalse(result.blocked)

    def test_payment_fingerprint_blocks_on_match(self):
        with override_settings(
            REFERRALS_PAYMENT_FINGERPRINT_LOOKUP=(
                "tests.test_referrals.test_fraud._fp_lookup"
            )
        ):
            result = fraud.check_payment_fingerprint(
                MagicMock(), MagicMock(), {"payment_fingerprint": "X"}
            )
        self.assertTrue(result.blocked)

    def test_payment_fingerprint_passes_when_no_lookup_configured(self):
        # With no lookup configured, the check logs a warning and passes.
        result = fraud.check_payment_fingerprint(
            MagicMock(), MagicMock(), {"payment_fingerprint": "X"}
        )
        self.assertFalse(result.blocked)


def _fp_lookup(user):
    return {"X"}
