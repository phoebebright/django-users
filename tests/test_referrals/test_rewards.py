from decimal import Decimal

from django.test import TestCase

from django_users.referrals import rewards
from django_users.referrals.rewards import Reward, RewardBundle


class RewardTypeTests(TestCase):
    def test_reward_bundle_is_empty(self):
        self.assertTrue(RewardBundle().is_empty())
        self.assertFalse(
            RewardBundle(referrer_reward=Reward(kind="credits", amount=Decimal("1"))).is_empty()
        )

    def test_handler_registry_get_missing(self):
        with self.assertRaises(KeyError):
            rewards.get_handler("nonexistent_kind_xyz")

    def test_credits_handler_registered_by_default(self):
        self.assertTrue(rewards.has_handler("credits"))

    def test_register_and_retrieve_custom_handler(self):
        calls = []

        def my_handler(user, reward, grant):
            calls.append((user, reward.kind, reward.amount))

        rewards.register_handler("test_custom_kind", my_handler)
        try:
            h = rewards.get_handler("test_custom_kind")
            h("u", Reward(kind="test_custom_kind", amount=Decimal("3")), None)
            self.assertEqual(calls, [("u", "test_custom_kind", Decimal("3"))])
        finally:
            rewards._HANDLERS.pop("test_custom_kind", None)
