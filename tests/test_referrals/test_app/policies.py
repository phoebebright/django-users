"""Test BonusPolicy used across tests."""

from decimal import Decimal

from django_users.referrals.policies import BaseBonusPolicy
from django_users.referrals.rewards import Reward, RewardBundle


class SimpleTestPolicy(BaseBonusPolicy):
    declared_events = ("referee_scored_test", "referee_purchased")

    def calculate_bonus(self, referral, event_name, event_data):
        if event_name == "referee_scored_test":
            return RewardBundle(
                referrer_reward=Reward(kind="credits", amount=Decimal("5")),
            )
        if event_name == "referee_purchased":
            return RewardBundle(
                referrer_reward=Reward(kind="credits", amount=Decimal("25")),
                referee_reward=Reward(kind="credits", amount=Decimal("10")),
            )
        return None
