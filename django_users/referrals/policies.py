from typing import Any, Optional

from django.utils.module_loading import import_string

from . import conf
from .rewards import RewardBundle


class BaseBonusPolicy:
    """Host apps subclass this and point REFERRALS_BONUS_POLICY at the subclass.

    Override `calculate_bonus`. Return a RewardBundle (possibly with only one
    side filled in) or None to skip the event.

    Optionally override `declared_events` to list the event names this policy
    handles; the dispatcher warns on unknown events.
    """

    declared_events: tuple[str, ...] = ()

    def calculate_bonus(
        self,
        referral: Any,
        event_name: str,
        event_data: dict,
    ) -> Optional[RewardBundle]:
        raise NotImplementedError


class NullBonusPolicy(BaseBonusPolicy):
    """Used when no policy is configured — never awards anything."""

    def calculate_bonus(self, referral, event_name, event_data):
        return None


_cached_policy: Optional[BaseBonusPolicy] = None


def get_active_policy() -> BaseBonusPolicy:
    global _cached_policy
    if _cached_policy is not None:
        return _cached_policy
    path = conf.bonus_policy_path()
    if not path:
        _cached_policy = NullBonusPolicy()
    else:
        cls = import_string(path)
        _cached_policy = cls()
    return _cached_policy


def reset_policy_cache() -> None:
    """Test hook — clears the cached policy so settings changes take effect."""
    global _cached_policy
    _cached_policy = None
