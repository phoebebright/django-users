from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import Any, Callable, Optional

from django.utils.module_loading import import_string

from . import conf


@dataclass
class Reward:
    kind: str
    amount: Decimal = Decimal("0")
    metadata: dict = field(default_factory=dict)
    expires_at: Optional[datetime] = None


@dataclass
class RewardBundle:
    referrer_reward: Optional[Reward] = None
    referee_reward: Optional[Reward] = None

    def is_empty(self) -> bool:
        return self.referrer_reward is None and self.referee_reward is None


RewardApplier = Callable[[Any, Reward, Any], None]
# signature: (user, reward, grant_record) -> None


_HANDLERS: dict[str, RewardApplier] = {}


def register_handler(kind: str, handler: RewardApplier) -> None:
    _HANDLERS[kind] = handler


def get_handler(kind: str) -> RewardApplier:
    if kind not in _HANDLERS:
        raise KeyError(
            f"No reward handler registered for kind={kind!r}. "
            "Register one with rewards.register_handler()."
        )
    return _HANDLERS[kind]


def has_handler(kind: str) -> bool:
    return kind in _HANDLERS


def _default_credits_handler(user, reward: Reward, grant) -> None:
    path = conf.credits_grant_callable_path()
    if not path:
        raise RuntimeError(
            "REFERRALS_CREDITS_GRANT_CALLABLE is not configured. "
            "Either set it to a 'module.path:function' that applies credits, "
            "or register a custom 'credits' handler with rewards.register_handler()."
        )
    fn = import_string(path)
    fn(user, reward, grant)


register_handler("credits", _default_credits_handler)
