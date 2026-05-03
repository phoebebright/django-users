"""Runtime registry of the host app's concrete referral models.

Host apps call `register_models()` from their AppConfig.ready() to wire up
their concrete subclasses of the abstract models. Services look the models
up here at call time — this keeps the module free of any assumption about
where the concretes live.
"""

from typing import Optional, Type

from django.db.models import Model


class _ModelRegistry:
    code: Optional[Type[Model]] = None
    referral: Optional[Type[Model]] = None
    bonus: Optional[Type[Model]] = None
    grant: Optional[Type[Model]] = None


_registry = _ModelRegistry()


def register_models(*, code=None, referral=None, bonus=None, grant=None) -> None:
    if code is not None:
        _registry.code = code
    if referral is not None:
        _registry.referral = referral
    if bonus is not None:
        _registry.bonus = bonus
    if grant is not None:
        _registry.grant = grant


def _require(name: str, model):
    if model is None:
        raise RuntimeError(
            f"django_users.referrals: no concrete {name} model registered. "
            "Call referrals.registry.register_models(...) from your "
            "AppConfig.ready()."
        )
    return model


def get_code_model():
    return _require("code", _registry.code)


def get_referral_model():
    return _require("referral", _registry.referral)


def get_bonus_model():
    return _require("bonus", _registry.bonus)


def get_grant_model():
    return _require("grant", _registry.grant)


def is_configured() -> bool:
    return all([_registry.code, _registry.referral, _registry.bonus, _registry.grant])


def reset() -> None:
    """Test hook."""
    _registry.code = None
    _registry.referral = None
    _registry.bonus = None
    _registry.grant = None
