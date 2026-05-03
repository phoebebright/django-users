"""OIDC authentication backend for Authentik.

Subclasses ``mozilla_django_oidc.auth.OIDCAuthenticationBackend`` to:

* look up Django users by ``authentik_id`` (the OIDC ``sub`` claim),
* on first login, create the Django user from the ID-token claims and
  seed an email ``CommsChannel``,
* keep ``email``/``first_name``/``last_name`` in sync with the IdP on
  subsequent logins.

Wire up in settings::

    AUTHENTICATION_BACKENDS = [
        "django.contrib.auth.backends.ModelBackend",
        "django_users.oidc_backend.AuthentikOIDCBackend",
    ]

    OIDC_RP_CLIENT_ID     = AUTHENTIK["OIDC_CLIENT_ID"]
    OIDC_RP_CLIENT_SECRET = AUTHENTIK["OIDC_CLIENT_SECRET"]
    OIDC_OP_AUTHORIZATION_ENDPOINT = AUTHENTIK["OIDC_ISSUER"] + "authorize/"
    OIDC_OP_TOKEN_ENDPOINT         = AUTHENTIK["OIDC_ISSUER"] + "token/"
    OIDC_OP_USER_ENDPOINT          = AUTHENTIK["OIDC_ISSUER"] + "userinfo/"
    OIDC_OP_JWKS_ENDPOINT          = AUTHENTIK["OIDC_ISSUER"] + "jwks/"
    OIDC_RP_SIGN_ALGO              = "RS256"
    OIDC_VERIFY_SSL                = AUTHENTIK.get("VERIFY_SSL", True)
"""

from __future__ import annotations

import logging
from uuid import UUID

from django.contrib.auth import get_user_model
from mozilla_django_oidc.auth import OIDCAuthenticationBackend

logger = logging.getLogger(__name__)


def _coerce_uuid(value: str | UUID | None) -> UUID | None:
    if value is None or value == "":
        return None
    if isinstance(value, UUID):
        return value
    try:
        return UUID(str(value))
    except (TypeError, ValueError):
        return None


class AuthentikOIDCBackend(OIDCAuthenticationBackend):
    def filter_users_by_claims(self, claims: dict) -> "list":
        sub = _coerce_uuid(claims.get("sub"))
        if sub is None:
            return self.UserModel.objects.none()
        return self.UserModel.objects.filter(authentik_id=sub)

    def create_user(self, claims: dict):
        User = get_user_model()
        sub = _coerce_uuid(claims.get("sub"))
        email = claims.get("email", "")
        first_name = claims.get("given_name", "")
        last_name = claims.get("family_name", "")

        user = User.objects.create(
            email=email,
            username=email or str(sub),
            first_name=first_name,
            last_name=last_name,
            authentik_id=sub,
        )

        self._ensure_email_channel(user, email, verified=bool(claims.get("email_verified")))
        return user

    def update_user(self, user, claims: dict):
        changed = []
        email = claims.get("email")
        if email and user.email != email:
            user.email = email
            changed.append("email")
        first_name = claims.get("given_name")
        if first_name and user.first_name != first_name:
            user.first_name = first_name
            changed.append("first_name")
        last_name = claims.get("family_name")
        if last_name and user.last_name != last_name:
            user.last_name = last_name
            changed.append("last_name")
        if changed:
            user.save(update_fields=changed)

        if email:
            self._ensure_email_channel(
                user, email, verified=bool(claims.get("email_verified"))
            )
        return user

    @staticmethod
    def _ensure_email_channel(user, email: str, *, verified: bool) -> None:
        if not email:
            return
        try:
            from django.utils import timezone

            CommsChannel = user.comms_channels.model
        except (ImportError, AttributeError):
            logger.debug("CommsChannel relation not available on %s; skipping seed", type(user))
            return

        defaults = {}
        if verified:
            defaults["verified_at"] = timezone.now()

        CommsChannel.objects.get_or_create(
            user=user,
            channel_type="email",
            value=email,
            defaults=defaults,
        )
