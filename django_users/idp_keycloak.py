"""Keycloak IdP adapter.

Mirror of :class:`django_users.idp.AuthentikIdP` for Keycloak, so views can
dispatch through ``get_idp()`` without caring which provider is live. Import
this module lazily (``get_idp()`` does) — python-keycloak is an optional
dependency and is only imported when a ``KeycloakIdP`` is instantiated.

Configuration via Django settings (same shape skorie hosts already use)::

    KEYCLOAK_CLIENTS = {
        "USERS": {
            "CLIENT_ID":     "...",
            "CLIENT_SECRET": "...",
            "URL":           "https://keycloak.example.com",
            "REALM":         "example",
        },
        ...
    }

The user identifier is Keycloak's user UUID, stored on the Django user model
as ``keycloak_id``.

Legacy module note: ``django_users.keycloak`` remains as a thin
deprecation shim over this adapter for hosts that import its functions
directly.
"""

from __future__ import annotations

import logging
import secrets
import string
from dataclasses import dataclass, field
from typing import Any

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from .idp import IdPError

logger = logging.getLogger(__name__)


class KeycloakError(IdPError):
    """Raised for any failed call to the Keycloak admin/OIDC API."""


@dataclass(frozen=True)
class KeycloakUser:
    id: str
    username: str
    email: str
    first_name: str
    last_name: str
    is_active: bool
    email_verified: bool
    required_actions: list = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_api(cls, data: dict) -> "KeycloakUser":
        return cls(
            id=str(data["id"]),
            username=data.get("username", ""),
            email=data.get("email", ""),
            first_name=data.get("firstName", ""),
            last_name=data.get("lastName", ""),
            is_active=bool(data.get("enabled", True)),
            email_verified=bool(data.get("emailVerified", False)),
            required_actions=list(data.get("requiredActions") or []),
            attributes=dict(data.get("attributes") or {}),
            raw=dict(data),
        )


class KeycloakIdP:
    """Thin adapter over the python-keycloak admin/OIDC clients.

    Methods take the Keycloak user UUID (``keycloak_id``) as the identifier.
    Instantiation raises ``ImproperlyConfigured`` when python-keycloak is not
    installed or KEYCLOAK_CLIENTS['USERS'] is missing/incomplete — same guard
    behaviour as ``AuthentikIdP``.
    """

    def __init__(self, *, config: dict | None = None) -> None:
        try:
            from keycloak import KeycloakAdmin, KeycloakOpenID
            from keycloak.exceptions import KeycloakAuthenticationError, KeycloakError as _KCError
        except ImportError as exc:
            raise ImproperlyConfigured(
                "AUTH_PROVIDER is 'keycloak' but python-keycloak is not installed. "
                "Install with: pip install 'django-users[keycloak]'"
            ) from exc

        self._KeycloakAdmin = KeycloakAdmin
        self._KeycloakOpenID = KeycloakOpenID
        self._KeycloakAuthenticationError = KeycloakAuthenticationError
        self._KeycloakLibError = _KCError

        cfg = config or (getattr(settings, "KEYCLOAK_CLIENTS", {}) or {}).get("USERS") or {}
        try:
            self.client_id = cfg["CLIENT_ID"]
            self.client_secret = cfg["CLIENT_SECRET"]
            self.base_url = cfg["URL"].rstrip("/")
            self.realm = cfg["REALM"]
        except KeyError as exc:
            raise ImproperlyConfigured(
                "KEYCLOAK_CLIENTS['USERS'] is missing or incomplete; needs "
                "CLIENT_ID, CLIENT_SECRET, URL and REALM."
            ) from exc
        if not all([self.client_id, self.client_secret, self.base_url, self.realm]):
            raise ImproperlyConfigured(
                "KEYCLOAK_CLIENTS['USERS'] has empty values; needs "
                "CLIENT_ID, CLIENT_SECRET, URL and REALM."
            )

        self._admin = None
        self._openid = None

    # ------------------------------------------------------------- clients

    @property
    def admin(self):
        if self._admin is None:
            self._admin = self._KeycloakAdmin(
                server_url=f"{self.base_url}/",
                realm_name=self.realm,
                client_id=self.client_id,
                client_secret_key=self.client_secret,
                verify=True,
            )
        return self._admin

    @property
    def openid(self):
        if self._openid is None:
            self._openid = self._KeycloakOpenID(
                server_url=f"{self.base_url}/",
                realm_name=self.realm,
                client_id=self.client_id,
                client_secret_key=self.client_secret,
            )
        return self._openid

    # ---------------------------------------------------- common interface

    def get_user(self, idp_id) -> KeycloakUser | None:
        try:
            data = self.admin.get_user(str(idp_id))
        except self._KeycloakLibError:
            return None
        return KeycloakUser.from_api(data) if data else None

    def find_by_email(self, email: str) -> KeycloakUser | None:
        try:
            user_id = self.admin.get_user_id(email)
            if not user_id:
                return None
            return KeycloakUser.from_api(self.admin.get_user(user_id))
        except self._KeycloakLibError as exc:
            logger.error("Failed to search user by email in Keycloak: %s", exc)
            return None

    def create_user(self, *, email: str, first_name: str = "",
                    last_name: str = "", attributes: dict | None = None) -> KeycloakUser:
        """Create a Keycloak user; if the email is already registered, return
        the existing user (preserves the 409-tolerant behaviour production
        relies on)."""
        payload = {
            "email": email,
            "username": email,
            "enabled": True,
            "firstName": first_name,
            "lastName": last_name,
            "requiredActions": [],
        }
        if attributes:
            payload["attributes"] = attributes
        try:
            user_id = self.admin.create_user(payload)
        except self._KeycloakLibError as exc:
            if getattr(exc, "response_code", None) == 409:
                user_id = self.admin.get_user_id(email)
                logger.info("Keycloak user for %s already exists (id %s)", email, user_id)
            else:
                raise KeycloakError(f"Failed to create user in Keycloak: {exc}") from exc
        else:
            logger.info("User created in Keycloak with ID %s (%s %s)", user_id, first_name, last_name)
        return KeycloakUser.from_api(self.admin.get_user(user_id))

    def set_password(self, idp_id, password: str) -> None:
        try:
            self.admin.set_user_password(user_id=str(idp_id), password=password, temporary=False)
        except self._KeycloakLibError as exc:
            raise KeycloakError(f"Failed to set password in Keycloak: {exc}") from exc

    def set_temporary_password(self, idp_id, length: int = 20) -> str:
        """Set a generated temporary password and return it.

        Note: Keycloak refuses direct-grant logins while a temporary password
        (UPDATE_PASSWORD required action) is outstanding, so the OTP login
        flow keeps its Django-side activation_code path; this method exists
        for interface parity and admin-driven resets.
        """
        alphabet = string.ascii_letters + string.digits
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        try:
            self.admin.set_user_password(user_id=str(idp_id), password=password, temporary=True)
        except self._KeycloakLibError as exc:
            raise KeycloakError(f"Failed to set temporary password in Keycloak: {exc}") from exc
        return password

    def set_must_change_password(self, idp_id, value: bool = True) -> None:
        actions = ["UPDATE_PASSWORD"] if value else []
        try:
            self.admin.update_user(user_id=str(idp_id), payload={"requiredActions": actions})
        except self._KeycloakLibError as exc:
            raise KeycloakError(f"Failed to update required actions in Keycloak: {exc}") from exc

    def mark_email_verified(self, idp_id) -> None:
        """Enable + mark verified without the email round-trip (same payload as
        the legacy ``verify_user_without_email``)."""
        payload = {"emailVerified": True, "enabled": True, "requiredActions": []}
        try:
            self.admin.update_user(user_id=str(idp_id), payload=payload)
            logger.info("User %s verified successfully in Keycloak", idp_id)
        except self._KeycloakLibError as exc:
            raise KeycloakError(f"Failed to verify user in Keycloak: {exc}") from exc

    def logout(self, idp_id) -> None:
        try:
            self.admin.user_logout(str(idp_id))
        except self._KeycloakLibError as exc:
            # Session may already be gone; log and continue like production did.
            logger.error("Failed to logout user %s from Keycloak: %s", idp_id, exc)

    def delete_user(self, idp_id) -> None:
        try:
            self.admin.delete_user(str(idp_id))
        except self._KeycloakLibError as exc:
            raise KeycloakError(f"Failed to delete user in Keycloak: {exc}") from exc

    # -------------------------------------------------- keycloak-only extras

    def verify_login(self, username: str, password: str) -> bool:
        """Validate credentials via a direct OIDC token grant (no session)."""
        try:
            self.openid.token(username=username, password=password)
        except self._KeycloakAuthenticationError:
            return False
        except self._KeycloakLibError as exc:
            logger.error("Keycloak verify_login failed for %s: %s", username, exc)
            return False
        return True

    def is_temporary_password(self, idp_id) -> bool:
        try:
            credentials = self.admin.get_credentials(str(idp_id))
        except self._KeycloakLibError as exc:
            logger.error("Error accessing Keycloak credentials API: %s", exc)
            return False
        return any(
            c.get("type") == "password" and c.get("temporary", False) for c in credentials
        )

    def clear_required_actions(self, idp_id) -> None:
        try:
            self.admin.update_user(user_id=str(idp_id), payload={"requiredActions": []})
            logger.info("Required actions cleared for user %s", idp_id)
        except self._KeycloakLibError as exc:
            raise KeycloakError(f"Failed to clear required actions in Keycloak: {exc}") from exc

    def get_access_token(self) -> str | None:
        try:
            token = self.openid.token(grant_type="client_credentials")
            return token["access_token"]
        except self._KeycloakLibError as exc:
            logger.error("Failed to get Keycloak access token: %s", exc)
            return None
