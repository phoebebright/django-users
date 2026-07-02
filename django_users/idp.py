"""Authentik IdP adapter.

Single chokepoint for all communication with the Authentik admin REST API.
Every other module that needs to talk to the IdP goes through here.

Authentik has both an integer ``pk`` and a UUID for each user. The UUID is
what surfaces as the OIDC ``sub`` claim and is what we store on the Django
user model as ``authentik_id``. Some Authentik admin endpoints take the
integer pk in the URL; this module resolves pk from uuid as needed.

Configuration via Django settings::

    AUTHENTIK = {
        "URL":                "https://authentik.example.com",
        "OIDC_ISSUER":        "https://authentik.example.com/application/o/<slug>/",
        "OIDC_CLIENT_ID":     "...",
        "OIDC_CLIENT_SECRET": "...",
        "API_TOKEN":          "...",
        "VERIFY_SSL":         True,        # set False for local self-signed
    }
"""

from __future__ import annotations

import logging
import secrets
import string
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

import httpx
from django.conf import settings

logger = logging.getLogger(__name__)


class AuthentikError(Exception):
    """Raised for any non-2xx response from the Authentik API."""


def authentik_enabled() -> bool:
    """Return True when Authentik is the active IdP for this project.

    Resolution order:
      * ``USE_KEYCLOAK = True``   -> always False (project is on Keycloak).
      * ``AUTH_PROVIDER`` is set   -> True only when it equals ``"authentik"``.
      * ``AUTH_PROVIDER`` is unset -> legacy fallback: True when an
        ``AUTHENTIK`` dict is present in settings.

    Why ``AUTH_PROVIDER`` takes precedence over dict-presence: downstream
    projects define the ``AUTHENTIK`` config dict unconditionally so that
    switching providers is a one-line change. Treating "dict is present" as
    "Authentik is live" therefore fires IdP calls against a server that may
    not be running (ConnectError) whenever the active provider is really
    ``django`` or ``keycloak``.
    """
    if getattr(settings, "USE_KEYCLOAK", False):
        return False
    provider = getattr(settings, "AUTH_PROVIDER", None)
    if provider is not None:
        return provider == "authentik"
    return bool(getattr(settings, "AUTHENTIK", None))


@dataclass(frozen=True)
class AuthentikUser:
    pk: int
    uuid: UUID
    username: str
    email: str
    name: str
    is_active: bool
    attributes: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_api(cls, data: dict) -> "AuthentikUser":
        return cls(
            pk=int(data["pk"]),
            uuid=UUID(str(data["uuid"])),
            username=data.get("username", ""),
            email=data.get("email", ""),
            name=data.get("name", ""),
            is_active=bool(data.get("is_active", True)),
            attributes=dict(data.get("attributes") or {}),
        )


class AuthentikIdP:
    """Thin adapter over Authentik's REST API.

    Methods take the OIDC ``sub`` (a UUID) as the user identifier; pk is
    resolved internally where the API requires it.
    """

    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_token: str | None = None,
        verify_ssl: bool | None = None,
        timeout: float = 10.0,
    ) -> None:
        cfg = getattr(settings, "AUTHENTIK", {}) or {}
        self.base_url = (base_url or cfg.get("URL", "")).rstrip("/")
        self.api_token = api_token or cfg.get("API_TOKEN", "")
        self.verify_ssl = cfg.get("VERIFY_SSL", True) if verify_ssl is None else verify_ssl
        self.timeout = timeout

        if not self.base_url:
            raise AuthentikError("AUTHENTIK['URL'] is not configured.")
        if not self.api_token:
            raise AuthentikError("AUTHENTIK['API_TOKEN'] is not configured.")

    # ---- transport ----------------------------------------------------

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.base_url,
            headers={
                "Authorization": f"Bearer {self.api_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            verify=self.verify_ssl,
            timeout=self.timeout,
        )

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        with self._client() as client:
            response = client.request(method, path, **kwargs)
        if response.status_code >= 400:
            raise AuthentikError(
                f"Authentik {method} {path} returned {response.status_code}: {response.text}"
            )
        if response.status_code == 204 or not response.content:
            return None
        return response.json()

    # ---- read ---------------------------------------------------------

    def get_user(self, sub: UUID | str) -> AuthentikUser | None:
        result = self._request("GET", "/api/v3/core/users/", params={"uuid": str(sub)})
        items = result.get("results", []) if isinstance(result, dict) else []
        return AuthentikUser.from_api(items[0]) if items else None

    def find_by_email(self, email: str) -> AuthentikUser | None:
        result = self._request("GET", "/api/v3/core/users/", params={"email": email})
        items = result.get("results", []) if isinstance(result, dict) else []
        return AuthentikUser.from_api(items[0]) if items else None

    def _resolve_pk(self, sub: UUID | str) -> int:
        user = self.get_user(sub)
        if user is None:
            raise AuthentikError(f"Authentik has no user with uuid={sub}.")
        return user.pk

    # ---- write --------------------------------------------------------

    def create_user(
        self,
        *,
        email: str,
        first_name: str = "",
        last_name: str = "",
        attributes: dict[str, Any] | None = None,
    ) -> AuthentikUser:
        name = (f"{first_name} {last_name}").strip() or email
        payload = {
            "username": email,
            "email": email,
            "name": name,
            "is_active": True,
            "groups": [],
            "attributes": attributes or {},
            "path": "users",
        }
        data = self._request("POST", "/api/v3/core/users/", json=payload)
        return AuthentikUser.from_api(data)

    def set_password(self, sub: UUID | str, password: str) -> None:
        pk = self._resolve_pk(sub)
        self._request(
            "POST",
            f"/api/v3/core/users/{pk}/set_password/",
            json={"password": password},
        )

    def set_temporary_password(self, sub: UUID | str, length: int = 20) -> str:
        alphabet = string.ascii_letters + string.digits
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        self.set_password(sub, password)
        return password

    def set_must_change_password(self, sub: UUID | str, value: bool = True) -> None:
        """Set the ``must_change_password`` attribute on the user.

        Authentik has no first-class flag for forcing password change at next
        login. Convention is a custom attribute that the auth flow inspects
        via a policy, routing the user through a ``password_change`` stage
        and clearing the attribute afterwards.
        """
        user = self.get_user(sub)
        if user is None:
            raise AuthentikError(f"Authentik has no user with uuid={sub}.")
        attrs = dict(user.attributes)
        attrs["must_change_password"] = bool(value)
        self._request(
            "PATCH",
            f"/api/v3/core/users/{user.pk}/",
            json={"attributes": attrs},
        )

    def generate_recovery_link(self, sub: UUID | str) -> str:
        """Generate a single-use recovery link for the user.

        Returns the URL that takes the user through Authentik's recovery
        flow (verify identity → set new password). The link is signed and
        time-limited by Authentik.
        """
        pk = self._resolve_pk(sub)
        data = self._request("POST", f"/api/v3/core/users/{pk}/recovery/")
        if not isinstance(data, dict) or "link" not in data:
            raise AuthentikError(f"Unexpected recovery response: {data!r}")
        return data["link"]

    def mark_email_verified(self, sub: UUID | str) -> None:
        """Mark the user's email verified in Authentik attributes.

        Authentik has no first-class ``email_verified`` flag — gating happens
        in flow stages. We record verification in attributes so flows that
        check ``user.attributes.email_verified`` skip the verification stage.
        """
        user = self.get_user(sub)
        if user is None:
            raise AuthentikError(f"Authentik has no user with uuid={sub}.")
        attrs = dict(user.attributes)
        attrs["email_verified"] = True
        self._request(
            "PATCH",
            f"/api/v3/core/users/{user.pk}/",
            json={"attributes": attrs},
        )

    def logout(self, sub: UUID | str) -> None:
        """End all active sessions for the user."""
        pk = self._resolve_pk(sub)
        self._request("POST", f"/api/v3/core/users/{pk}/disable/", json={})

    def delete_user(self, sub: UUID | str) -> None:
        pk = self._resolve_pk(sub)
        self._request("DELETE", f"/api/v3/core/users/{pk}/")
