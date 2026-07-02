"""System checks for the Authentik integration.

Two checks:
  * ``check_authentik_settings`` - fast, always runs. Validates the AUTHENTIK
    settings dict has the required keys. Only active when
    ``AUTH_PROVIDER == "authentik"``.
  * ``check_authentik_reachable`` - slow, network-touching. Tagged so it only
    runs under ``manage.py check --deploy`` (or explicitly via ``--tag idp``).

Run::

    python manage.py check                  # settings shape only
    python manage.py check --deploy         # also probes Authentik
    python manage.py check --tag idp        # only the IdP-related checks

These checks live in django-users so every host project gets them for free;
they are registered automatically from ``DjangoUsersConfig.ready``.
"""

from __future__ import annotations

import json
import socket
import ssl
import urllib.error
import urllib.request

from django.conf import settings
from django.core.checks import Error, Tags, Warning, register

REQUIRED_KEYS = ("URL", "OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "API_TOKEN")


@register("idp")
def check_authentik_settings(app_configs, **kwargs):
    # Only Authentik needs the AUTHENTIK config; Keycloak and plain Django auth
    # do not.
    if getattr(settings, "AUTH_PROVIDER", None) != "authentik":
        return []
    cfg = getattr(settings, "AUTHENTIK", None)
    if cfg is None:
        return [
            Error(
                "AUTHENTIK setting is missing.",
                hint=(
                    "Add an AUTHENTIK dict to settings_local.py with keys: "
                    + ", ".join(REQUIRED_KEYS)
                ),
                id="django_users.E001",
            )
        ]

    if not isinstance(cfg, dict):
        return [Error("AUTHENTIK setting must be a dict.", id="django_users.E002")]

    errors = []
    for idx, key in enumerate(REQUIRED_KEYS):
        if not cfg.get(key):
            errors.append(
                Error(
                    f"AUTHENTIK[{key!r}] is missing or empty.",
                    hint=f"Set AUTHENTIK[{key!r}] in settings_local.py.",
                    id=f"django_users.E{10 + idx:03d}",
                )
            )
    return errors


@register(Tags.security, "idp", deploy=True)
def check_authentik_reachable(app_configs, **kwargs):
    if getattr(settings, "AUTH_PROVIDER", None) != "authentik":
        return []
    cfg = getattr(settings, "AUTHENTIK", None)
    if not cfg:
        return []

    issuer = (cfg.get("OIDC_ISSUER") or "").rstrip("/")
    if not issuer:
        return []

    discovery_url = f"{issuer}/.well-known/openid-configuration"
    req = urllib.request.Request(discovery_url, headers={"User-Agent": "django-users-check"})

    verify_ssl = cfg.get("VERIFY_SSL", True)
    ssl_ctx = None if verify_ssl else ssl._create_unverified_context()

    try:
        with urllib.request.urlopen(req, timeout=5, context=ssl_ctx) as resp:
            if resp.status != 200:
                return [
                    Warning(
                        f"Authentik discovery returned HTTP {resp.status} at {discovery_url}",
                        id="django_users.W001",
                    )
                ]
            data = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return [
            Warning(
                f"Authentik discovery returned HTTP {exc.code} at {discovery_url}",
                hint="Check OIDC_ISSUER matches the Application slug in Authentik.",
                id="django_users.W001",
            )
        ]
    except (urllib.error.URLError, socket.timeout, TimeoutError) as exc:
        return [
            Warning(
                f"Could not reach Authentik at {discovery_url}: {exc}",
                hint="Is Authentik running? Try: docker compose ps in the authentik dir.",
                id="django_users.W002",
            )
        ]
    except json.JSONDecodeError as exc:
        return [
            Warning(
                f"Authentik discovery did not return valid JSON: {exc}",
                id="django_users.W003",
            )
        ]

    warnings = []
    if "authorization_endpoint" not in data:
        warnings.append(
            Warning(
                f"Discovery doc missing authorization_endpoint at {discovery_url}",
                id="django_users.W004",
            )
        )
    if "jwks_uri" not in data:
        warnings.append(
            Warning(
                f"Discovery doc missing jwks_uri at {discovery_url}",
                id="django_users.W005",
            )
        )

    server_issuer = (data.get("issuer") or "").rstrip("/")
    if server_issuer and server_issuer != issuer:
        warnings.append(
            Warning(
                f"OIDC_ISSUER mismatch: configured {issuer!r}, server reports {server_issuer!r}",
                hint="Update AUTHENTIK['OIDC_ISSUER'] to match the server's issuer exactly.",
                id="django_users.W006",
            )
        )

    return warnings