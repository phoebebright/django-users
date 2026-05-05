"""Apply the must-change-password flow gate to Authentik via the REST API.

Same end state as ``blueprints/must_change_password.yaml`` — pick whichever
deployment path suits you. This command is idempotent: it looks each
object up by its identifier (name / field_key / target+stage) and only
creates what's missing, only patches what's drifted.

Usage::

    python manage.py setup_authentik_must_change
    python manage.py setup_authentik_must_change --flow-slug my-auth-flow
    python manage.py setup_authentik_must_change --remove
"""

from __future__ import annotations

import textwrap
from typing import Any

from django.core.management.base import BaseCommand, CommandError

from django_users.idp import AuthentikIdP, AuthentikError


# ---- desired state ---------------------------------------------------------

POLICIES = {
    "must_change_password_pending": {
        "expression": (
            'return bool(request.user.attributes.get("must_change_password"))'
        ),
        "execution_logging": False,
    },
    "clear_must_change_password": {
        "expression": textwrap.dedent(
            """
            user = request.user
            attrs = dict(user.attributes or {})
            attrs.pop("must_change_password", None)
            user.attributes = attrs
            user.save()
            return True
            """
        ).strip(),
        "execution_logging": False,
    },
}

PROMPT_FIELDS = {
    "must_change_password": {
        "label": "New password",
        "type": "password",
        "required": True,
        "placeholder": "New password",
        "order": 0,
    },
    "must_change_password_repeat": {
        "label": "Confirm new password",
        "type": "password",
        "required": True,
        "placeholder": "Confirm new password",
        "order": 1,
    },
}

PROMPT_STAGE_NAME = "prompt-set-new-password"
USER_WRITE_STAGE_NAME = "user-write-new-password"


# ---- command ---------------------------------------------------------------


class Command(BaseCommand):
    help = "Configure Authentik to force password change when must_change_password=True."

    def add_arguments(self, parser):
        parser.add_argument(
            "--flow-slug",
            default="default-authentication-flow",
            help="Slug of the authentication flow to bind into.",
        )
        parser.add_argument(
            "--prompt-order",
            type=int,
            default=30,
            help="Stage-binding order for the prompt stage (write goes at order+1).",
        )
        parser.add_argument(
            "--recovery-slug",
            default="default-recovery-flow",
            help="Slug to use for the recovery flow (created if missing).",
        )
        parser.add_argument(
            "--skip-recovery",
            action="store_true",
            help="Skip recovery-flow creation/wiring (only set up the must-change gate).",
        )
        parser.add_argument(
            "--remove",
            action="store_true",
            help="Remove the bindings (keeps policies/stages so you can re-bind).",
        )

    def handle(self, *args, flow_slug: str, prompt_order: int,
               recovery_slug: str, skip_recovery: bool, remove: bool, **opts):
        idp = AuthentikIdP()
        api = AuthentikAdminAPI(idp)

        flow = api.find_one("/api/v3/flows/instances/", {"slug": flow_slug})
        if not flow:
            raise CommandError(
                f"Authentication flow with slug '{flow_slug}' not found."
            )
        flow_uuid = flow["pk"]
        self.stdout.write(self.style.NOTICE(f"Flow: {flow['name']} ({flow_uuid})"))

        if remove:
            return self._remove(api, flow_uuid)

        # ---- policies ------------------------------------------------------
        policy_pks: dict[str, str] = {}
        for name, attrs in POLICIES.items():
            pk = api.upsert(
                list_url="/api/v3/policies/expression/",
                detail_url_tpl="/api/v3/policies/expression/{pk}/",
                lookup={"name": name},
                payload={"name": name, **attrs},
                writer=self.stdout,
            )
            policy_pks[name] = pk

        # ---- prompt fields -------------------------------------------------
        prompt_pks: dict[str, str] = {}
        for field_key, attrs in PROMPT_FIELDS.items():
            pk = api.upsert(
                list_url="/api/v3/stages/prompt/prompts/",
                detail_url_tpl="/api/v3/stages/prompt/prompts/{pk}/",
                lookup={"field_key": field_key},
                payload={"field_key": field_key, "name": field_key, **attrs},
                writer=self.stdout,
            )
            prompt_pks[field_key] = pk

        # ---- prompt stage --------------------------------------------------
        # Authentik nests the prompt stage under .../prompt/stages/ because
        # the prompt subapp also exposes prompt fields at .../prompt/prompts/.
        prompt_stage_pk = api.upsert(
            list_url="/api/v3/stages/prompt/stages/",
            detail_url_tpl="/api/v3/stages/prompt/stages/{pk}/",
            lookup={"name": PROMPT_STAGE_NAME},
            payload={
                "name": PROMPT_STAGE_NAME,
                "fields": list(prompt_pks.values()),
            },
            writer=self.stdout,
        )

        # ---- user write stage ----------------------------------------------
        write_stage_pk = api.upsert(
            list_url="/api/v3/stages/user_write/",
            detail_url_tpl="/api/v3/stages/user_write/{pk}/",
            lookup={"name": USER_WRITE_STAGE_NAME},
            payload={
                "name": USER_WRITE_STAGE_NAME,
                "user_creation_mode": "never_create",
            },
            writer=self.stdout,
        )

        # ---- flow stage bindings -------------------------------------------
        # upsert_binding returns the binding's policybindingmodel_ptr_id —
        # that's what PolicyBinding.target expects, not the binding's own pk.
        prompt_binding_target = api.upsert_binding(
            flow_uuid=flow_uuid,
            stage_pk=prompt_stage_pk,
            order=prompt_order,
            writer=self.stdout,
        )
        write_binding_target = api.upsert_binding(
            flow_uuid=flow_uuid,
            stage_pk=write_stage_pk,
            order=prompt_order + 1,
            writer=self.stdout,
        )

        # ---- policy bindings -----------------------------------------------
        api.upsert_policy_binding(
            target_pk=prompt_binding_target,
            policy_pk=policy_pks["must_change_password_pending"],
            order=0,
            writer=self.stdout,
        )
        api.upsert_policy_binding(
            target_pk=write_binding_target,
            policy_pk=policy_pks["must_change_password_pending"],
            order=0,
            writer=self.stdout,
        )
        api.upsert_policy_binding(
            target_pk=write_binding_target,
            policy_pk=policy_pks["clear_must_change_password"],
            order=1,
            writer=self.stdout,
        )

        self.stdout.write(self.style.SUCCESS("Authentik must-change-password gate installed."))

        if not skip_recovery:
            self._setup_recovery_flow(
                api, recovery_slug, prompt_stage_pk, write_stage_pk,
            )

    def _setup_recovery_flow(
        self, api: "AuthentikAdminAPI", slug: str,
        prompt_stage_pk: str, write_stage_pk: str,
    ):
        """Ensure a recovery flow exists, has the prompt + write stages bound
        to it (no policies — always-on), and is set as the default brand's
        ``flow_recovery``. Reuses the must-change stages so we don't
        duplicate prompt fields.
        """
        # 1. Find or create the recovery flow itself.
        flow = api.find_one("/api/v3/flows/instances/", {"slug": slug})
        if not flow:
            payload = {
                "name": "Recovery flow",
                "slug": slug,
                "title": "Reset your password",
                "designation": "recovery",
                "authentication": "none",
                "denied_action": "message_continue",
                "policy_engine_mode": "any",
                "layout": "stacked",
            }
            flow = api._request("POST", "/api/v3/flows/instances/", json=payload)
            self.stdout.write(f"  created recovery flow → {flow['pk']}")
        else:
            self.stdout.write(f"  ok      recovery flow → {flow['pk']}")
        recovery_flow_uuid = flow["pk"]

        # 2. Bind the prompt + user-write stages (no policies — always run on
        #    this flow; the recovery link itself is the gate).
        api.upsert_binding(
            flow_uuid=recovery_flow_uuid, stage_pk=prompt_stage_pk,
            order=10, writer=self.stdout,
        )
        api.upsert_binding(
            flow_uuid=recovery_flow_uuid, stage_pk=write_stage_pk,
            order=20, writer=self.stdout,
        )

        # 3. Set flow_recovery on every brand we'll hit at runtime.
        #
        #    Authentik routes API requests to a brand by Host header — the
        #    one whose ``domain`` matches the request's hostname wins. The
        #    "default" flag is only the fallback when nothing matches. So
        #    if our AUTHENTIK URL points at e.g. ``localhost:9000``, the
        #    matching brand is ``localhost:9000`` (default=false), not
        #    ``authentik-default`` (default=true). We patch both: the
        #    runtime-matching brand *and* the default, so admin-UI users
        #    hitting either get a working recovery flow.
        from urllib.parse import urlparse
        from django.conf import settings as _settings
        parsed = urlparse(_settings.AUTHENTIK.get("URL", ""))
        runtime_host = parsed.hostname or ""
        runtime_domain_candidates = {
            runtime_host,
            f"{runtime_host}:{parsed.port}" if parsed.port else "",
        }
        runtime_domain_candidates.discard("")

        all_brands = api.find_all("/api/v3/core/brands/", {"page_size": 100})
        targets: list[dict] = []
        for b in all_brands:
            if b.get("default") or b.get("domain") in runtime_domain_candidates:
                targets.append(b)
        if not targets:
            self.stdout.write(self.style.WARNING(
                "  no matching brand found — set flow_recovery manually in Authentik admin."
            ))
            return

        for brand in targets:
            brand_pk = brand.get("brand_uuid") or brand.get("pk")
            label = f"brand {brand.get('domain')!r} (default={brand.get('default')})"
            if brand.get("flow_recovery") == recovery_flow_uuid:
                self.stdout.write(f"  ok      {label} flow_recovery → already {recovery_flow_uuid}")
            else:
                api._request(
                    "PATCH",
                    f"/api/v3/core/brands/{brand_pk}/",
                    json={"flow_recovery": recovery_flow_uuid},
                )
                self.stdout.write(f"  patched {label} flow_recovery → {recovery_flow_uuid}")

        self.stdout.write(self.style.SUCCESS(
            f"Authentik recovery flow installed and wired to {len(targets)} brand(s)."
        ))

    def _remove(self, api: "AuthentikAdminAPI", flow_uuid: str):
        """Delete the bindings only — leave policies/stages in place.

        Removing those would orphan their associations elsewhere; the user
        can drop them manually if they really want a clean slate.
        """
        for stage_name in (PROMPT_STAGE_NAME, USER_WRITE_STAGE_NAME):
            stage = api.find_one("/api/v3/stages/all/", {"name": stage_name})
            if not stage:
                continue
            bindings = api.find_all(
                "/api/v3/flows/bindings/",
                {"target": flow_uuid, "stage": stage["pk"]},
            )
            for b in bindings:
                api.delete(f"/api/v3/flows/bindings/{b['pk']}/")
                self.stdout.write(self.style.WARNING(
                    f"Deleted binding {b['pk']} (stage {stage_name})"
                ))
        self.stdout.write(self.style.SUCCESS("Bindings removed."))


# ---- thin wrapper around AuthentikIdP._request -----------------------------


class AuthentikAdminAPI:
    """Generic CRUD against Authentik's admin REST API.

    Reuses the auth/transport from :class:`AuthentikIdP`. Kept inside this
    command file rather than promoted to ``idp.py`` because flow-config is
    a setup concern, not part of the runtime user-management surface.
    """

    def __init__(self, idp: AuthentikIdP) -> None:
        self.idp = idp

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        return self.idp._request(method, path, **kwargs)

    # ---- generic helpers --------------------------------------------------

    def find_one(self, url: str, params: dict) -> dict | None:
        result = self._request("GET", url, params=params)
        items = result.get("results") if isinstance(result, dict) else None
        return items[0] if items else None

    def find_all(self, url: str, params: dict) -> list[dict]:
        result = self._request("GET", url, params=params)
        return result.get("results", []) if isinstance(result, dict) else []

    def delete(self, url: str) -> None:
        self._request("DELETE", url)

    def upsert(
        self,
        list_url: str,
        detail_url_tpl: str,
        lookup: dict,
        payload: dict,
        writer=None,
    ) -> str:
        existing = self.find_one(list_url, lookup)
        if existing:
            pk = existing["pk"]
            if _needs_patch(existing, payload):
                self._request("PATCH", detail_url_tpl.format(pk=pk), json=payload)
                _log(writer, f"  patched {list_url} ({lookup}) → {pk}")
            else:
                _log(writer, f"  ok      {list_url} ({lookup}) → {pk}")
            return pk
        created = self._request("POST", list_url, json=payload)
        pk = created["pk"]
        _log(writer, f"  created {list_url} ({lookup}) → {pk}")
        return pk

    # ---- bindings (slightly bespoke; identifier is target+stage+order) ----

    def upsert_binding(
        self, flow_uuid: str, stage_pk: str, order: int, writer=None
    ) -> str:
        """Create/update a FlowStageBinding. Returns the binding's
        ``policybindingmodel_ptr_id`` — the UUID PolicyBinding.target expects.
        """
        existing = self.find_one(
            "/api/v3/flows/bindings/",
            {"target": flow_uuid, "stage": stage_pk},
        )
        payload = {
            "target": flow_uuid,
            "stage": stage_pk,
            "order": order,
            "evaluate_on_plan": True,
            "re_evaluate_policies": True,
            "policy_engine_mode": "any",
        }
        if existing:
            pk = existing["pk"]
            if _needs_patch(existing, payload):
                self._request("PATCH", f"/api/v3/flows/bindings/{pk}/", json=payload)
                _log(writer, f"  patched flow-stage binding (stage={stage_pk}) → {pk}")
            else:
                _log(writer, f"  ok      flow-stage binding (stage={stage_pk}) → {pk}")
            return existing["policybindingmodel_ptr_id"]
        created = self._request("POST", "/api/v3/flows/bindings/", json=payload)
        pk = created["pk"]
        _log(writer, f"  created flow-stage binding (stage={stage_pk}) → {pk}")
        return created["policybindingmodel_ptr_id"]

    def upsert_policy_binding(
        self, target_pk: str, policy_pk: str, order: int, writer=None
    ) -> str:
        existing = self.find_one(
            "/api/v3/policies/bindings/",
            {"target": target_pk, "policy": policy_pk},
        )
        payload = {
            "target": target_pk,
            "policy": policy_pk,
            "order": order,
            "enabled": True,
        }
        if existing:
            pk = existing["pk"]
            if _needs_patch(existing, payload):
                self._request("PATCH", f"/api/v3/policies/bindings/{pk}/", json=payload)
                _log(writer, f"  patched policy binding (target={target_pk}) → {pk}")
            else:
                _log(writer, f"  ok      policy binding (target={target_pk}) → {pk}")
            return pk
        created = self._request("POST", "/api/v3/policies/bindings/", json=payload)
        pk = created["pk"]
        _log(writer, f"  created policy binding (target={target_pk}) → {pk}")
        return pk


def _needs_patch(existing: dict, desired: dict) -> bool:
    """True if any key in ``desired`` differs from ``existing``."""
    for k, v in desired.items():
        if existing.get(k) != v:
            return True
    return False


def _log(writer, msg: str) -> None:
    if writer is not None:
        writer.write(msg)
