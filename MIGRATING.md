# Migrating to the `authentik` branch

This document describes how a project on `main` (Keycloak) moves to
`authentik`. Skorie4 is a fresh project so doesn't need a migration; this
guide is for sibling projects (skorie1, skorie3, whinnie, builtair) when
their turn comes.

> **TL;DR:** the `authentik` branch is intentionally clean — no KC code,
> no `keycloak_id` placeholder field. Sibling projects need to design
> their own transition strategy (e.g. dual-field window) since this
> branch alone won't bridge for them.

## What changed on the package

- Single new IdP-aware field on the user model: `authentik_id`.
  `keycloak_id` is gone from `CustomUserBase`.
- All KC admin API helpers replaced by `django_users.idp.AuthentikIdP`.
- OIDC backend (`django_users.oidc_backend.AuthentikOIDCBackend`)
  replaces `django_keycloak_admin.backends.*`.
- `LoginView`, `Troubleshoot`, `ProblemSignup`, `ProblemLogin`,
  `UserMigrationView`, `UnverifiedUsersList`, `update_users`, and the
  KC admin endpoints (`CheckEmailInKeycloak[Public]`,
  `add_to_keycloak`) are removed.
- `KEYCLOAK_*` settings are no longer read.

## Migration shape (for an existing project)

1. **Stand up Authentik** alongside the running Keycloak instance.
2. **Branch your project**, switch its `requirements.txt` to point at
   `django-users@authentik`, and resolve the import diff.
3. **Add `authentik_id` alongside `keycloak_id`** on your concrete user
   model — the dual-field window from the consolidation decision.
4. **Backfill**: a one-shot script that, for each user with
   `keycloak_id`, creates the user in Authentik via
   `AuthentikIdP.create_user` and stores the resulting UUID in
   `authentik_id`. Passwords are not portable from KC; either send a
   "set your password" link or, if `KEYCLOAK_MIGRATING=True` was active
   on `main` and you have captured passwords in Django, push those.
5. **Switch authentication backends** to OIDC. `keycloak_id` becomes
   read-only legacy data.
6. **Remove `keycloak_id`** in a follow-up release.

## Settings cheatsheet

| Old (`main`) | New (`authentik`) |
|---|---|
| `USE_KEYCLOAK` | removed |
| `KEYCLOAK_CLIENTS = {DEFAULT/USERS/ADMIN}` | `AUTHENTIK = {URL, OIDC_*, API_TOKEN, VERIFY_SSL}` |
| `KEYCLOAK_MIGRATING` | removed |
| `django_keycloak_admin.backends.Keycloak*` | `django_users.oidc_backend.AuthentikOIDCBackend` |
| `KeycloakDRFAuthentication` (DRF) | OIDC JWT auth class |
| `KeycloakLoginRedirectMiddleware` | `mozilla_django_oidc.middleware.SessionRefresh` |
| `path('logout/', logout_user_from_keycloak_and_django, ...)` | `path('oidc/', include('mozilla_django_oidc.urls'))` |

## Status field

`USER_STATUS_UNCONFIRMED` (3) → `USER_STATUS_CONFIRMED` (4) when the user
"does something" (e.g. fills profile). Behaviour unchanged from `main`.
Call `self.confirm()` explicitly in your save path if needed:

```python
if self.country and self.status == self.USER_STATUS_UNCONFIRMED:
    self.confirm()
```

## CommsChannel

The OIDC backend creates an email `CommsChannel` on first login (matches
the existing save invariant in skorie projects). Other channels (SMS,
WhatsApp) are added through the existing `AddCommsChannelView` flow —
unchanged from `main`.

## SSO between projects sharing a realm

Authentik supports cross-app SSO the same way Keycloak does — register
each project as an Application inside the same Authentik instance. The
session-cookie alignment from decision 0063 (`SESSION_COOKIE_DOMAIN =
".skor.ie"`, shared `SECRET_KEY`, etc.) still applies and needs
re-testing under Authentik when sibling projects migrate.
