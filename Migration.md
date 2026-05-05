# Migration notes — Keycloak → Authentik branch

Companion to `MIGRATING.md`. That file covers settings/backend swaps and the
overall transition shape; this one collects the **template-level changes**
and **gotchas** that have come up while moving live projects across.

> Quick scope check: if your project is already on `authentik` and you're
> just pulling new commits, skim "Recent gotchas" at the bottom. If you're
> a sibling project (skorie1, skorie3, whinnie, builtair) starting the
> move, work top-to-bottom.

---

## Templates removed

These templates existed for the Keycloak diagnostic flow and are gone on
`authentik`. Any host-app `extends "django_users/<name>.html"` will 500.

| Removed | Replacement / disposition |
|---|---|
| `problem_login.html` | Authentik handles login problems in its own flow — point users at the IdP recovery URL. |
| `problem_register.html` | Replaced by the invite + OTP flow (`accept_invite.html`, `enter_otp.html`). |
| `problem_signup.html` | Same — drop any references; the wizard is being rebuilt per `TODO.md`. |
| `subscribe.html` | Stand-alone subscription page removed; use the in-page newsletter widgets. |

If you need to keep an "I'm having trouble" entry point in the host app,
link to `users:enter_otp` (admin issues OTP) or to Authentik's recovery
flow URL — do not re-add the old templates.

## Templates added

| Added | Purpose |
|---|---|
| `accept_invite.html` | User lands here from the invite link, confirms identity, sets a password. |
| `enter_otp.html` | OTP entry page paired with `users:enter_otp`. |
| `admin/admin_invite.html` | Admin-side invite issuer. |
| `admin/add_user.html` | Replaces the old "add user" pathway that touched `add_to_keycloak`. |
| `admin/add_channel.html`, `admin/edit_contact.html` | Comms-channel admin (mobile, email mirror, opt-ins). |
| `admin/manage_roles.html`, `admin/manage_users.html`, `admin/new_users.html`, `admin/organisation_list.html`, `admin/user_countries.html` | Admin lists/dashboards. |
| `admin/send_comms.html`, `admin/send_otp.html` | Outbound comms + OTP issuance. |
| `session_reset.html`, `verify_failed.html`, `whoami.html`, `user_about.html` | Misc — verify failure, OIDC sub introspection, "tell us about yourself". |

`admin/send_otp.html` is being phased out in skorie4 in favour of an
inline modal on `admin/admin_user.html` that calls
`api:generate_otp` / `api:generate_recovery_link`. Keep the standalone
template for now; sibling apps still reach it via `users:send_otp`.

## Templates that changed shape

These exist on both branches but have non-trivial diffs — check your host
app's overrides.

- `login.html`, `signin.html`, `signup.html`, `register.html`,
  `include_login_form.html`, `forgot_password.html` — Keycloak hooks
  removed; forms post to mozilla-django-oidc URLs or the OTP flow.
- `change_password.html` — calls `idp.set_password` via the
  `SetTemporaryPassword` API rather than the KC admin.
- `change_profile.html`, `profile.html` — references to `keycloak_id`
  replaced by `authentik_id` and `user_pk`.
- `qr_login.html`, `verify.html`, `verify_channel.html` — adapted to the
  new `CommsChannel` two-layer model (see `b9c2144`).

If a host app shadows any of these in `templates/_client/<name>/...`, the
override needs the same updates — easy to miss.

---

## Python modules removed

Anything importing from these will fail at import — search before pulling.

- `django_users.api_keycloak`
- `django_users.keycloak`, `django_users.keycloak_models`
- `django_users.no_keycloak`
- View classes: `LoginView`, `Troubleshoot`, `ProblemSignup`,
  `ProblemLogin`, `UserMigrationView`, `UnverifiedUsersList`,
  `update_users`
- API helpers: `CheckEmailInKeycloak`, `CheckEmailInKeycloakPublic`,
  `add_to_keycloak`

Replace with `django_users.idp.AuthentikIdP` — single chokepoint for
admin-side IdP calls.

## Python modules added

- `django_users.idp` — Authentik adapter. `AuthentikIdP()` is the only
  thing that should talk to Authentik's REST API. Don't bypass it.
- `django_users.oidc_backend.AuthentikOIDCBackend` — drop-in for
  `mozilla_django_oidc`.
- `django_users.checks` — Django system checks for `AUTHENTIK` settings.
- `django_users.services` — invite + OTP issuance flows
  (`create_user_with_invite`, `send_invite_email`, `send_otp_email`).
- `django_users.referrals/` — referrals subapp (independent of the auth
  migration; safe to ignore if you don't enable it).
- `django_users.urls_api` — DRF API URLs are now mounted separately
  (`api/u1/`); the old `urls.py` only carries page views.

---

## Settings — what disappears

```python
# delete these — no longer read
USE_KEYCLOAK = ...
KEYCLOAK_CLIENTS = {...}
KEYCLOAK_MIGRATING = ...
```

```python
# AUTHENTICATION_BACKENDS — replace KC entry with:
'django_users.oidc_backend.AuthentikOIDCBackend'
```

```python
# add (configure against your Authentik instance)
AUTHENTIK = {
    "URL":                "https://auth.example.com",
    "OIDC_ISSUER":        "https://auth.example.com/application/o/<slug>/",
    "OIDC_CLIENT_ID":     "...",
    "OIDC_CLIENT_SECRET": "...",
    "API_TOKEN":          "...",   # admin token, scoped narrowly
    "VERIFY_SSL":         True,
}
```

`KEYCLOAK_*` env vars in deployment configs (Docker, systemd) need the
same treatment — they're silently ignored otherwise.

---

## URL changes

Old:

```python
path('logout/', logout_user_from_keycloak_and_django, name='logout'),
```

New:

```python
path('oidc/', include('mozilla_django_oidc.urls')),
# logout becomes an mozilla-django-oidc-managed view
```

API URLs split out — host apps that did
`path('api/u1/', include('django_users.urls'))` need to switch to
`include('django_users.urls_api')` for the DRF endpoints, leaving
`urls.py` for HTML views.

---

## User model

- `keycloak_id` — gone from `CustomUserBase`. If your concrete user model
  still declares it (e.g. for a dual-field migration window), you keep
  the column but the package will not read or write it.
- `authentik_id` — new IdP-aware field. Stored as UUID; surfaces as the
  OIDC `sub` claim.
- `user_pk` cached property — returns `authentik_id` when set, else the
  Django pk. Use this anywhere you previously used `keycloak_id` for
  cross-system references.

Templates referencing `{{ user.keycloak_id }}` need to switch to
`{{ user.authentik_id }}` (or `{{ user.user_pk }}`).

---

## Recent gotchas (post-`586858b`)

These post-date the initial conversion commit; if your install is from
git you may not have them yet (`pip install -U` from `authentik`).

- `b9c2144` — `CommsChannel.verified_at` is now opt-in per channel,
  separate from `User.email_verified_at` / `User.mobile_verified_at`
  (which are address-ownership stamps). Email rows mirror; SMS/WhatsApp
  are independent. Templates in admin/comms-channel admin assume this
  split.
- `7d5f916` — SMS/WhatsApp verification helpers were sending the wrong
  variable; fixed to send the actual code. If your test SMS messages
  read as "None" or were silently empty, this was the cause.
- `2435c02` — Admin can now edit a user's contact (email/mobile) and
  manage their channel list directly from the manage-user page. New
  templates: `admin/edit_contact.html`, `admin/add_channel.html`.

---

## Checklist for a sibling-project switchover

1. [ ] Stand up Authentik; create the application + admin token.
2. [ ] Branch the project; bump `requirements.txt` to
       `git+...@authentik`.
3. [ ] Settle the `keycloak_id` / `authentik_id` dual-field window on
       your concrete user model.
4. [ ] Run a backfill: for each user with `keycloak_id`, call
       `AuthentikIdP().create_user(...)` and store the UUID. Passwords
       don't migrate — issue invite/OTP links.
5. [ ] Search-and-replace `keycloak_id` → `authentik_id` (or
       `user_pk`) in templates and JS.
6. [ ] Remove `KEYCLOAK_*` settings; add `AUTHENTIK = {...}`.
7. [ ] Swap `AUTHENTICATION_BACKENDS` and middleware.
8. [ ] Re-test SSO if multiple sibling apps share the realm
       (decision 0063 cookie/secret alignment still applies).
9. [ ] Smoke-test the OTP and recovery flows end-to-end before
       cutting traffic over.