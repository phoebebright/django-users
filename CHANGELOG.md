# Changelog

One version sequence, on the trunk only. Hosts pin a release tag
(`@v<version>`), never a branch. See decision 003, *Versions and pinning*.

Each entry records:
- **Affects:** all hosts, a provider (`django` / `keycloak` / `authentik`), or
  skorie hosts only.
- **Host action:** every migration, setting or import change a host must make,
  or `none`.

## Unreleased

Trunk ports from `skorie_users` (decision 003, step 1). Nothing from `main`
needed porting: its changes are already on this branch in a newer form, or are
deliberately not taken (see below).

- **QR phone login** (`django_users.phone_login`, `views_phone_login`).
  - Replaces `QRLogin` on `qr_login/` (same URL name, `qr-login`) and adds
    `phone/`.
  - Single use, with a two-minute window.
  - The code sits after `#`, so it never reaches server logs.
  - The phone confirms before the code is spent.
  - A password change cancels outstanding codes.
  - Looks users up by primary key, so it works with every provider.
  - `lwt/` (`login_with_token`) is unchanged.
- **Bot registrations dropped.** `looks_like_bot_name()` spots UUID, hex,
  random-case and consonant-run names. `RegisterView` silently drops those
  registrations.
- **New command `drop_bot_users`:** finds and deletes existing bot accounts.
  Dry-run unless `--delete` is passed.
- **`drop_expired` now runnable.** It was in `management/command/`, a folder
  Django never looks in. It is now in `management/commands/` and is dry-run
  unless `--delete` is passed.
- **Both commands load rows normally**, with no `.iterator()` (server-side
  cursors fail behind a transaction-mode pgbouncer) and no `.only()` (host user
  models that track field changes reload each deferred field in its own query).

**Affects:** all hosts.

**Host action:**
- **Shared cache.** Single-use phone login needs a cache shared by every
  worker (Redis or Memcached). With Django's default per-process cache, a code
  can be used once per process.
- **Phone login templates.** Hosts on `django_users/users_narrow_base.html`
  get them working as shipped. Others set `template_name` on both views.
- **Phone login settings (optional):**
  - `DJANGO_USERS_PHONE_LOGIN_MAX_AGE` (default 120 seconds);
  - `DJANGO_USERS_PHONE_LOGIN_DEFAULT_NEXT` (default `/`);
  - `DJANGO_USERS_PHONE_LOGIN_SESSION_KEYS` (default none).
- **Skorie hosts' "Login on Mobile" changes:** the phone now shows a
  "Log in as …?" page before logging in.

**Deliberately not taken from `main`:**
- `improving user search` (d9efc2e). It made `MemberViewSet` a writable
  `ModelViewSet` over every user, with no `icansee()` scoping. The read-only,
  scoped version here stays.
- Post-office compatibility changes (dd7bfe3, 18729e8, 8550225, df5c3b9). These
  are workarounds for an old post-office version, and they read
  `CommsChannel.value`, which this line has removed.
- Zammad integration. Deferred (003).

Tests: `python -m tests.test_phone_login.runtests`,
`python -m tests.test_bot_names.runtests`.

## 3.0.0

`unified-auth`: `AUTH_PROVIDER` selects `django`, `keycloak` or `authentik`.
See `README.md` and `MIGRATING.md`.
