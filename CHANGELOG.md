# Changelog

One version sequence, on the trunk only. Hosts pin a release tag
(`@v<version>`), never a branch. See decision 003, *Versions and pinning*.

Each entry records:
- **Affects:** all hosts, a provider (`django` / `keycloak` / `authentik`), or
  skorie hosts only.
- **Host action:** every migration, setting or import change a host must make,
  or `none`.

## 3.1.2 (27 Sep 2026)

Found testing BuiltAir on 3.1.1 (BuiltAir HD-0154). BuiltAir is a plain-Django
host: the user model is built on `CustomUserBaseBasic` and tracks field
changes, and `django_users` is not an installed app. Every fault below broke
such a host outright, and none showed on a skorie host.

- **Users could not be saved.** `CustomUserBaseBasic.save()` read the previous
  row with `.only()`; a user model that tracks field changes recursed without
  end. It now uses `.values()`.
- **Codes could not be issued or verified.** Four `UserHistory` lookups called
  `apps.get_app_config('django_users')`, which raises when the app is not
  installed. They now check `apps.is_installed()` first; skorie behaviour is
  unchanged.
- **Verification failed on the Basic base.** `idp_id` existed only on
  `CustomUserBase`. It is now on `CustomUserBaseBasic` too, returning None
  under `AUTH_PROVIDER='django'`.
- **The profile page was a 500:**
  - it redirected through skorie's `users:tell_us_about` by default. It now
    redirects only when `CONFIRM_USER_PAGE` is set;
  - anonymous users now go through `LoginRequiredMixin` instead of a
    hand-built URL;
  - `skorie_news.Subscription` is looked up only when `USE_NEWSLETTER` is on
    and `skorie_news` is installed;
  - `USE_SUBSCRIBE` and `USE_NEWSLETTER` now default to False.
- **Forgot-password was a 500:** it read `USE_MAGIC_LINK_FOR_FORGOT` with no
  default. It now defaults to False.
- **`EXTRA_ROLES`** defaults to `{}` on `CustomUserBaseBasic`, which
  `user_roles()` reads.
- **New `tests/test_plain_host`:** a reference plain-Django host in BuiltAir's
  shape. Each fault above has a test. All 8 fail on 3.1.1 and pass here.

**Affects:** all hosts. Only plain-Django hosts on `CustomUserBaseBasic` were broken.

**Host action:** none.

**Documented here, for any host:** `django_users` needs these installed in
`INSTALLED_APPS`:
- `django.contrib.sites` and `django.contrib.flatpages` (models import them);
- `django_countries`, `rest_framework` and `rest_framework_api_key`
  (`django_users.urls` imports them).

The host's users app must be importable as the top-level module `users`,
because `serializers.py` imports `users.models`.

**Noticed, not fixed:** `user_roles(descriptions=True)` calls `.update()` on
the class-level `ModelRoles.ROLE_DESCRIPTIONS`, so extra roles leak into it for
every later caller.

## 3.1.1 (27 Sep 2026)

Found moving BuiltAir onto 3.1.0 (BuiltAir ticket HD-0154). Both faults stopped
a non-skorie host from starting at all.

- **Skorie role mixins moved** from `django_users.tools.permission_mixins` to
  `django_users.skorie.permission_mixins`: `UserCanAdministerOrIssuerMixin`,
  `UserCanAdministerOrganise`, `UserCanJudgeMixin`, `UserCanCompeteMixin` and
  `UserCanOrganiserMixin`. They read skorie roles (`ROLE_ISSUER`,
  `ROLE_ORGANISER`, `ROLE_JUDGE`, `JUDGE_ROLES`, `ROLE_COMPETITOR`) when defined,
  so importing the generic module crashed for any host without them. This is
  the first piece of decision 002's `django_users.skorie` subpackage.
- **`pycountry` declared** as a dependency. `django_users.api` imports it at the
  top, but it was never listed, so a host that lacked it could not start.
- **New `tests/test_boundary`:** a host with generic roles only must be able to
  import the generic modules, and no generic module may import
  `django_users.skorie`.

**Affects:** skorie hosts, and non-skorie hosts, which can now start.

**Host action:** skorie hosts change these imports when they pin 3.1.1:

```python
# was
from django_users.tools.permission_mixins import UserCanJudgeMixin
# now
from django_users.skorie.permission_mixins import UserCanJudgeMixin
```

Other hosts: none (`pycountry` installs with the package).

## 3.1.0 (27 Sep 2026)

The first tagged release from the trunk. `main` now carries it.

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
