# Changelog

One version sequence, on the trunk only. Hosts pin a release tag
(`@v<version>`), never a branch. See decision 003, *Versions and pinning*.

Each entry records:
- **Affects:** all hosts, a provider (`django` / `keycloak` / `authentik`), or
  skorie hosts only.
- **Host action:** every migration, setting or import change a host must make,
  or `none`.

## 3.2.4 (20 Oct 2026)

- **Change password no longer crashes when the session has ended.** Any new
  password ends the sessions signed in with the old one, e.g. an admin
  issuing a fresh OTP while the user has the form open (skorie4, 20 Oct 2026).
  Submitting `ChangePasswordView` from that session was a 500
  (`'NoneType' object has no attribute 'check_password'`). It now says the
  session has ended and sends the user to log in, then back to the form,
  on GET and POST. `ChangePasswordNowView` already sent a signed-out user to
  Forgot Password on GET; it now does on POST too, which was also a 500.
  `tests/test_plain_host` covers both.
- **Affects:** all hosts.
- **Host action:** none.

## 3.2.3 (19 Oct 2026)

- **`UserContact.add()` saved every contact twice.** It saved one row with no
  `site`, then created a second with it. The first save logged "No site set
  when adding to UserContact - possible attack" on every Contact Us and
  Subscribe & Interest form (seen on whinn.ie, 15 Oct 2026), and every contact
  was stored twice. Now one row, with `site` set, and no warning.
  `tests/test_plain_host` gains a concrete `UserContact` and a test.
- **Affects:** all hosts.
- **Host action:** none. Duplicate `UserContact` rows from before this release
  stay; they are harmless.

## 3.2.2 (15 Oct 2026)

- **Login form labels back.** The Email and Password labels in
  `include_login_form.html` were dropped in 8cc74f6 (3 Jul 2026). The fields
  use Bootstrap's floating labels, which hide the placeholder, so without a
  label the boxes were blank and typed text sat at the bottom of the box.
- **Affects:** all hosts.
- **Host action:** none.

## 3.2.1 (15 Oct 2026)

- **Open redirects closed.** A link to the login page with
  `?next=https://evil.example` signed the user in, then sent them off-site.
  Every redirect to a URL taken from the request now goes through
  `django_users.redirects.safe_next()`. It allows only this site, via Django's
  `url_has_allowed_host_and_scheme`; anything else falls back to the view's
  usual default. The places fixed:
  - `LoginView` (both paths) and `VerifyMagicLinkView`
  - `SendComms` and `ResetSessionView`
  - `logout`, and `ProblemSignup`, through `get_legitimate_redirect()`, which
    only rejected values starting `http` and missed `//host`, `/\host` and
    `HTTP://`
  - every `GoNextMixin` view, through `get_next()`, which accepted any value
    containing a `/`
  - the `next` that `GoNextTemplateMixin` puts in the template context (the
    login, change password and Send Comms pages), where `href="{{ next }}"`
    could carry `javascript:`. `AdminInviteView` builds its own context and
    is not covered yet.
  - `subscribe_only` / `unsubscribe_only`, which followed the client's
    Referer
- **No more 500s on a bad `next` at sign-in or magic-link login.** Before,
  `next=javascript:...` or a bare word such as `next=foo` made `redirect()`
  raise. A checked `next` is now always redirected to as a URL.
- Hand-built `?next=` query strings are URL-encoded (slashes kept), and so is
  `get_next()`'s `anchor`.
- **Affects:** all hosts.
- **Host action:** none, unless a host relies on either of these, which no
  longer work:
  - redirecting to another site through `next`, which now lands on the
    default page instead
  - passing a namespaced url name as `next` to these views (e.g.
    `next=users:user-profile`), which Django reads as a URL scheme, so it
    falls back. `get_next()`'s `go_next` url names still work.

## 3.2.0 (15 Oct 2026)

- **Limit on failed sign-ins** (`django_users/login_limits.py`, used by
  `LoginView`).
  - Counts failures only: 5 per email address in 15 minutes and 30 per client
    IP an hour by default.
  - Once a limit is reached, even the correct password is refused. The page
    returns 429 with "Too many sign-in attempts. Please wait up to N minutes,
    or reset your password."
  - A completed Forgot Password reset clears that email's count.
  - It fails open if the cache is down.
  - The per-IP limit is skipped for an address that isn't public (a proxy's),
    so one person can't lock out everyone behind it.
  - If the host has `UserHistory`, `login_rate_limited` is logged once, when a
    known user reaches the limit.
- **New checks:** `django_users.W010` warns when the counts' cache isn't shared
  between processes, and `W011` when `RATELIMIT_USE_CACHE` names a missing
  cache.
- **New dependency:** `django-ratelimit>=4.1,<5`.
- **Fixed before release:** the merge of 3.1.4 into the trunk dropped
  `looks_like_bot_name` from `views.py`'s imports, so registration was a
  `NameError` on the untagged trunk. No tag had it.
- **Affects:** all hosts.
- **Host action:**
  - Set `RATELIMIT_USE_CACHE` to a shared cache (Redis or memcached).
  - Behind nginx, set
    `RATELIMIT_IP_META_KEY = 'django_users.login_limits.forwarded_client_ip'`.
  - Optionally set `LOGIN_RATELIMIT_EMAIL` / `LOGIN_RATELIMIT_IP` (`None`
    turns a limit off).
  - Without a shared cache, the limit still works but counts per process.
    `manage.py check` warns.

## 3.1.4 (13 Oct 2026)

Found in skorie1's bug hunt (C5). The same fix is on `skorie_users` as 1.4.8.

- **Forgot Password could reset anyone's password.** The session kept
  "verified" as a bare True. Entering another email at step 1 did not clear
  it, and `set_current_user()` (run by `problem_register`) reset the step and
  email but not the flag, and step 3 skipped the code whenever it was set. So:
  verify your own address, open `problem_register`, enter anyone's email, and
  step 4 set their password. Administrators too.
  - `forgot_verified` now holds the pk of the user a code or link verified,
    and steps 3 and 4 check it against the user being reset
    (`ForgotPassword.is_verified_for`).
  - Step 1 clears any earlier channel, code and verification.
    `set_current_user()` clears `forgot_verified` and `forgot_vc_pk` with the
    rest of the flow.
- **`LOGIN_URL` may be a path.** Five places did `reverse(settings.LOGIN_URL)`,
  which only takes a url name, so each was a 500 on a host that sets a path:
  - Forgot Password, after a successful reset. The password was already
    saved, so the user saw an error after a reset that had worked.
  - `RegisterView`, for an email that already has an active account.
  - `ResetSessionView`.
  - `login_redirect`.
  - `send_otp()`, so no login code email could be sent.

  They now use `resolve_url()`, which takes a url name or a path; a url name
  gives the same result as before.
- `tests/test_plain_host` gains three forgot-password tests and four
  `LOGIN_URL` tests. On 3.1.3 all fail except the wrong-code test.

**Affects:** all hosts that route `users:forgot_password`; the `LOGIN_URL`
fixes, hosts that set it to a path.
**Host action:** none.

## 3.1.3 (27 Sep 2026)

Found by BuiltAir's full test run on 3.1.2 (HD-0154).

- **Login no longer depends on DNS.** `LoginView` passed the address through
  `normalise_email()`, which asked DNS whether the domain accepts mail, and an
  address that failed made login a 500. A DNS outage was a login outage, and a
  user on a domain with no mail server could never log in. 0.2.x did not check
  at login.
  - `normalise_email()` takes `check_deliverability` (default True).
  - The 15 call sites that look up an EXISTING account pass False: login,
    forgot password, the check-email APIs, sending a code.
  - The two that accept a NEW address keep the check: `RegisterView` and
    `ContactView`.
- **A bad or empty address at login is a failed login**, answered "Invalid
  email or password", not a 500. `normalise_email(None)` now raises
  `ValidationError` instead of `AttributeError`.
- `tests/test_plain_host` gains three login tests. Two fail on 3.1.2.

**Affects:** all hosts.
**Host action:** none.

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
