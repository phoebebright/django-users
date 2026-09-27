# 003 One `django-users` branch for every host

# Status

proposed (2026-09-27). Nothing moved yet.

**Direction agreed with Dev, 27Sep26:**
- **`unified-auth` becomes the trunk** that every host installs.
- **A separate branch is allowed only when a host's requirements differ enough
  to justify one.** Small differences go in that host's own `users` app.
- **Zammad integration is left out for now**, to be taken up later.

# History

| Date | What changed | Why |
| :--- | :--- | :--- |
| 27Sep26 | Proposed | Adding one feature (QR phone login) meant writing it twice, for two branches that had drifted apart, and a third app could not use it at all |

Detail is in git: `git log --follow _project_docs/decisions/003_one_branch_for_every_host.md`.

# Context

Every host needs the same thing from this package: users managed within an
organisation. What varies is how they log in:

- plain Django authentication;
- Keycloak;
- Authentik.

That variation is what the long-lived branches grew up around. Each host now
pins its own:

| Branch | Host(s) | Last commit | Commits not on `unified-auth` | `unified-auth` commits it lacks |
|---|---|---|---:|---:|
| `unified-auth` (3.0.0) | skorie2 (pinned to a commit) | 30 Jul 2026 | — | — |
| `skorie-users2` | skorie4 | 3 Jul 2026 | 0 | 12 |
| `authentik` | none | 29 Jun 2026 | 0 | 13 |
| `skorie_users` (1.4.x) | skorie1, skorie3, skorie-news, whinnie | 27 Sep 2026 | 12 | 29 |
| `zammadMay25` (0.2.x) | gadget_admin (BuiltAir) | 27 Sep 2026 | 4 | 331 |
| `main` | none found | 30 Jun 2026 | 11 | 232 |
| `builtair`, `skorie1`, `skorie2` | none | Dec 2024 | 0–3 | 465+ |
| `no_keycloak_no_skorie` | none | Feb 2025 | 23 | 404 |
| `merge_with_no_keycloak` | none | Mar 2025 | 0 | 374 |

Counts exclude merge commits and were measured on 27Sep26.

The cost of this showed on 27Sep26. Adding the single-use QR phone login
(`django_users.phone_login`) meant:
- writing it once for `skorie_users`;
- porting it by hand to `zammadMay25`, which lays out its templates
  differently and does not package them at all;
- leaving skorie2 and skorie4 without it.

Every fix pays that price, once for each branch.

`unified-auth` already solves the part that caused the branches. It selects
the login method with a setting:

```python
AUTH_PROVIDER = 'django'     # plain Django session auth (default)
AUTH_PROVIDER = 'keycloak'   # Keycloak (the [keycloak] extra)
AUTH_PROVIDER = 'authentik'  # Authentik OIDC (the [authentik] extra)
```

behind the adapters in `idp.py`, `idp_keycloak.py` and `oidc_backend.py`. Its
README already gives a host migration order.

## Related Decisions/Issues

- **002, Extract a `skorie-users` layer.** 002 decides *what code lives in which
  layer*: generic `django-users`, then `skorie-users`, then the host. This
  decision is about *which branch* the generic layer is, and it comes first.
  Extracting skorie code once, from one trunk, is far cheaper than extracting
  it from four branches. 002's proof that the library stands alone is
  gadget_admin importing it with no skorie apps present, which this decision
  also delivers.
- **002a**, the per-host review. It already identifies skorie2 as the proof
  case for `AUTH_PROVIDER='django'`.
- **001**, Affiliate / Referral: the abstract-models-plus-hooks pattern that
  keeps host differences out of the library.

# Change Proposed

Make `unified-auth` the trunk. Port onto it what live branches have that it
lacks, move hosts onto it one at a time, and retire the rest.

# Option 1: One trunk, host differences in the host's `users` app (recommended)

Every host pins the trunk. Login method is `AUTH_PROVIDER`. Anything else that
differs per host — fields, admin, extra views — lives in that host's concrete
`users` app, which subclasses this package's abstract models and base views.
This is the arrangement 001 and 002 already assume.

## Pros

- A fix or feature is written once and reaches every host on the next deploy.
- It builds on work already done: `AUTH_PROVIDER` and the adapters exist.
- It gives 002 one source to extract from.

## Cons

- A breaking change on the trunk reaches every host. That needs tests that
  cover all three providers (`tests/test_providers` is a start), and hosts pinned
  to commits rather than to a moving branch name.
- Each move is real work: import renames, and on older hosts a `users`
  migration (see gadget_admin below).

# Option 2: One trunk per login method

`django`, `keycloak` and `authentik` branches, each merged from a common base.

## Pros

- A Keycloak change cannot break an Authentik host.

## Cons

- The same fix is still made three times, plus the merges between branches.
- `unified-auth` has already put the login method behind a setting. Branching on
  it again would undo that.

# Option 3: Leave the branches as they are

## Cons

- Every change costs one port per branch, as the phone login did, and older
  branches keep falling further behind. `zammadMay25` is 331 commits behind.

# Decision

**Option 1.** One trunk, `unified-auth`.

**A separate branch is the exception, and must be argued for.** It is allowed
only when a host's requirements differ enough that a setting, a hook, or the
host's own `users` app cannot carry the difference. Such a branch:
- is named for the reason it exists, not for the host or a date;
- merges from the trunk regularly;
- has its reason recorded in this document.

No host needs one today.

## 1. Bring the trunk up to date

Port onto `unified-auth` what live branches have that it lacks, each with a test.

**From `skorie_users` (12 commits):**
- bot detection for registrations, and `drop_bot_users` with its
  transaction and `ProtectedError` handling;
- `runtests.py`;
- *Pin login session to ModelBackend*. Check it against the provider adapters;
  it may already be covered there;
- the single-use QR phone login (`phone_login.py`, `views_phone_login.py`, the
  two templates, the `qr_login/` and `phone/` routes);
- *updates - from a while ago* and *try to import keycloak*. Review these; they
  may be superseded.

**From `main` (11 commits):**
- user search improvements;
- the invite base and missing serializers;
- the post-office compatibility changes.

For each: check whether `unified-auth` already has it. If not, port it.

**From `zammadMay25`:**
- the phone login, which is the same code as above.
- Zammad is **deferred** (Dev, 27Sep26). `unified-auth` already has
  `zammad_service.py`; reconcile it when Zammad is taken up.

**Then make the trunk the default:**
- merge `unified-auth` into `main`;
- make `main` the branch hosts pin, from then on by commit;
- keep the `unified-auth` name as an alias until every host has moved.

## 2. Move the hosts

Follow the order in the README: prove the branch on a plain-Django host first,
then the Authentik host, then the Keycloak hosts one at a time, on staging first.

| Order | Host | Provider | Work |
|---|---|---|---|
| 1 | skorie2 | `django` | Already on it. Re-pin to the new trunk commit |
| 2 | gadget_admin | `django` | See below |
| 3 | skorie4 | `authentik` | `skorie-users2` is wholly contained in the trunk. Re-pin and set `AUTH_PROVIDER='authentik'` |
| 4 | skorie3 | `keycloak` | Re-pin; add `AUTH_PROVIDER='keycloak'`; the `[keycloak]` extra |
| 5 | skorie-news, whinnie | per host | as skorie3 |
| 6 | skorie1 | `keycloak` | Last: the heaviest `users` app (002a) |

**gadget_admin, measured 27Sep26:**
- **15 imported names were renamed** in 3.0, losing the `Base` suffix (e.g.
  `AddCommsChannelViewBase` → `AddCommsChannelView`,
  `UserEmailSerializerBase` → `UserEmailSerializer`). Mechanical.
- **Its `users` migration:**
  - `CustomUserBaseBasic` gains `mobile`, `email_verified_at` and
    `mobile_verified_at`.
  - **`CommsChannelBase.value` is removed.** The channel now reads the address
    from the user, so existing phone numbers must be copied from the channel to
    `user.mobile` *before* the column is dropped.
  - `VerificationCodeBase.code` becomes hashed (`code_hash`, `code_salt`,
    `token_hash`, `consumed_at`, `purpose`). Codes are short-lived, so any
    outstanding at the switch can be dropped.
- **It currently packages no templates.** Its `MANIFEST.in` names
  `django-users/static`. gadget_admin supplies its own, which keeps working.

## 3. Retire the dead branches

- **Retire:** `authentik`, `skorie-users2` (once skorie4 has moved), `builtair`,
  `skorie1`, `skorie2`, `merge_with_no_keycloak`.
- **Look first:** `no_keycloak_no_skorie` has 23 commits of its own. Look
  through them before retiring it.
- **`skorie_users` and `zammadMay25`** go once their last host has moved.

Retiring means tagging the branch tip, e.g. `archive/skorie_users`, then
deleting the branch, so a commit a host is still pinned to stays reachable.

# Consequences

**Easier:**
- One place to fix. The phone login would have been written once.
- 002's extraction works from a single source.
- A new host gets a supported line on day one.

**Harder:**
- The trunk must not break any provider. Before step 2 starts, the test
  suite should run each provider's login path; `tests/test_providers` covers
  resolution and `KeycloakIdP` today.
- Hosts pin commits and move deliberately, instead of floating on a branch name.

**Risks:**
- gadget_admin's `CommsChannel.value` → `user.mobile` copy is the one step that
  can lose data. It needs a data migration and a count check before the drop.
- Keycloak hosts are in production. Move them one at a time, staging first,
  as the README says.

# Who is involved

| Name | Why/When |
| :---- | :---- |
| Dev | Agrees the direction; approves each host's move |
| Host maintainers | Each host's migration and deploy |
