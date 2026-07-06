# django-users — `unified-auth` branch

Reusable Django app providing the user models, views, and helpers used by
the Skorie family of projects. **This branch unifies the three historical
auth branches** (`skorie_users`/Keycloak, `skorie-users2`/Django,
`authentik`/Authentik): all functionality is shared, and a single setting
selects how authentication is handled:

```python
AUTH_PROVIDER = 'django'     # plain Django session auth (default)
AUTH_PROVIDER = 'keycloak'   # Keycloak SSO (needs the [keycloak] extra)
AUTH_PROVIDER = 'authentik'  # Authentik OIDC (needs the [authentik] extra)
```

Legacy settings keep working without change: `USE_KEYCLOAK = True` resolves
to `'keycloak'`, and a defined `AUTHENTIK` dict resolves to `'authentik'`
when `AUTH_PROVIDER` is unset. An explicit `AUTH_PROVIDER` always wins.

Key modules:

- `django_users/idp.py` — `get_auth_provider()`, `get_idp()`, and the
  `AuthentikIdP` adapter.
- `django_users/idp_keycloak.py` — `KeycloakIdP` adapter (python-keycloak is
  imported lazily; install with `pip install 'django-users[keycloak]'`).
- `django_users/keycloak.py` — deprecated shim over the adapter for hosts
  that import the old function names.
- Users carry **both** `keycloak_id` and `authentik_id` (nullable UUIDs), so
  switching provider is settings-only and host migrations stay additive.
- Keycloak-only routes (`migrate_login/`, `unverified/`, `update_users/`,
  `email_exists_on_keycloak(_p)/`, `problem_register/<email>/`) are always
  wired but return 404 unless `AUTH_PROVIDER == 'keycloak'`.

Run the standalone test suites from the repo root (full suites run from a
host project):

```
python -m tests.test_providers.runtests    # provider resolution + KeycloakIdP
python -m tests.test_authentik.runtests    # Authentik guard tests
```

## Rollout for existing consumers

Order: prove the branch on a dev host with `AUTH_PROVIDER='django'` first,
then the Authentik consumer (near-zero diff), then skorie1/2/3 (Keycloak,
production) **one at a time, staging first**.

Per Keycloak host (skorie1/2/3):

1. Repin `requirements.txt`:
   `git+https://github.com/phoebebright/django-users@unified-auth`
   (or a `v3.0.0` tag once cut) and add the Keycloak stack
   (`django-keycloak-admin`) which is no longer implied.
2. Settings: add `AUTH_PROVIDER = 'keycloak'` explicitly. Keep
   `USE_KEYCLOAK` / `KEYCLOAK_MIGRATING` / `VERIFY_ONCE` as they are. Set
   `KEYCLOAK_DB_ALIAS` only if the Keycloak DB alias differs from
   `keycloak_new`.
3. `python manage.py makemigrations users` — expect **additive only**: an
   `authentik_id` column, plus Invite/ZammadTicketContact/EntryTicketLink
   tables if the host subclasses those new abstract models. Dev signs off.
4. `python manage.py check --tag idp` — validates AUTH_PROVIDER and the
   provider's config.
5. **Static paths:** the `static/js_no_keycloak/` tree is gone; templates
   referencing it must point at `static/js/` (single tree, provider-aware).
6. Smoke test: login (confirm `_auth_user_backend` is ModelBackend),
   register, forgot-password (all 4 steps), change-password(-now), admin
   AddUser, OTP generate/send, logout + logout_all, `unverified/` report,
   `migrate_login/` if enabled.

**Rollback:** the old branches are untouched — repin back to `skorie_users`
and redeploy. The new migrations are additive (nullable column + new
tables), so the old code runs against the migrated database without reverse
migrations.

This is not (yet?) a standard pip-installable app. It expects you to create
your own `users` app in your project and use these base models.

## Setup (Authentik)

### 1. Stand up Authentik

You need a running Authentik instance. For local development, run it via
Docker Compose on its own host (e.g. `localhost:9000` HTTP / `:9443` HTTPS).
See <https://goauthentik.io/docs/installation/docker-compose>.

In the Authentik admin UI:

1. **Providers → Create → OAuth2/OpenID Provider**
   - Note Client ID, Client Secret, the OpenID Configuration URL.
   - Add your project's redirect URI to the list, e.g.
     `http://localhost:8000/oidc/callback/`.
2. **Applications → Create**
   - Slug must match the slug used in the issuer URL.
   - Provider: select the one created above.
3. **Directory → Tokens & App passwords → Create → API Token**
   - User: an admin (e.g. `akadmin`); copy the token value once.

### 2. Install the package and dependencies

```
pip install git+https://github.com/phoebebright/django-users@authentik
```

Required packages (also brought in via `requirements.txt`):

- `mozilla-django-oidc` — handles the OIDC authorization-code flow
- `httpx` — used by the IdP admin adapter

### 3. Add settings

```python
INSTALLED_APPS = [
    ...
    "users",                # your concrete users app
    "mozilla_django_oidc",
]

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "django_users.oidc_backend.AuthentikOIDCBackend",
]

AUTHENTIK = {
    "URL":                "https://localhost:9443",
    "OIDC_ISSUER":        "https://localhost:9443/application/o/<slug>/",
    "OIDC_CLIENT_ID":     "...",
    "OIDC_CLIENT_SECRET": "...",
    "API_TOKEN":          "...",
    "VERIFY_SSL":         True,    # False for local self-signed certs
}

# OIDC client configuration (mozilla-django-oidc)
OIDC_RP_CLIENT_ID                = AUTHENTIK["OIDC_CLIENT_ID"]
OIDC_RP_CLIENT_SECRET            = AUTHENTIK["OIDC_CLIENT_SECRET"]
OIDC_OP_AUTHORIZATION_ENDPOINT   = AUTHENTIK["OIDC_ISSUER"] + "authorize/"
OIDC_OP_TOKEN_ENDPOINT           = AUTHENTIK["OIDC_ISSUER"] + "token/"
OIDC_OP_USER_ENDPOINT            = AUTHENTIK["OIDC_ISSUER"] + "userinfo/"
OIDC_OP_JWKS_ENDPOINT            = AUTHENTIK["OIDC_ISSUER"] + "jwks/"
OIDC_RP_SIGN_ALGO                = "RS256"
OIDC_VERIFY_SSL                  = AUTHENTIK["VERIFY_SSL"]

LOGIN_URL              = "oidc_authentication_init"
LOGIN_REDIRECT_URL     = "/"
LOGOUT_REDIRECT_URL    = "/"

# Optional middleware — keeps the session token fresh against Authentik
MIDDLEWARE = [
    ...
    "mozilla_django_oidc.middleware.SessionRefresh",
]
```

Add the OIDC URL include to your project's `urls.py`:

```python
path("oidc/", include("mozilla_django_oidc.urls")),
```

### 4. Define your concrete user model

```python
# users/models.py
from django_users.models import CustomUserBase

class CustomUser(CustomUserBase):
    # add project-specific fields here
    class Meta(CustomUserBase.Meta):
        abstract = False
```

```python
# settings.py
AUTH_USER_MODEL = "users.CustomUser"
```

### 5. Required project settings

Same as on `main`:

```python
MODEL_ROLES_PATH = "config.roles_and_disciplines.ModelRoles"
DISCIPLINES_PATH = "config.roles_and_disciplines.Disciplines"
```

See `default_roles_and_disciplines.py` for an example.

## Optional settings

```python
LOGIN_REGISTER                  = "users:register"
CHANNEL_EMAIL                   = "email"
VERIFY_ONCE                     = True
NOTIFY_NEW_USER_EMAILS          = "phoebebright310@gmail.com"
USERS_BIG                       = False     # paged users list
CONFIRM_USER_PAGE               = "users:tell_us_about"
INVITE_LINK_EXPIRY_DAYS         = 7
OTP_EXPIRY_HOURS                = 24
REQUIRES_APPROVAL               = False     # gate self-registered users
```

## What lives on this branch

- `django_users.idp` — `get_auth_provider()` / `get_idp()` provider
  selection, plus `AuthentikIdP`, the single chokepoint for Authentik admin
  API calls (`create_user`, `set_password`, `mark_email_verified`,
  `logout`, etc.).
- `django_users.idp_keycloak.KeycloakIdP` — the same interface over
  python-keycloak, plus keycloak-only extras (`verify_login`,
  `is_temporary_password`, `clear_required_actions`, `get_access_token`).
- `django_users.oidc_backend.AuthentikOIDCBackend` — custom
  `mozilla_django_oidc` backend. Looks up Django users by `authentik_id`
  (the OIDC `sub` claim); seeds an email `CommsChannel` on first login.
- `CustomUserBase.keycloak_id` / `CustomUserBase.authentik_id` — one field
  per external IdP; `user.idp_id` resolves the active provider's one.
- `LoginView` — Django-session email+password login. Whatever backend
  verifies the credentials, the session always records `ModelBackend` so
  `get_user()` isn't tied to a short-lived IdP token.
- Standard views: `AddUser`, `RegisterView`, `ChangePasswordView`,
  `ChangePasswordNowView`, `ForgotPassword`, `TellUsAbout`, etc. All
  password-mutating views dispatch through `get_idp()`: external IdP when
  one is active and the user is linked, local hash otherwise.
- Keycloak-only views behind `ProviderRequiredMixin`: `UserMigrationView`,
  `UpdateUsersView`, `UnverifiedUsersList`, `CheckEmailInKeycloak(+Public)`,
  plus `Troubleshoot` / `ProblemSignup` / `ProblemLogin` support paths.

## Health check

After wiring everything up, run the system check:

```
./manage.py check --tag idp
./manage.py check --deploy --tag idp     # also probes /.well-known/openid-configuration
```

(Project-side; see `users/checks.py` in your project for an example.)

## Branching policy

- `unified-auth` *(this branch)* — the merge target: all three auth methods
  behind `AUTH_PROVIDER`. Once every consumer has repinned here, the legacy
  branches below are archived and fixes land in one place only.
- `skorie_users` — legacy Keycloak production branch (skorie1/2/3 pins until
  they repin here). Frozen except emergency back-ports.
- `skorie-users2` — legacy Django-auth line; superseded by this branch.
- `authentik` — legacy Authentik-only line; superseded by this branch.

Until consumers repin, a fix needed on a legacy branch must still be
back-ported manually — check `git branch -a` and confirm scope with Dev.
