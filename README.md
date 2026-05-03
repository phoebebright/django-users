# django-users — `authentik` branch

Reusable Django app providing the user models, views, and helpers used by
the Skorie family of projects. **This branch is Authentik-only**: there is
no Keycloak code on this branch, and there are no fallback flags. For the
Keycloak version, use `main`.

This is not (yet?) a standard pip-installable app. It expects you to create
your own `users` app in your project and use these base models.

## Setup

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

- `django_users.idp.AuthentikIdP` — the single chokepoint for Authentik
  admin API calls (`create_user`, `set_password`, `mark_email_verified`,
  `logout`, etc.). Every other module that talks to the IdP goes through
  this class.
- `django_users.oidc_backend.AuthentikOIDCBackend` — custom
  `mozilla_django_oidc` backend. Looks up Django users by `authentik_id`
  (the OIDC `sub` claim); seeds an email `CommsChannel` on first login.
- `CustomUserBase.authentik_id` — the only IdP-aware field on the user
  model. Stores the OIDC `sub` UUID.
- Standard views: `AddUser`, `RegisterView`, `ChangePasswordView`,
  `ChangePasswordNowView`, `ForgotPassword`, `TellUsAbout`, etc. All
  password-mutating views call `AuthentikIdP.set_password` rather than
  hashing locally.

## What does NOT live on this branch

- No `LoginView` — `mozilla-django-oidc` handles the auth handshake.
- No `Troubleshoot`, `ProblemSignup`, `ProblemLogin` — Authentik admin
  UI replaces these support paths.
- No `UserMigrationView`, `update_users` — no realm-to-realm migration on
  a fresh project.
- No `UnverifiedUsersList` — relied on direct reads from KC's user table.
- No `add_to_keycloak` admin action.
- No `KEYCLOAK_*` settings or `USE_KEYCLOAK` flag.

## Health check

After wiring everything up, run the system check:

```
./manage.py check --tag idp
./manage.py check --deploy --tag idp     # also probes /.well-known/openid-configuration
```

(Project-side; see `users/checks.py` in your project for an example.)

## Branching policy

- `main` — Keycloak baseline, used by skorie1 / skorie3 / whinnie / builtair.
- `authentik` *(this branch)* — Authentik-only, used by skorie4 first.

The two diverge hard; bug fixes that apply to both must be applied to
both manually until `main` is retired.
