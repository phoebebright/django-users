# KeycloakLoginRedirectMiddleware removed on the authentik branch.
# OIDC session refresh and login-required redirection are handled by
# `mozilla_django_oidc.middleware.SessionRefresh` — wire it up in your
# project's MIDDLEWARE setting.
