"""Provider-specific middleware.

Keycloak hosts can mount ``KeycloakLoginRedirectMiddleware`` to force
anonymous visitors through the hosted Keycloak login. It no-ops unless the
active provider (``django_users.idp.get_auth_provider()``) is ``keycloak``,
so it is safe to leave in MIDDLEWARE while switching providers.

Authentik hosts don't need anything from here: OIDC session refresh and
login-required redirection are handled by
``mozilla_django_oidc.middleware.SessionRefresh`` — wire it up in your
project's MIDDLEWARE setting.
"""

from urllib.parse import urlencode

from django.conf import settings
from django.shortcuts import redirect

from .idp import get_auth_provider


class KeycloakLoginRedirectMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Only active when Keycloak is the auth provider; otherwise pass through
        # so the middleware can stay mounted across provider switches.
        if get_auth_provider() != "keycloak":
            return self.get_response(request)

        # Skip redirect for authenticated users or certain paths
        if request.user.is_authenticated or self._is_exempt_path(request.path):
            return self.get_response(request)

        # Build Keycloak authorize URL
        redirect_uri = request.build_absolute_uri(settings.KEYCLOAK_REDIRECT_URI)
        params = {
            'client_id': settings.KEYCLOAK_CLIENTS['DEFAULT']['CLIENT_ID'],
            'response_type': 'code',
            'scope': 'openid email profile',
            'redirect_uri': redirect_uri,
        }
        authorize_url = f"{settings.KEYCLOAK_CLIENTS['DEFAULT']['URL']}/realms/{settings.KEYCLOAK_CLIENTS['DEFAULT']['REALM']}/protocol/openid-connect/auth?{urlencode(params)}"
        return redirect(authorize_url)

    def _is_exempt_path(self, path):
        # Add paths that should not trigger redirect (e.g., static, admin, health checks)
        exempt_paths = [
            '/oidc/callback/',  # your Keycloak callback view
            '/admin/login/',
            '/static/',
            '/api/',  # Optional: exclude API calls
        ]
        return any(path.startswith(p) for p in exempt_paths)
