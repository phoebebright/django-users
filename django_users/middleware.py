from django.shortcuts import redirect
from django.conf import settings
from urllib.parse import urlencode


class KeycloakLoginRedirectMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
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
