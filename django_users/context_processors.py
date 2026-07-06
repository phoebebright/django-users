"""Template context processors for django-users.

Add to the host project's TEMPLATES OPTIONS['context_processors']::

    'django_users.context_processors.auth_provider',

Templates can then gate provider-specific blocks::

    {% if auth_provider == 'keycloak' %} ... {% endif %}
"""

from .idp import get_auth_provider


def auth_provider(request):
    return {"auth_provider": get_auth_provider()}
