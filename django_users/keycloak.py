"""DEPRECATED Keycloak helpers — thin shim over ``django_users.idp_keycloak``.

Ported from the skorie_users branch so hosts that import these functions
directly keep working on the unified branch. New code should use
``django_users.idp.get_idp()`` (returns a :class:`KeycloakIdP` when
``AUTH_PROVIDER == 'keycloak'``) instead.

Import-safe without python-keycloak installed: the library is only imported
when a client is actually created. Return types are unchanged from the
legacy module (raw Keycloak dicts, status-code ints), NOT the dataclasses
the adapter returns.
"""

import logging

from django.conf import settings
from django.contrib.auth import logout
from django.core.exceptions import ImproperlyConfigured
from django.shortcuts import redirect

from .idp import keycloak_enabled

logger = logging.getLogger('django')

_keycloak_admin = None
_keycloak_openid = None

# The legacy module re-exported these python-keycloak names at import time.
# Re-export them lazily so this module stays importable without the package.
_REEXPORTS = ("KeycloakAdmin", "KeycloakOpenID", "KeycloakGetError", "KeycloakAuthenticationError")


def __getattr__(name):
    if name in _REEXPORTS:
        import keycloak as _kc
        import keycloak.exceptions as _kc_exc
        return getattr(_kc, name, None) or getattr(_kc_exc, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def _get_keycloak_config():
    """Return Keycloak configuration from settings or raise a clear error.

    We do not access settings at import time to keep this module safe to import
    in environments (e.g., tests) where Keycloak is not used.
    """
    if not keycloak_enabled():
        raise ImproperlyConfigured(
            "Keycloak is not the active auth provider "
            "(set AUTH_PROVIDER='keycloak' or USE_KEYCLOAK=True)"
        )

    try:
        cfg = settings.KEYCLOAK_CLIENTS['USERS']
        client_id = cfg['CLIENT_ID']
        client_secret = cfg['CLIENT_SECRET']
        keycloak_url = cfg['URL']
        keycloak_realm = cfg['REALM']
    except Exception as exc:
        logger.error("Keycloak USERS client configuration is missing in settings.KEYCLOAK_CLIENTS", exc_info=exc)
        raise ImproperlyConfigured("Missing Keycloak USERS client configuration") from exc

    return client_id, client_secret, keycloak_url, keycloak_realm


def get_keycloak_admin():
    """Lazily create and cache a KeycloakAdmin client."""
    global _keycloak_admin
    if _keycloak_admin is not None:
        return _keycloak_admin

    from keycloak import KeycloakAdmin  # optional dependency; import on demand

    client_id, client_secret, keycloak_url, keycloak_realm = _get_keycloak_config()
    _keycloak_admin = KeycloakAdmin(
        server_url=f"{keycloak_url}/",
        realm_name=keycloak_realm,
        client_id=client_id,
        client_secret_key=client_secret,
        verify=True,
    )
    return _keycloak_admin


def get_keycloak_openid():
    """Lazily create and cache a KeycloakOpenID client."""
    global _keycloak_openid
    if _keycloak_openid is not None:
        return _keycloak_openid

    from keycloak import KeycloakOpenID  # optional dependency; import on demand

    client_id, client_secret, keycloak_url, keycloak_realm = _get_keycloak_config()
    _keycloak_openid = KeycloakOpenID(
        server_url=f"{keycloak_url}/",
        realm_name=keycloak_realm,
        client_id=client_id,
        client_secret_key=client_secret,
    )
    return _keycloak_openid


class _KeycloakAdminProxy:
    def __getattr__(self, name):
        return getattr(get_keycloak_admin(), name)

    def __setattr__(self, name, value):
        setattr(get_keycloak_admin(), name, value)


# Backwards-compatible proxy exported as module attribute
keycloak_admin = _KeycloakAdminProxy()


def get_access_token(requester):
    '''Get an access token for the Keycloak admin API'''
    from keycloak.exceptions import KeycloakAuthenticationError

    if not requester.is_administrator and not requester.is_manager:
        logger.error(f"User {requester} is not an administrator or manager and cannot request a Keycloak access token")
        return None

    try:
        token = get_keycloak_openid().token(grant_type="client_credentials")
        logger.info(f"User {requester} requesting Keycloak access token")
        return token['access_token']
    except ImproperlyConfigured:
        # Keycloak disabled or not configured; behave as if no token available
        return None
    except KeycloakAuthenticationError as e:
        logger.error(f"Failed to get access token: {e}")
        return None


def logout_user_from_keycloak_and_django(request, user=None, should_redirect=True):
    """
    Logs out a user from both Keycloak and Django.
    set should_redirect=False if you want to run the function without redirecting to login page
    """
    from keycloak.exceptions import KeycloakGetError

    if not user:
        user = request.user

    # check not logged out already
    if user.is_authenticated:
        try:
            # End the user session in Keycloak
            try:
                get_keycloak_admin().user_logout(user.keycloak_id)
            except Exception as e:
                logger.error(f"Failed to logout user {user.pk} from keycloak: {e} ")

            # Log out the user from Django
            logout(request)
            logger.info(f"Successfully logged out user {user} from both Keycloak and Django.")

        except KeycloakGetError as e:
            logger.error(f"Failed to log out user {user} from Keycloak: {e}")

    else:
        # can be left partially logged out in django so force logout and clear session of _auth values
        logout(request)

    # Redirect to a specified page after logout
    if should_redirect:
        return redirect(settings.LOGOUT_REDIRECT_URL)


def create_keycloak_user(user_details, requester):
    '''Create a Keycloak user and return the user ID that will be used as the username in Django'''

    try:
        user_id = get_keycloak_admin().create_user(user_details)
        logger.info(
            f"User created in Keycloak with ID {user_id} and name {user_details['firstName']} {user_details['lastName']} by {requester}")
        return user_id, 201
    except Exception as e:
        if getattr(e, 'response_code', None) == 409:
            # user already exists so get details
            user_id = get_keycloak_admin().get_user_id(user_details['email'])
            return user_id, 409
        else:
            logger.error(f"Failed to create user in Keycloak: {e}")
            return None, 500


def verify_user_without_email(user_id):
    '''allow user to be enabled and verified in keycloak without clicking the link in the email process'''
    payload = {
        'emailVerified': True,
        'enabled': True,
        'requiredActions': []
    }

    try:
        get_keycloak_admin().update_user(user_id=user_id, payload=payload)
        logger.info(f"User {user_id} verified successfully in Keycloak")
    except Exception as e:
        logger.error(f"Failed to verify user in Keycloak: {e}")


def search_user_by_email_in_keycloak(email, requester):
    '''Search for a user by email in Keycloak. Returns the raw Keycloak user dict or None.'''
    try:
        user_id_keycloak = get_keycloak_admin().get_user_id(email)
    except Exception as e:
        logger.error(f"Failed to search user by email in Keycloak: {e}")
        return None
    else:
        if user_id_keycloak:
            return get_keycloak_admin().get_user(user_id_keycloak)

    return None


def get_user_by_id(user_id):
    return get_keycloak_admin().get_user(user_id)


def set_temporary_password(user_id, payload, requester):
    '''Set the temporary password for a Keycloak user.

    NOTE (preserved production behaviour): this legacy function only clears
    the user's requiredActions and returns — it never actually sets the
    password (the second block below it was unreachable on skorie_users).
    Keycloak temporary passwords block direct-grant login, so the OTP flow
    uses the Django-side activation_code instead. Use
    ``KeycloakIdP.set_temporary_password`` if you really want one set.
    '''

    access_token = get_access_token(requester)
    if not access_token:
        return 401

    admin = get_keycloak_admin()
    admin.token = access_token  # Set the access token

    try:
        admin.update_user(user_id, {"requiredActions": []})
        logger.info(f"Required actions cleared for user {user_id}")
        return 204
    except Exception as e:
        logger.error(f"Failed to clear required actions in Keycloak: {e}")
        return 500


def clear_required_actions(user_id, requester):
    '''Clear the required actions for a user in Keycloak'''

    access_token = get_access_token(requester)
    if not access_token:
        return 401

    admin = get_keycloak_admin()
    admin.token = access_token  # Set the access token
    try:
        admin.clear_user_required_actions(user_id)
        logger.info(f"Required actions cleared for user {user_id}")
        return 204
    except Exception as e:
        logger.error(f"Failed to clear required actions in Keycloak: {e}")
        return 500


def is_temporary_password(user):
    from keycloak.exceptions import KeycloakAuthenticationError

    try:
        # Retrieve the user's credentials from Keycloak
        user_id = user.keycloak_id  # Assuming `keycloak_id` is stored on the user model
        credentials = get_keycloak_admin().get_credentials(user_id)

        for credential in credentials:
            if credential['type'] == 'password' and credential.get('temporary', False):
                return True

    except KeycloakAuthenticationError as e:
        logger.error(f"Error accessing Keycloak API: {e}")

    return False


def verify_login(username, password):
    '''Verify a user's login credentials'''
    from keycloak.exceptions import KeycloakAuthenticationError

    try:
        get_keycloak_openid().token(username=username, password=password)
    except ImproperlyConfigured:
        return False
    except KeycloakAuthenticationError:
        return False
    else:
        return True


def update_password_keycloak(keycloak_id, new_password):
    '''Update the password for a Keycloak user'''

    try:
        get_keycloak_admin().set_user_password(user_id=keycloak_id, password=new_password, temporary=False)
        return True
    except Exception as e:
        logger.error(f"Failed to update password in Keycloak: {e}")
        return False
