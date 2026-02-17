import json
import logging
from urllib.parse import urlencode

import requests
from django.conf import settings
from django.contrib.auth import get_user_model, logout, login
from django.core import signing
from django.core.signing import TimestampSigner, SignatureExpired, BadSignature
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.utils import timezone


from django_users import apps
from keycloak import KeycloakAdmin, KeycloakOpenID
from keycloak.exceptions import KeycloakAuthenticationError, KeycloakGetError

logger = logging.getLogger('django')

# Lazy configuration and clients to avoid import-time failures in tests or
# environments where Keycloak is not configured/used.
from django.core.exceptions import ImproperlyConfigured

_keycloak_admin = None
_keycloak_openid = None


def _get_keycloak_config():
    """Return Keycloak configuration from settings or raise a clear error.

    We do not access settings at import time to keep this module safe to import
    in environments (e.g., tests) where Keycloak is not used.
    """
    if not getattr(settings, 'USE_KEYCLOAK', False):
        raise ImproperlyConfigured("Keycloak is disabled (USE_KEYCLOAK=False)")

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
    '''
    new_user = keycloak_admin.create_user({"email": "example@example.com",
                                       "username": "example@example.com",
                                       "enabled": True,
                                       "firstName": "Example",
                                       "lastName": "Example",
                                        "credentials": [{"value": "secret","type": "password",}]})
    user_details = {
        "email": "example@example.com",
        "username": "example@example.com",
        "enabled": True,
        "firstName": "Example",
        "lastName": "Example",
        "credentials": [{
            "value": "secret",  # Password for the new user
            "type": "password",
            "temporary": False  # If True, forces the user to reset the password on first login
        }],
        "requiredActions": []  # Optional: Actions the user must complete (e.g., VERIFY_EMAIL)
    }
        '''

    try:
        user_id = get_keycloak_admin().create_user(user_details)
        logger.info(
            f"User created in Keycloak with ID {user_id} and name {user_details['firstName']} {user_details['lastName']} by {requester}")
        return user_id, 201
    except Exception as e:
        if e.response_code == 409:
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
    '''Search for a user by email in Keycloak'''
    # how do we prevent ordinary users abusing this?
    # if not requester.is_administrator and not requester.email == email:
    #     logger.error(f"User {requester} is not an administrator and cannot search for other users by email in Keycloak")
    #     return None
    try:
        user_id_keycloak = get_keycloak_admin().get_user_id(email)

    except Exception as e:
        logger.error(f"Failed to search user by email in Keycloak: {e}")
        return None
    except KeycloakGetError as e:
        pass
    else:
        if user_id_keycloak:
            user = get_keycloak_admin().get_user(user_id_keycloak)
            return user

    return None


def get_user_by_id(user_id):
    return get_keycloak_admin().get_user(user_id)


#
# def update_users(request):
#     # temporary function to update all users with keycloak_id
#     from users.models import User
#     for user in User.objects.filter(keycloak_id__isnull=True):
#         try:
#             user.keycloak_id = keycloak_admin.get_user_id(user.email)
#         except Exception as e:
#             print(e)
#         else:
#             user.save(update_fields=['keycloak_id',])


def set_temporary_password(user_id, payload, requester):
    '''Set the temporary password for a Keycloak user'''

    access_token = get_access_token(requester)
    if not access_token:
        return 401

    admin = get_keycloak_admin()
    admin.token = access_token  # Set the access token

    try:
        # TODO: should probably just clear reset password
        admin.update_user(user_id, {"requiredActions": []})
        logger.info(f"Required actions cleared for user {user_id}")
        return 204
    except Exception as e:
        logger.error(f"Failed to clear required actions in Keycloak: {e}")
        return 500

    try:
        get_keycloak_admin().set_user_password(user_id=user_id, password=payload['value'], temporary=True)
        logger.info(f"Temporary password set for user {user_id}")
        return 204
    except Exception as e:
        logger.error(f"Failed to set temporary password in Keycloak: {e}")
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
        return False
