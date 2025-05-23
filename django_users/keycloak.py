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

try:
    client_id = settings.KEYCLOAK_CLIENTS['USERS']['CLIENT_ID']
    client_secret = settings.KEYCLOAK_CLIENTS['USERS']['CLIENT_SECRET']
    keycloak_url = settings.KEYCLOAK_CLIENTS['USERS']['URL']
    keycloak_realm = settings.KEYCLOAK_CLIENTS['USERS']['REALM']
except:
    logger.error("Keycloak client ID and secret not found in settings")
    raise

# Initialize KeycloakAdmin for administrative actions
keycloak_admin = KeycloakAdmin(
    server_url=f"{keycloak_url}/",
    realm_name=keycloak_realm,
    client_id=client_id,
    client_secret_key=client_secret,
    verify=True
)

# Initialize KeycloakOpenID
keycloak_openid = KeycloakOpenID(
    server_url=f"{keycloak_url}/",
    realm_name=keycloak_realm,
    client_id=client_id,
    client_secret_key=client_secret,
)


def get_access_token(requester):
    '''Get an access token for the Keycloak admin API'''
    if not requester.is_administrator and not requester.is_manager:
        logger.error(f"User {requester} is not an administrator or manager and cannot request a Keycloak access token")
        return None

    try:
        token = keycloak_openid.token(grant_type="client_credentials")
        logger.info(f"User {requester} requesting Keycloak access token")
        return token['access_token']
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
            keycloak_admin.user_logout(user.keycloak_id)

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
        user_id = keycloak_admin.create_user(user_details)
        logger.info(
            f"User created in Keycloak with ID {user_id} and name {user_details['firstName']} {user_details['lastName']} by {requester}")
        return user_id, 201
    except Exception as e:
        if e.response_code == 409:
            # user already exists so get details
            user_id = keycloak_admin.get_user_id(user_details['email'])
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
        keycloak_admin.update_user(user_id=user_id, payload=payload)
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
        user_id_keycloak = keycloak_admin.get_user_id(email)

    except Exception as e:
        logger.error(f"Failed to search user by email in Keycloak: {e}")
        return None
    except KeycloakGetError as e:
        pass
    else:
        if user_id_keycloak:
            user = keycloak_admin.get_user(user_id_keycloak)
            return user

    return None


def get_user_by_id(user_id):
    return keycloak_admin.get_user(user_id)


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

    keycloak_admin.token = access_token  # Set the access token

    try:
        # TODO: should probably just clear reset password
        keycloak_admin.update_user(user_id, {"requiredActions": []})
        logger.info(f"Required actions cleared for user {user_id}")
        return 204
    except Exception as e:
        logger.error(f"Failed to clear required actions in Keycloak: {e}")
        return 500

    try:
        keycloak_admin.set_user_password(user_id=user_id, password=payload['value'], temporary=True)
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

    keycloak_admin.token = access_token  # Set the access token
    try:
        keycloak_admin.clear_user_required_actions(user_id)
        logger.info(f"Required actions cleared for user {user_id}")
        return 204
    except Exception as e:
        logger.error(f"Failed to clear required actions in Keycloak: {e}")
        return 500


def is_temporary_password(user):
    try:
        # Retrieve the user's credentials from Keycloak
        user_id = user.keycloak_id  # Assuming `keycloak_id` is stored on the user model
        credentials = keycloak_admin.get_credentials(user_id)

        for credential in credentials:
            if credential['type'] == 'password' and credential.get('temporary', False):
                return True

    except KeycloakAuthenticationError as e:
        logger.error(f"Error accessing Keycloak API: {e}")

    return False


def verify_login(username, password):
    '''Verify a user's login credentials'''

    try:
        keycloak_openid.token(username=username, password=password)
    except KeycloakAuthenticationError:
        return False
    else:
        return True


def update_password_keycloak(keycloak_id, new_password):
    '''Update the password for a Keycloak user'''

    try:
        keycloak_admin.set_user_password(user_id=keycloak_id, password=new_password, temporary=False)
        return True
    except Exception as e:
        return False

# not using keycloak and should be elsewhere!
def generate_login_token(user, next_path='/'):
    '''used to get a token to login to another system using the same keycloak realm
    NOTE: this only works if used within the same django app'''
    payload = {
        'user_id': str(user.keycloak_id),
        'ts': timezone.now().timestamp(),
        'next': next_path,
    }
    return signing.dumps(payload)

# not using keycloak and should be elsewhere!
def generate_remote_login_token(user, setting_name, next_path='/'):
    payload = {
        'user_id': str(user.keycloak_id),
        'next': next_path,
    }
    secret = getattr(settings, setting_name, None)
    signer = TimestampSigner(secret, salt='cross-app-login')
    token = signer.sign(json.dumps(payload).encode()).decode()
    return token
