Django-users shares the common functionality used in particular by skorie but potentially other projects as well.

Can be run with or without keycloak



## Settings

This will run without any additional settings but the following settings can be added:


    USE_KEYCLOAK = getattr(settings, 'USE_KEYCLOAK', False)
    LOGIN_URL = getattr(settings, 'LOGIN_URL', 'users:login')
    LOGIN_REGISTER = getattr(settings, 'LOGIN_REGISTER', 'users:register')
    VERIFICATION_CODE_EXPIRY_MINUTES = 5
    VERIFY_ONCE = True    # if user is verified in one system sharing a realm  then will be auto everified on a second - if you want each client to verify their users then set to False

Make sure that django model authentication is your first choice, eg.

    AUTHENTICATION_BACKENDS = (
        "django.contrib.auth.backends.ModelBackend",      # MODELBACKEND must be first
        'django_keycloak_admin.backends.KeycloakAuthorizationCodeBackend',
        'django_keycloak_admin.backends.KeycloakPasswordCredentialsBackend',  
    )

## Setting up without Keycloak

1. copy users directory from another system
2. copy users template directory from another system
3. add to requirements: git+https://github.com/phoebebright/django-users
4. install
5. add to settings.py:


```python
INSTALLED_APPS = [
    ...
    'users',
    ...
]

USE_KEYCLOAK = False
```

6. check there is a login and register url

from django_users.api import ChangePassword, resend_activation, CheckEmailInKeycloak, SetTemporaryPassword, \
    CheckEmailInKeycloakPublic, toggle_role, CreateUser
from users.api import UserProfileUpdate, CheckEmail, OrganisationViewSet, UserViewset, CommsChannelViewSet, \
    UserListViewset, SendOTP2User, InternalRoleViewSet, RoleViewSet, MyInternalRoles, PersonViewSet
from django_users.views import login_redirect, signup_redirect, after_login_redirect, send_test_email,  \
     unsubscribe_only
from users.views import SubscribeView, ManageRoles

    # users apis
    path('api/v2/change_pw/', ChangePassword.as_view(), name="change_pw"),
    path('api/v2/resend_activation/', resend_activation, name="resend_activation"),
    path('api/v2/email_exists_on_keycloak/', CheckEmailInKeycloak.as_view(), name='email_exists_on_keycloak'),
    # admin only
    path('api/v2/email_exists_on_keycloak_p/', CheckEmailInKeycloakPublic.as_view(), name='email_exists_on_keycloak_p'),
    # public with throttle
    path('api/v2/set_temp_password/', SetTemporaryPassword.as_view(), name='set_temp_password'),
    path('api/v2/toggle_role/', toggle_role, name="toggle_role"),
    path('api/v2/toggle_tag_for_deletion/', toggle_tag_for_deletion, name="toggle_tag_for_deletion"),
    path('api/v2/comms_otp/', SendOTP2User.as_view(), name='comms_otp'),
    path('api/v2/create_user/', CreateUser.as_view(), name='create-user-api'),

    path('ql/', login_with_token, name='qr-login'),   # login to same app, eg. on mobile
    path('lwt/', login_with_token,{'key': settings.REMOTE_LOGIN_SECRET}, name='login-with-token'),   # request to login from remote app with token
    path('login/', login_redirect, name='login'),
    path('logout', logout_user_from_keycloak_and_django, name="logout"),
    path('after_login_redirect/', after_login_redirect, name="after_login_redirect"),

    path('send_comms/<int:user_id>/', login_required()(SendComms.as_view()),
         name='comms2user'),    # TODO: convert to keycloak id and uuid:pk
    path('send_comms/<uuid:pk>/', login_required()(SendComms.as_view()),
         name='comms2user'),
    path('send_comms/<int:user_id>/<str:template>/', login_required()(SendComms.as_view()),
         name='comms2user'), # TODO: convert to keycloak id and uuid:pk

    path('subscribe_only/', SubscribeView.as_view(), name="subscribe_only"),
    path('unsubscribe_only/', unsubscribe_only, name="unsubscribe_only"),
    path('subscribe_thanks/', TemplateView.as_view(template_name="registration/thanks.html"), name="subscribe_thanks"),

    # path('preview123/', TemplateView.as_view(template_name="email/confirm_email_copy.html"), name="preview123"),
    # path('invite/', login_required()(InviteUserView.as_view()), name='invite'),
    path('outstanding_invites/', login_required()(OutstandingEventTeamInvites.as_view()), name='outstanding-invite'),
    path('request_role/<str:role>/', login_required()(RequestRole.as_view()), name='request-role'),

You will need these in requirements (should not have all these dependancies!)

    git+https://github.com/phoebebright/django-users
    django_countries
    nanoid
    django-timezone-field
    # original library - not being updated
    git+https://github.com/phoebebright/django-yamlfield

Currently need roles and disciplines.  Create a file (see default_roles_and_disciplines.py) and add settings to point to it:

```python
MODEL_ROLES_PATH = 'config.roles_and_disciplines.ModelRoles'
DISCIPLINES_PATH = 'config.roles_and_disciplines.Disciplines'
```


## Migrating from keycloak to no keycloak

We need the password.  Best approach is to have a migration period to get most of the users across automatically, saving the password in django as we go.  

in settings: KEYCLOAK_MIGRATING = True
This will save the password in the django database (encrypted) on successful login

Benefits of keeping keycloak:
- MFA (not currently used)
- SSO (if multiple apps share same users)
- Social Signon - can also be implemented in django


## Status Updates

By default users are USER_STATUS_UNCONFIRMED (3) and then they become USER_STATUS_CONFIRMED (4) when they do something like fill in the profile.  By default this is done when update_subscribed is called but  decide how you want this to work and ensure it is in the save code of your user model.  You can call self.confirm()

```python
       # confirm once profile complete (ie. country is set)
        if self.country and self.status == self.USER_STATUS_UNCONFIRMED:
            self.confirm()
