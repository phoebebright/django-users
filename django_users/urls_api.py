# skorie_news/urls_api.py
from django.conf import settings
from rest_framework.routers import DefaultRouter
from django.urls import path, include



from django_users.api import UserViewset, UserListViewset, CheckEmail, UserCountry, CreateUser, SendOTP2User, \
    UserProfileUpdate, SetTemporaryPassword, toggle_role, CheckEmailInKeycloakPublic, CheckEmailInKeycloak, \
    resend_activation, ChangePassword, CommsChannelViewSet, PersonViewSet, RoleViewSet, OrganisationViewSet, \
    email_exists, SendVerificationCode, CheckUserPublic, PagedUserListViewset
from django_users.views import login_with_token

# Use DRF's DefaultRouter, not django.db.router
router = DefaultRouter()
router.register(r'users', UserViewset, basename="userviewset")  # admins only
router.register(r'userlist', UserListViewset, basename="userlistviewset")  # admins only
router.register(r'userlist_paged', PagedUserListViewset, basename="paged_userlistviewset")  # admins only
# router.register(r'email_exists', CheckEmail, basename='checkemail') . # think this was not used in the end - admins only - returns more info than basic email_exists
router.register(r'users', UserViewset, basename="users")  # admins only
router.register(r'comms_channel', CommsChannelViewSet, basename="commschannel")

router.register(r'person', PersonViewSet, basename="persons")


router.register(r'role', RoleViewSet, basename="role")
router.register(r'organisations', OrganisationViewSet, basename='organisation-ro')

urlpatterns = [
    #these are prepended with api/u1
    path('change_pw/', ChangePassword.as_view(), name="change_pw"),
    path('resend_activation/', resend_activation, name="resend_activation"),
    path('email_exists_on_keycloak/', CheckEmailInKeycloak.as_view(), name='email_exists_on_keycloak'),
    # admin only
    path('email_exists_on_keycloak_p/', CheckEmailInKeycloakPublic.as_view(), name='email_exists_on_keycloak_p'),
    # public with throttle
    path('set_temp_password/', SetTemporaryPassword.as_view(), name='set_temp_password'),
    path('toggle_role/', toggle_role, name="toggle_role"),

    path('userprofile/<uuid:pk>/', UserProfileUpdate.as_view({'patch': 'update'}), name="userprofile_update"),
    path('userprofile/<str:username>/', UserProfileUpdate.as_view({'patch': 'update'}), name="userprofile_update"),
    path('comms_otp/', SendOTP2User.as_view(), name='comms_otp'),
    path('create_user/', CreateUser.as_view(), name='create-user-api'),
    path('user_countries/', UserCountry.as_view(), name='user-country-api'),
    path('ql/', login_with_token, name='qr-login'),  # login to same app, eg. on mobile
    path('lwt/', login_with_token, {'key': settings.REMOTE_LOGIN_SECRET}, name='login-with-token'), # request to login from remote app with token
    # path('email_exists/', email_exists, name='email_exists'),

    # these two calls do very similar things - at some point combine
    path('email_exists/', email_exists, name='email_exists'),
    path('check_user/', CheckUserPublic.as_view({'post': 'post'}), name='check_user'),

    path('resend_verify_code/', SendVerificationCode.as_view(), name='resend_verify_code'),




    path('', include(router.urls)),
]
