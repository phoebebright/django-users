# create your own urls.py in your users views app - this is a template
from django.contrib.auth.decorators import user_passes_test, login_required
from django.urls import path, register_converter

from .api import SendVerificationCode
from .ref import EventRefConverter
from .views import ProblemSignup, NewUsers, UserMigrationView, UserProfileView, \
    RegisterView, AddCommsChannelView, VerifyChannelView, ManageCommsChannelsView, LoginView, \
    ChangePasswordView, ProblemLogin, ChangePasswordNowView, ForgotPassword, AddUser, update_users, \
    Troubleshoot, UnverifiedUsersList, SendOTP, QRLogin, login_with_token, UserContactAnalyticsView, \
    UnsubscribeTokenView, SubscriptionPreferencesView, subscribe_only, unsubscribe_only, ManageRoles, ManageUsers, \
    ManageUser, SubscriptionDataFrameView, dedupe_role, UserCountries, ConfirmAccount, \
    ManageUserProfile, VerifyMagicLinkView, SendComms, TellUsAbout, after_login_redirect, WhoAmIView, ResetSessionView
from .keycloak import logout_user_from_keycloak_and_django

# using this seems to cause urls to end up with users:users:url rather than users:url
# run python manage.py show_urls to see the actual url names
#app_name = 'users'

register_converter(EventRefConverter, 'event_ref')

def has_role_administrator(user):
    if user and user.is_authenticated:
        return user.is_superuser or user.is_administrator
    else:
        return False

def is_authenticated(user):
    return user and user.is_authenticated

# urlpatterns = [
#
#     path('add_user/',user_passes_test(has_role_administrator)(AddUser.as_view()),name='add-user'),
#     path('manage_user_profile/',user_passes_test(has_role_administrator)(ManagerUserProfile.as_view()),name='manage-user-profile'),
#     path('subscribers/', user_passes_test(has_role_administrator)(subscribers_list), name='subscriber_list'),
#     path('manage_roles/', user_passes_test(has_role_administrator)(ManageRoles.as_view()), name="manage_roles"),
#     path('manage_users/', user_passes_test(has_role_administrator)(ManageUsers.as_view()), name="manage_users"),
#     path('admin_user/<int:pk>/', user_passes_test(has_role_administrator)(ManageUser.as_view()), name="admin_user"),
#     path('admin_user/<str:email>/', user_passes_test(has_role_administrator)(ManageUser.as_view()), name="admin_user"),
#     path('subscribe_only/', SubscribeView.as_view(), name="subscribe_only"),
#     path('profile/', UserProfileView.as_view(), name='user-profile'),
#     path('migrate_login/', UserMigrationView.as_view(), name='user_login'),
#     ]


urlpatterns = [
    # path('api/v2/userprofile/<str:username>/', UserProfileUpdate.as_view(), name="userprofile_update"),
    # path('api/v2/email_exists_on_keycloak/', CheckEmailInKeycloak.as_view(), name='email_exists_on_keycloak'),
    # path('api/v2/set_temp_password/', SetTemporaryPassword.as_view(), name='set_temp_password'),
    path('add_user/', user_passes_test(has_role_administrator)(AddUser.as_view()), name='add-user'),
    path('manage_user_profile/', user_passes_test(has_role_administrator)(ManageUserProfile.as_view()),
         name='manage-user-profile'),
    # path('subscribers/', user_passes_test(has_role_administrator)(subscribers_list), name='subscriber_list'),
    # create ManageRoles, Users and User using Base views in django-users
    path('manage_roles/', user_passes_test(has_role_administrator)(ManageRoles.as_view()), name="manage_roles"),

    path('manage_users/', user_passes_test(has_role_administrator)(ManageUsers.as_view()), name="manage_users"),
    path('admin_user/<int:pk>/', user_passes_test(has_role_administrator)(ManageUser.as_view()), name="admin_user"),
    path('admin_user/<uuid:pk>/', user_passes_test(has_role_administrator)(ManageUser.as_view()), name="admin_user"),
    path('admin_user/<str:email>/', user_passes_test(has_role_administrator)(ManageUser.as_view()), name="admin_user"),  # deprecated
    path('tell_us_about/', TellUsAbout.as_view(), name="tell_us_about"),
    path('profile/', UserProfileView.as_view(), name='user-profile'),

    path('problem_register/', ProblemSignup.as_view(), name="problem_register"),
    path('problem_register/<str:email>/', user_passes_test(has_role_administrator)(ProblemSignup.as_view()),
         name="problem_register_admin"),
    path('troubleshoot/', user_passes_test(has_role_administrator)(Troubleshoot.as_view()), name="troubleshoot"),
    path('problem_login/', ProblemLogin.as_view(), name="problem_login"),
    # path('migrate_login/', UserMigrationView.as_view(), name='user_login'),   # turning off migration view by default
    path('new_users_report/', NewUsers.as_view(), name="new_users_report"),
    path("verify_link/<str:purpose>/", VerifyMagicLinkView.as_view(), name="verify_link"),


    path('logout/', logout_user_from_keycloak_and_django, name='logout'),
    path('logout_all/', logout_user_from_keycloak_and_django, name='logout_all'),
    path('qr_login/', QRLogin.as_view(), name='qr-login'),
    path('lwt/', login_with_token, name='qr-login'),
    path('login/', LoginView.as_view(), name='login'),
    path('after_login_redirect/', after_login_redirect, name='after_login_redirect'),

    # path('login/', LoginView.as_view(), name='signin'),  # deprecated
    path('login/', LoginView.as_view(), name='user_login'),    # switching back to no-migration as default 20nov25

    path('register/', RegisterView.as_view(), name='register'),
    # path('register/', RegisterView.as_view(), name='signup'),  # deprecated
    path("forgot_password/", ForgotPassword.as_view(), name="forgot_password"),
    path("change_password/", ChangePasswordView.as_view(), name="change_password"),
    path("change_password_now/", ChangePasswordNowView.as_view(), name="change_password_now"),

    # path('verify/<uuid:pk>/', VerificationView.as_view(), name='verify'),

    path('channels/add/', AddCommsChannelView.as_view(), name='add_channel'),
    path('channels/verify/<int:channel_id>/', VerifyChannelView.as_view(), name='verify_channel'),

    # path('channels/manage/', ManageCommsChannelsView.as_view(), name='manage_channels'),
    path('update_users/', update_users, name='update_users'),

    path('unverified/', UnverifiedUsersList.as_view(), name='unverified_users_report'),
    path('send_otp/<int:pk>/', SendOTP.as_view(), name='send_otp'),
    path('contact_viz/',UserContactAnalyticsView.as_view(),name='user_contact_analytics'),
    path('preferences/', SubscriptionPreferencesView.as_view(), name='subscription_preferences'),
    path('unsubscribe/<str:token>/', UnsubscribeTokenView.as_view(), name='unsubscribe_token'),


    path('confirm_account/<int:pk>/', ConfirmAccount.as_view(), name='confirm_account'),

    path('contact_list/', SubscriptionDataFrameView.as_view(), name='user_contact_list'),
    path('dedupe_role/<str:role_ref>/', dedupe_role, name='dedupe_role'),
    path("countries/", UserCountries.as_view(), name="user-countries"),

    path('send_comms/<int:user_id>/', login_required()(SendComms.as_view()),
         name='comms2user'),    # TODO: convert to keycloak id and uuid:pk
    path('send_comms/<uuid:pk>/', login_required()(SendComms.as_view()),
         name='comms2user'),
    path('send_comms/<int:user_id>/<str:template>/', login_required()(SendComms.as_view()),
         name='comms2user'), # TODO: convert to keycloak id and uuid:pk
    path("whoami/", WhoAmIView.as_view(), name="whoami"),
    path("reset_session/", ResetSessionView.as_view(), name="reset-session"),
]
