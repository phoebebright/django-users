# Reference URLs for projects consuming django-users:authentik. Copy into
# your project's users/urls.py and adapt as needed.
from django.contrib.auth.decorators import user_passes_test, login_required
from django.urls import path, register_converter

from .api import SendVerificationCode
from .ref import EventRefConverter
from .views import (
    NewUsers,
    UserProfileView,
    RegisterView,
    AddCommsChannelView,
    VerifyChannelView,
    ManageCommsChannelsView,
    ChangePasswordView,
    ChangePasswordNowView,
    ForgotPassword,
    AddUser,
    SendOTP,
    QRLogin,
    login_with_token,
    UserContactAnalyticsView,
    UnsubscribeTokenView,
    SubscriptionPreferencesView,
    subscribe_only,
    unsubscribe_only,
    ManageRoles,
    ManageUsers,
    ManageUser,
    SubscriptionDataFrameView,
    dedupe_role,
    UserCountries,
    ConfirmAccount,
    ManageUserProfile,
    VerifyMagicLinkView,
    SendComms,
    TellUsAbout,
    after_login_redirect,
    WhoAmIView,
    ResetSessionView,
    login_with_remote_token,
    AdminInviteView,
    AcceptInvite,
    EnterOTP,
    AdminEditContact,
    AdminAddChannel,
    AdminDeleteChannel,
    AdminSendChannelVerification,
    AdminMarkChannelVerified,
)

# using this seems to cause urls to end up with users:users:url rather than users:url
# run python manage.py show_urls to see the actual url names
# app_name = 'users'

try:
    register_converter(EventRefConverter, 'event_ref')
except ValueError:
    # Already registered by the consumer project's urls.
    pass


def has_role_administrator(user):
    if user and user.is_authenticated:
        return user.is_superuser or user.is_administrator
    else:
        return False


def is_authenticated(user):
    return user and user.is_authenticated


urlpatterns = [
    path('add_user/', user_passes_test(has_role_administrator)(AddUser.as_view()), name='add-user'),
    path('manage_user_profile/', user_passes_test(has_role_administrator)(ManageUserProfile.as_view()),
         name='manage-user-profile'),
    path('manage_roles/', user_passes_test(has_role_administrator)(ManageRoles.as_view()), name="manage_roles"),
    path('manage_users/', user_passes_test(has_role_administrator)(ManageUsers.as_view()), name="manage_users"),
    path('admin_user/<int:pk>/', user_passes_test(has_role_administrator)(ManageUser.as_view()), name="admin_user"),
    path('admin_user/<uuid:pk>/', user_passes_test(has_role_administrator)(ManageUser.as_view()), name="admin_user"),
    path('admin_user/<str:email>/', user_passes_test(has_role_administrator)(ManageUser.as_view()), name="admin_user"),  # deprecated
    path('tell_us_about/', TellUsAbout.as_view(), name="tell_us_about"),
    path('profile/', UserProfileView.as_view(), name='user-profile'),

    path('new_users_report/', NewUsers.as_view(), name="new_users_report"),
    path("verify_link/<str:purpose>/", VerifyMagicLinkView.as_view(), name="verify_link"),

    # Auth flow lives in mozilla-django-oidc — projects should include
    # `path('oidc/', include('mozilla_django_oidc.urls'))` in their main urls.
    # The 'login' and 'logout' URL names below are aliases that resolve to
    # the OIDC views.
    path('after_login_redirect/', after_login_redirect, name='after_login_redirect'),

    path('register/', RegisterView.as_view(), name='register'),
    path("forgot_password/", ForgotPassword.as_view(), name="forgot_password"),
    path("change_password/", ChangePasswordView.as_view(), name="change_password"),
    path("change_password_now/", ChangePasswordNowView.as_view(), name="change_password_now"),

    path('channels/add/', AddCommsChannelView.as_view(), name='add_channel'),
    path('channels/verify/<int:channel_id>/', VerifyChannelView.as_view(), name='verify_channel'),

    path('qr_login/', QRLogin.as_view(), name='qr-login'),
    path('lwt/', login_with_token, name='lwt'),
    path('lwrt/', login_with_remote_token, name='lwrt'),

    path('send_otp/<int:pk>/', SendOTP.as_view(), name='send_otp'),
    path('contact_viz/', UserContactAnalyticsView.as_view(), name='user_contact_analytics'),
    path('preferences/', SubscriptionPreferencesView.as_view(), name='subscription_preferences'),
    path('unsubscribe/<str:token>/', UnsubscribeTokenView.as_view(), name='unsubscribe_token'),

    path('confirm_account/<int:pk>/', ConfirmAccount.as_view(), name='confirm_account'),

    # Admin invite + accept (Slice 2 of authentik migration plan).
    path('add_user/invite/', user_passes_test(has_role_administrator)(AdminInviteView.as_view()), name='admin_invite'),
    path('accept_invite/<str:token>/', AcceptInvite.as_view(), name='accept_invite'),
    path('enter_otp/', EnterOTP.as_view(), name='enter_otp'),

    path('contact_list/', SubscriptionDataFrameView.as_view(), name='user_contact_list'),
    path('dedupe_role/<str:role_ref>/', dedupe_role, name='dedupe_role'),
    path("countries/", UserCountries.as_view(), name="user-countries"),

    path('send_comms/<int:user_id>/', login_required()(SendComms.as_view()),
         name='comms2user'),
    path('send_comms/<uuid:pk>/', login_required()(SendComms.as_view()),
         name='comms2user'),
    path('send_comms/<int:user_id>/<str:template>/', login_required()(SendComms.as_view()),
         name='comms2user'),
    path("whoami/", WhoAmIView.as_view(), name="whoami"),
    path("reset_session/", ResetSessionView.as_view(), name="reset-session"),

    # Admin: edit contact + manage comms channels on behalf of a user.
    # Each pattern accepts both int pk and uuid (authentik_id) — same as
    # the existing admin_user routes that consuming projects define.
    path('admin_user/<int:pk>/edit-contact/',
         user_passes_test(has_role_administrator)(AdminEditContact.as_view()),
         name='admin_user_edit_contact'),
    path('admin_user/<uuid:pk>/edit-contact/',
         user_passes_test(has_role_administrator)(AdminEditContact.as_view()),
         name='admin_user_edit_contact'),
    path('admin_user/<int:pk>/add-channel/',
         user_passes_test(has_role_administrator)(AdminAddChannel.as_view()),
         name='admin_user_add_channel'),
    path('admin_user/<uuid:pk>/add-channel/',
         user_passes_test(has_role_administrator)(AdminAddChannel.as_view()),
         name='admin_user_add_channel'),
    path('admin_user/<int:pk>/delete-channel/<int:channel_pk>/',
         user_passes_test(has_role_administrator)(AdminDeleteChannel.as_view()),
         name='admin_user_delete_channel'),
    path('admin_user/<uuid:pk>/delete-channel/<int:channel_pk>/',
         user_passes_test(has_role_administrator)(AdminDeleteChannel.as_view()),
         name='admin_user_delete_channel'),
    path('admin_user/<int:pk>/send-channel-verify/<int:channel_pk>/',
         user_passes_test(has_role_administrator)(AdminSendChannelVerification.as_view()),
         name='admin_user_send_channel_verify'),
    path('admin_user/<uuid:pk>/send-channel-verify/<int:channel_pk>/',
         user_passes_test(has_role_administrator)(AdminSendChannelVerification.as_view()),
         name='admin_user_send_channel_verify'),
    path('admin_user/<int:pk>/mark-channel-verified/<int:channel_pk>/',
         user_passes_test(has_role_administrator)(AdminMarkChannelVerified.as_view()),
         name='admin_user_mark_channel_verified'),
    path('admin_user/<uuid:pk>/mark-channel-verified/<int:channel_pk>/',
         user_passes_test(has_role_administrator)(AdminMarkChannelVerified.as_view()),
         name='admin_user_mark_channel_verified'),
]
