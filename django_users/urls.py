# create your own urls.py in your users views app - this is a template
from django.contrib.auth.decorators import user_passes_test
from django.urls import path

from .api import SendVerificationCode
from .views import SubscribeView, ProblemSignup, NewUsers, UserMigrationView, UserProfileView, \
    RegisterView, AddCommsChannelView, VerifyChannelView, ManageCommsChannelsView, LoginView, \
    ChangePasswordView, ProblemLogin, ChangePasswordNowView, ForgotPassword, ManagerUserProfile, AddUser, update_users, \
    Troubleshoot, UnverifiedUsersList, SendOTP, QRLogin, login_with_token, UserContactAnalyticsView
from .keycloak import logout_user_from_keycloak_and_django

app_name = 'users'


def has_role_administrator(user):
    if user and user.is_authenticated:
        return user.is_superuser or user.is_administrator
    else:
        return False


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
    path('manage_user_profile/', user_passes_test(has_role_administrator)(ManagerUserProfile.as_view()),
         name='manage-user-profile'),
    path('subscribers/', user_passes_test(has_role_administrator)(subscribers_list), name='subscriber_list'),
    path('manage_roles/', user_passes_test(has_role_administrator)(ManageRoles.as_view()), name="manage_roles"),
    path('manage_users/', user_passes_test(has_role_administrator)(ManageUsers.as_view()), name="manage_users"),
    path('admin_user/<int:pk>/', user_passes_test(has_role_administrator)(ManageUser.as_view()), name="admin_user"),
    path('admin_user/<str:email>/', user_passes_test(has_role_administrator)(ManageUser.as_view()), name="admin_user"),
    path('subscribe_only/', SubscribeView.as_view(), name="subscribe_only"),
    path('profile/', UserProfileView.as_view(), name='user-profile'),

    path('problem_register/', ProblemSignup.as_view(), name="problem_register"),
    path('problem_register/<str:email>/', user_passes_test(has_role_administrator)(ProblemSignup.as_view()),
         name="problem_register_admin"),
    path('troubleshoot/', user_passes_test(has_role_administrator)(Troubleshoot.as_view()), name="troubleshoot"),
    path('problem_login/', ProblemLogin.as_view(), name="problem_login"),
    path('migrate_login/', UserMigrationView.as_view(), name='user_login'),
    path('new_users_report/', NewUsers.as_view(), name="new_users_report"),
    # path('verify_account/<str:code>/', VerifyWithCode.as_view(), name="verify_with_code"),

    path('logout/', logout_user_from_keycloak_and_django, name='logout'),
    path('logout_all/', logout_user_from_keycloak_and_django, name='logout_all'),
    path('qr_login/', QRLogin.as_view(), name='qr-login'),
    path('lwt/', login_with_token, name='qr-login'),
    path('login/', LoginView.as_view(), name='login'),
    path('register/', RegisterView.as_view(), name='register'),
    path("forgot_password/", ForgotPassword.as_view(), name="forgot_password"),
    path("change_password/", ChangePasswordView.as_view(), name="change_password"),
    path("change_password_now/", ChangePasswordNowView.as_view(), name="change_password_now"),

    # path('verify/<uuid:pk>/', VerificationView.as_view(), name='verify'),
    path('resend_verify_code/', SendVerificationCode.as_view(), name='resend_verify_code'),
    path('channels/add/', AddCommsChannelView.as_view(), name='add_channel'),
    path('channels/verify/<int:channel_id>/', VerifyChannelView.as_view(), name='verify_channel'),

    # path('channels/manage/', ManageCommsChannelsView.as_view(), name='manage_channels'),
    path('update_users/', update_users, name='update_users'),

    path('unverified/', UnverifiedUsersList.as_view(), name='unverified_users_report'),
    path('send_opt/<int:pk>/', SendOTP.as_view(), name='send_opt'),
    path('contact_viz/',UserContactAnalyticsView.as_view(),name='user_contact_analytics'),
]

'''API urls
    path('api/v2/toggle_role/', toggle_role, name="toggle_role"),
    router.register(r'members', MemberViewSet, basename="members")
    router.register(r'comms_channel', CommsChannelViewSet, basename="commschannel")
    '''
