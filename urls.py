from django.contrib.auth.decorators import user_passes_test
from django.urls import path
from skorie.common.views import subscribers_list, ManageRoles, ManageUsers, ManageUser
from .views import ManagerUserProfile, SubscribeView, AddUser, UserProfileView, UserMigrationView

app_name = 'users'

def has_role_administrator(user):
    if user and user.is_authenticated:
        return user.is_superuser or user.is_administrator
    else:
        return False

urlpatterns = [

    path('add_user/',user_passes_test(has_role_administrator)(AddUser.as_view()),name='add-user'),
    path('manage_user_profile/',user_passes_test(has_role_administrator)(ManagerUserProfile.as_view()),name='manage-user-profile'),
    path('subscribers/', user_passes_test(has_role_administrator)(subscribers_list), name='subscriber_list'),
    path('manage_roles/', user_passes_test(has_role_administrator)(ManageRoles.as_view()), name="manage_roles"),
    path('manage_users/', user_passes_test(has_role_administrator)(ManageUsers.as_view()), name="manage_users"),
    path('admin_user/<int:pk>/', user_passes_test(has_role_administrator)(ManageUser.as_view()), name="admin_user"),
    path('admin_user/<str:email>/', user_passes_test(has_role_administrator)(ManageUser.as_view()), name="admin_user"),
    path('subscribe_only/', SubscribeView.as_view(), name="subscribe_only"),
    path('profile/', UserProfileView.as_view(), name='user-profile'),
    path('migrate_login/', UserMigrationView.as_view(), name='user_login'),
    ]
