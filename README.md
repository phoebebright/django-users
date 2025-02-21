Django-users shares the common functionality used in particular by skorie but potentially other projects as well.

Currently assumes there is a keycloak realm but this will decoupled in future.



## Settings

This will run without any additional settings but the following settings can be added:


    USE_KEYCLOAK = getattr(settings, 'USE_KEYCLOAK', False)
    LOGIN_URL = getattr(settings, 'LOGIN_URL', 'users:login')
    LOGIN_REGISTER = getattr(settings, 'LOGIN_REGISTER', 'users:register')



## Setting up without Keycloak

Create a users app and add django-users to the project and INSTALLED_APPS
In the users app create models, views, api and urls and base them on the classes in django-users - CREATE YOUR OWN URLS.PY - django_users is not intended to be used directly.

eg. here there is a mix of calls to views in django_users and views that have custom functionality in the users app.

    from django.urls import path
    from django.contrib.auth.decorators import login_required, user_passes_test
    from django_users.api import SendVerificationCode
    from django_users.views import LoginView, NewUsers, logout, ForgotPassword, ChangePasswordView, \
        VerifyChannelViewBase as VerifyChannelView, ProblemLogin
    
    from users.api import RenewCookiePermission
    from users.views import AddCommsChannelView, AddUser, ManagerUserProfile, ManageUsers, ManageUser, ManageRoles

models.py
        
    class CommsChannel(CommsChannelBase):
    
       pass
    
    class VerificationCode(VerificationCodeBase):
        pass
    

Note that if this is being built on top of an existing users model, then add the CustomUserBase or CustomUserBaseBasic model definition and migrate.  Then you will need to save each object individually so it can create a people instance.  Then you will need to setup roles for the different users, by hand or write a migration.
