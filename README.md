Django-users shares the common functionality used in particular by skorie but potentially other projects as well.

Currently assumes there is a keycloak realm but this will decoupled in future.



## Settings

This will run without any additional settings but the following settings can be added:


    USE_KEYCLOAK = getattr(settings, 'USE_KEYCLOAK', False)
    LOGIN_URL = getattr(settings, 'LOGIN_URL', 'users:login')
    LOGIN_REGISTER = getattr(settings, 'LOGIN_REGISTER', 'users:register')
    VERIFICATION_CODE_EXPIRY_MINUTES = 5


## Setting up without Keycloak

Create a users app and add django-users to the project and INSTALLED_APPS
