import json
import logging
from datetime import datetime
from urllib.parse import urlencode

import requests


from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin

from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import redirect
from django.urls import reverse_lazy, reverse
from django.utils import timezone
from django.views import generic, View
from django.conf import settings
from django.views.generic import FormView
from keycloak import KeycloakAdmin, KeycloakGetError
from post_office import mail
from django.contrib.auth import (authenticate, get_user_model, login, logout as log_out,
                                 update_session_auth_hash)

from skorie.common.mixins import GoNextMixin
from .keycloak import get_access_token
from .forms import CustomUserCreationForm, SubscribeForm, ProfileForm, UserMigrationForm
from .keycloak import create_keycloak_user
from .models import UserContact, CustomUser

logger = logging.getLogger('django')

def get_legitimate_redirect(request):
    nextpage=request.GET.get('next','/')
    if nextpage.startswith('http'):
        # prevent malicious redirects
        nextpage='/'
    return nextpage

class AddUser(generic.CreateView):
    '''this creates both a local user instance and a keycloak instance (if it doesn't already exist)'''
    #TODO: must be administrator or manager (?)
    form_class = CustomUserCreationForm
    template_name = 'organiser/users/add_user.html'

    def form_valid(self, form):
        '''create the keycloak user first then the local user'''
        me = self.request.user

        payload = {
            "email": form.cleaned_data['email'],
            "firstName": form.cleaned_data['first_name'],
            "lastName": form.cleaned_data['last_name'],
            "enabled": True,
            "credentials": [{
                "type": "password",
                "value": form.cleaned_data['password'],
                "temporary": True
            }]
        }

        username, status_code = create_keycloak_user(payload, me)

        if username:
            # now create the django instance
            user = form.save(commit=False)
            user.username = username
            user.attributes = {'temporary_password': form.cleaned_data['password']}
            user.creator = me
            user.save()

            message = f"Dear {user.first_name},\n\nYou have been signed up with Skor.ie by {me.name}.  Your temporary password is {form.cleaned_data['password']}.  Please log in and change your password as soon as possible. \nIf this is a mistake please ignore this email and the account will be deleted after 1 week.\n\nBest wishes,\nSkor.ie"
            mail.send(
                subject="You are signed up with Skor.ie",
                message=message,
                html_message=message,
                recipients=[user.email, ],
                sender=settings.DEFAULT_FROM_EMAIL,
                priority='now',
            )
        return HttpResponseRedirect(reverse_lazy('users:admin_user', kwargs={'pk': user.pk}))

class ManagerUserProfile(generic.CreateView):
    form_class = CustomUserCreationForm
    template_name = 'organiser/users/manage_user_profile.html'

    def form_valid(self, form):
        # This method is called when valid form data has been POSTed.
        # It should return an HttpResponse.
        user = form.save()  # Save the user and get the instance

        # Custom post-save logic here
        # e.g., sending a confirmation email

        return super().form_valid(form)


class SubscribeView(FormView):
    template_name = "subscribe.html"
    form_class = SubscribeForm
    success_url = '/'

    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

    def form_valid(self, form):

        # only available for signed in user
        user = self.request.user

        # extra fields
        user.country = form.cleaned_data['country']
        user.mobile = form.cleaned_data['mobile']
        user.whatsapp = form.cleaned_data['whatsapp']
        user.city = form.cleaned_data['city']
        user.save()


        # this will set status to at least Confirmed
        user.update_subscribed(form.cleaned_data['subscribe'])



        # add contact note
        notify = settings.NOTIFY_NEW_USER_EMAILS > ""
        UserContact.add(user=user, method="Subscribe & Interest Form", notes = json.dumps(form.cleaned_data), data=form.cleaned_data, send_mail=notify)

        return super().form_valid(form)



def unsubscribe_only(request):

    if request.user.is_authenticated:
        request.user.update_subscribed(False)


    return HttpResponseRedirect()




@login_required()
def send_test_email(request):


    # send_test_message('smtp', to=request.user)
    mail.send(
        subject="Test Message from Skor.ie",
        message="This is a test message to check that email can be sent to your account.",
        recipients=[request.user.email, ],
        sender=settings.DEFAULT_FROM_EMAIL,
        priority='now',
    )

    return HttpResponse("Mail Sent...")

def add_user(payload, user):

    access_token = get_access_token()


    status_code, userid = create_user(access_token, user_details)
    if status_code != 201:
        initial_password = ""
    print("User creation status code:", status_code)
    if userid:
        CustomUser.objects.create
    return Response(initial_password)


# user = User.objects.create_user(username=userid, email=user_details['email'],
#                                 first_name=user_details['firstName'], last_name=user_details['lastName'])


def logout(request):

    nextpage=get_legitimate_redirect(request)

    if len(settings.AUTHENTICATION_BACKENDS) > 1:
        return HttpResponseRedirect(f"/keycloak/logout?next={nextpage}")

    else:
        log_out(request)
        return HttpResponseRedirect(nextpage)

    # return_to = urlencode({'returnTo': request.build_absolute_uri('/')})
    # return HttpResponseRedirect("/keycloak/logout")
    # return HttpResponseRedirect(logout_url)

def login_redirect(request):
    if len(settings.AUTHENTICATION_BACKENDS) > 1:
        return HttpResponseRedirect(f"/keycloak/login?next={request.GET.urlencode()}")
    else:
        # this doesn't seem to be working
        return HttpResponseRedirect(f"/account/login/?next={request.GET.urlencode()}")

def signup_redirect(request):
    '''in previous version if you passed in any query_param it assumed it was next - now you have to specify'''
    #TODO: not adding login_hint so reverting to previous behavoir
    # allowed_params = {}
    # if 'next' in request.GET:
    #     allowed_params['next'] = request.GET['next']
    # if 'login_hint' in request.GET:
    #     allowed_params['login_hint'] = request.GET['login_hint']

    if len(settings.AUTHENTICATION_BACKENDS) > 1:
        url = f"/keycloak/register"
    else:
        url = f"/account/login/"


    # Construct the final URL
    # signup_url = f"{url}?{urlencode(allowed_params)}"


    if 'next' in request.GET.urlencode():
        url += "?{request.GET.urlencode()}"
    elif request.GET.urlencode():
        url += "?next={request.GET.urlencode()}"

    return HttpResponseRedirect(url)

def logout(request):

    nextpage=get_legitimate_redirect(request)

    if len(settings.AUTHENTICATION_BACKENDS) > 1:
        return HttpResponseRedirect(f"/keycloak/logout?next={nextpage}")

    else:
        log_out(request)
        return HttpResponseRedirect(nextpage)

    # return_to = urlencode({'returnTo': request.build_absolute_uri('/')})
    # return HttpResponseRedirect("/keycloak/logout")
    # return HttpResponseRedirect(logout_url)

def login_redirect(request):
    if len(settings.AUTHENTICATION_BACKENDS) > 1:
        return HttpResponseRedirect(f"/keycloak/login?next={request.GET.urlencode()}")
    else:
        # this doesn't seem to be working
        return HttpResponseRedirect(f"/account/login/?next={request.GET.urlencode()}")

def after_login_redirect(request):
    # using skor.ie emails as temporary emails so don't want subscirbe form displayed
    if request.user.status < CustomUser.USER_STATUS_CONFIRMED and not "@skor.ie" in request.user.email:
        url = reverse("subscribe_only")
    else:
        url = "/"

    return HttpResponseRedirect(url)


class UserProfileView(LoginRequiredMixin, GoNextMixin, FormView):
    form_class = ProfileForm
    model = CustomUser

    def get_template_names(self):

        return  "competitor/profile.html"

    def get_object(self, queryset=None):
        # can only see your own profile

        return self.request.user


    def get_initial(self):
        initial = super().get_initial()
        user = self.request.user
        if user.is_authenticated:

            initial['country'] = user.country
            initial['city'] = user.profile['city'] if 'city' in user.profile else ''
            initial['where_did_you_hear'] = user.profile['where_did_you_hear'] if 'where_did_you_hear' in user.profile else ''
            initial['mobile'] = user.mobile
            initial['whatsapp'] = user.whatsapp
        return initial



    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['USE_SUBSCRIBE'] = settings.USE_SUBSCRIBE
        context['now'] = timezone.now()
        context['roles'] = self.request.user.user_roles(descriptions=True)
        context['update_account_url'] = f"{settings.KEYCLOAK_CLIENTS['DEFAULT']['URL']}/auth/realms/{settings.KEYCLOAK_CLIENTS['DEFAULT']['REALM']}/account/"

        return context

    def post(self, request, *args, **kwargs):

        form = self.get_form()
        if form.is_valid():
            user = request.user
            user.country = form.cleaned_data['country']
            user.profile['city'] = form.cleaned_data['city']
            user.profile['where_did_you_hear'] = form.cleaned_data['where_did_you_hear']
            user.mobile = form.cleaned_data['mobile']
            user.whatsapp = form.cleaned_data['whatsapp']
            user.save()

            return HttpResponseRedirect(self.get_success_url())

def get_keycloak_signup_url(email):
        """Construct the Keycloak signup URL with the email pre-filled."""
        base_url = f"{settings.KEYCLOAK_CLIENTS['DEFAULT']['URL']}/realms/{settings.KEYCLOAK_CLIENTS['DEFAULT']['REALM']}/protocol/openid-connect/auth"
        params = {
            'client_id': settings.KEYCLOAK_CLIENTS['DEFAULT']['CLIENT_ID'],
            'response_type': 'code',
            'scope': 'email',
            'redirect_uri': "http://whinnie.eu.ngrok.io/keycloak/login-complete/",
            'login_hint': email,
            'action': 'register'
        }
        signup_url = f"{base_url}?{urlencode(params)}"
        return signup_url

class UserMigrationView(View):
    http_method_names = ['post',]

    def authenticate_old_keycloak(self, email, password):
        token_url = f"{settings.OLD_KEYCLOAK_URL}/realms/{settings.OLD_REALM}/protocol/openid-connect/token"
        data = {
            'client_id': settings.OLD_CLIENT_ID,
            'client_secret': settings.OLD_CLIENT_SECRET,  # Include the client secret here
            'grant_type': 'password',
            'username': email,
            'password': password,
        }
        response = requests.post(token_url, data=data)
        return response.status_code == 200

    def update_password_new_keycloak(self, email, password):
        try:
            # Initialize KeycloakAdmin for the new Keycloak instance
            new_keycloak_admin = KeycloakAdmin(
                server_url=settings.KEYCLOAK_CLIENTS['ADMIN']['URL'],
                username=settings.KEYCLOAK_ADMIN_USERNAME,  # Admin username for new Keycloak
                password=settings.KEYCLOAK_ADMIN_PASSWORD,  # Admin password for new Keycloak
                realm_name=settings.KEYCLOAK_CLIENTS['ADMIN']['REALM'],
                client_id=settings.KEYCLOAK_CLIENTS['ADMIN']['CLIENT_ID'],
                client_secret_key=settings.KEYCLOAK_CLIENTS['ADMIN']['CLIENT_SECRET'],
                verify=True  # Set to False if you encounter SSL issues
            )

        except KeycloakGetError as e:
            print(f"Failed to update password in new Keycloak: {e.response_code} - {e.error_message}")
            return False

        try:
            # Find the user by email
            users = new_keycloak_admin.get_users({"email": email})
            if users:
                user_id = users[0]['id']
                # Update the user's password
                new_keycloak_admin.set_user_password(user_id, password, temporary=False)
                return True
            else:
                print(f"User with email {email} not found in new Keycloak.")
                # need to add them
                return False
        except Exception as e:
            print(f"Failed to update password in new Keycloak: {e}")

        return False

    def post(self, request, *args, **kwargs):
        from django_keycloak_admin.backends import KeycloakPasswordCredentialsBackend
        email = request.POST.get('email')
        password = request.POST.get('password')

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            # check if user has signup in new keycloak and is so proceed with login first time
            # Need to redirect to register page - email already filled in
            user = None
        else:
            if user.last_login < timezone.make_aware(datetime(*settings.USER_MIGRATION_DATE)):

                    # try authenticating with old keycloak
                    if self.authenticate_old_keycloak(email, password):
                        if self.update_password_new_keycloak(email, password):
                            logger.info(f"User {email} has been migrated successfully.")
                        else:
                            logger.info(f"User {email} Failed to update password in the new system.")
                            return redirect(settings.FORGOT_PASSWORD_URL)

        # need to sign in user with new keycloak
        backend = KeycloakPasswordCredentialsBackend()
        authenticated_user = backend.authenticate(self.request, username=email, password=password)
        if authenticated_user:
            login(request, authenticated_user, backend='django_keycloak_admin.backends.KeycloakPasswordCredentialsBackend')
            messages.success(request, "You have been successfully logged in.")
            return redirect(settings.LOGIN_REDIRECT_URL)
        else:
            messages.error(self.request, "Authentication failed. Please check your credentials.")
            return redirect("/")
