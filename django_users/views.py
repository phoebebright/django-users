import json
import logging

from datetime import datetime, timedelta
from urllib.parse import urlencode

from django.apps import apps
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache

from .forms import SubscribeForm, ChangePasswordNowCurrentForm, ForgotPasswordForm, ChangePasswordForm
from .keycloak_models import UserEntity

import requests

from django.contrib.auth.decorators import login_required, user_passes_test

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils.translation import gettext_lazy as _
from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import redirect, get_object_or_404, render
from django.urls import reverse_lazy, reverse
from django.utils import timezone
from django.views import generic, View
from django.conf import settings
from django.views.generic import FormView, TemplateView, DetailView, ListView
from keycloak import KeycloakAdmin, KeycloakGetError, KeycloakAuthenticationError
from post_office import mail
from django.contrib.auth import (authenticate, get_user_model, login, logout as log_out,
                                 update_session_auth_hash, get_user_model)


from tools.permission_mixins import UserCanAdministerMixin

from .keycloak import get_access_token, verify_user_without_email, keycloak_admin, verify_login, update_password, \
    is_temporary_password, get_user_by_id, search_user_by_email_in_keycloak
from .keycloak import create_keycloak_user
from .tools.views_mixins import GoNextMixin, CheckLoginRedirectMixin


User = get_user_model()

logger = logging.getLogger('django')

USE_KEYCLOAK = getattr(settings, 'USE_KEYCLOAK', False)
LOGIN_URL = getattr(settings, 'LOGIN_URL', 'users:login')
LOGIN_REGISTER = getattr(settings, 'LOGIN_REGISTER', 'users:register')

CommsChannel = apps.get_model('users.CommsChannel')  # Replace 'users' with your app name
CHANNEL_EMAIL = CommsChannel.CHANNEL_EMAIL

def get_legitimate_redirect(request):
    nextpage = request.GET.get('next', '/')
    if nextpage.startswith('http'):
        # prevent malicious redirects
        nextpage = '/'
    return nextpage

class GoNextTemplateMixin(TemplateView):
    '''used for event views to work out where to go next'''

    def get_context_data(self, **kwargs):
        '''some forms put a url name in 'go_next' - respect this, otherwise go to event home'''
        context = super().get_context_data(**kwargs)

        context['next'] = self.request.GET.get('next', "")

        return context

class AddUserBase(generic.CreateView):
    '''this creates both a local user instance and a keycloak instance (if it doesn't already exist)
    To use, inherit this class and ensure correct permissions are set in the child class
    Define success url that may pass on to a send message to user - this only creates the user
    '''

    template_name = 'users/organiser/add_user.html'

    def get_form_class(self):
        if not hasattr(self, 'form_class') or self.form_class is None:
            raise NotImplementedError("Define `form_class` in the child class.")
        return self.form_class

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['message'] = self.get_message_template()
        return context

    # def get_message_template(self):
    #
    #     return '''Dear {user.first_name},\n\nYou have been signed up with Skor.ie by {me.name}.  Your temporary password is {form.cleaned_data['password']}.  Please log in and change your password as soon as possible. \nIf this is a mistake please ignore this email and the account will be deleted after 1 week.\n\nBest wishes,\nSkor.ie'''

    def create_keycloak_user(self, data, user):
        '''at the moment we are creating the keycloak user then the django user to make it easier to
        ensure the django user points to the keycloak user.  In future we might want to think about creating just
        the django user at this point and then creating the keycloak user when the user signs in'''
        payload = {
            "email": data['email'],
            "username": data['email'],
            "firstName": data['first_name'],
            "lastName": data['last_name'],
            "enabled": True,
            "credentials": [{
                "type": "password",
                "value": data['password'].replace(" ", ""),  # remove spaces
                "temporary": True
            }],
            "requiredActions": [],

        }

        keycloak_id, status_code = create_keycloak_user(payload, user)

        print(status_code)

        return keycloak_id


    def form_valid(self, form):
        '''create the keycloak user first then the local user'''

        me = self.request.user
        keycloak_id = self.create_keycloak_user(form.cleaned_data, me)


        if keycloak_id:
            # now create the django instance
            user = form.save(commit=False)
            user.keycloak_id = keycloak_id
            user.attributes = {'temporary_password': form.cleaned_data['password']}   # lets use activation code (or verification code) to store the temporary password
            user.activation_code = form.cleaned_data['password']
            user.creator = me
            if not user.username:
                user.username = user.email
            user.save()


        return super().form_valid(form)



class ManageUserProfileBase(LoginRequiredMixin, generic.CreateView):
    # form_class = CustomUserCreationForm
    template_name = 'organiser/users/manage_user_profile.html'

    def get_form_class(self):
        if not hasattr(self, 'form_class') or self.form_class is None:
            raise NotImplementedError("Define `form_class` in the child class.")
        return self.form_class

    def form_valid(self, form):
        # This method is called when valid form data has been POSTed.
        # It should return an HttpResponse.
        user = form.save()  # Save the user and get the instance

        # Custom post-save logic here
        # e.g., sending a confirmation email

        return super().form_valid(form)


class SubscribeView(LoginRequiredMixin, FormView):
    template_name = "subscribe.html"
    form_class = SubscribeForm
    success_url = '/'

    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

    def form_valid(self, form):
        UserContact = apps.get_model('users.UserContact')

        # only available for signed in user
        user = self.request.user

        # extra fields
        user.country = form.cleaned_data['country']
        # user.mobile = form.cleaned_data['mobile']
        # user.whatsapp = form.cleaned_data['whatsapp']
        # user.city = form.cleaned_data['city']
        user.save()

        # this will set status to at least Confirmed
        user.update_subscribed(form.cleaned_data['subscribe'])

        # add contact note
        notify = settings.NOTIFY_NEW_USER_EMAILS > ""
        UserContact.add(user=user, method="Subscribe & Interest Form", notes=json.dumps(form.cleaned_data),
                        data=form.cleaned_data, send_mail=notify)

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


# user = User.objects.create_user(username=userid, email=user_details['email'],
#                                 first_name=user_details['firstName'], last_name=user_details['lastName'])


def logout(request):
    nextpage = get_legitimate_redirect(request)

    if len(settings.AUTHENTICATION_BACKENDS) > 1:
        return HttpResponseRedirect(f"/keycloak/logout?next={nextpage}")

    else:
        log_out(request)
        return HttpResponseRedirect(nextpage)

    # return_to = urlencode({'returnTo': request.build_absolute_uri('/')})
    # return HttpResponseRedirect("/keycloak/logout")
    # return HttpResponseRedirect(logout_url)


def login_redirect(request):

    url = reverse(settings.LOGIN_URL)
    if 'next' in request.GET.urlencode():
        url += "?{request.GET.urlencode()}"
    elif request.GET.urlencode():
        url += "?next={request.GET.urlencode()}"
    return HttpResponseRedirect(url)


def signup_redirect(request):
    url = reverse(settings.LOGIN_REGISTER)
    if 'next' in request.GET.urlencode():
        url += "?{request.GET.urlencode()}"
    elif request.GET.urlencode():
        url += "?next={request.GET.urlencode()}"
    return HttpResponseRedirect(url)



def after_login_redirect(request):
    # using skor.ie emails as temporary emails so don't want subscirbe form displayed
    User = get_user_model()
    if request.user.status < User.USER_STATUS_CONFIRMED and not "@skor.ie" in request.user.email:
        url = reverse("subscribe_only")
    else:
        url = "/"

    return HttpResponseRedirect(url)


@method_decorator(never_cache, name='dispatch')
class UserProfileViewBase(LoginRequiredMixin, GoNextMixin, FormView):
    # form_class = ProfileForm
    # model = CustomUser

    def get_form_class(self):
        if not hasattr(self, 'form_class') or self.form_class is None:
            raise NotImplementedError("Define `form_class` in the child class.")
        return self.form_class

    def get_template_names(self):

        return "users/change_profile.html"

    def get_object(self, queryset=None):
        # can only see your own profile

        return self.request.user

    def get_initial(self):
        initial = super().get_initial()
        user = self.request.user
        if user.is_authenticated:
            initial['country'] = user.country
            initial['county'] = user.profile['county'] if 'county' in user.profile else ''
            initial['level'] = user.profile['level'] if 'level' in user.profile else ''
            initial['where_did_you_hear'] = user.profile[
                'where_did_you_hear'] if 'where_did_you_hear' in user.profile else ''

        return initial

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['USE_SUBSCRIBE'] = settings.USE_SUBSCRIBE
        context['now'] = timezone.now()
        context['roles'] = self.request.user.user_roles(descriptions=True)

        return context

    def post(self, request, *args, **kwargs):

        form = self.get_form()
        if form.is_valid():
            user = request.user
            # user.country = form.cleaned_data['country']
            user.profile['county'] = form.cleaned_data['county']
            user.profile['level'] = form.cleaned_data['level']

            user.save()

            return HttpResponseRedirect(self.get_success_url())
        else:
            return self.form_invalid(form)


@method_decorator(never_cache, name='dispatch')
class Troubleshoot(UserCanAdministerMixin, View):
    '''given an email, see what the problem is'''

    def post(self, request, *args, **kwargs):
        email = request.POST.get('email')
        CustomUser = get_user_model()
        try:
            django_user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            django_user = None

        if django_user:
            if django_user.is_active:
                # redirect to profile as they are fully activated
                return HttpResponseRedirect(reverse('users:manage-user-profile') + f"?email={email}")

        # still not verified
        return HttpResponseRedirect(reverse('users:problem_register') + f"?email={email}")


@method_decorator(never_cache, name='dispatch')
class ProblemSignup(TemplateView):
    template_name = "users/problem_signup.html"
    verified = False

    def get_template_names(self):
        if self.request.user.is_authenticated and self.request.user.is_administrator:
            return "users/problem_signup_admin.html"
        else:
            return "users/problem_signup.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        set_current_user(self.request, None, None)

        context['next'] = get_legitimate_redirect(self.request)
        context['email'] = kwargs['email'] if 'email' in kwargs else self.request.GET.get('email', '')
        return context


@method_decorator(never_cache, name='dispatch')
class ProblemLogin(ProblemSignup):
    template_name = "users/problem_login.html"

    def dispatch(self, request, *args, **kwargs):

        email = request.GET.get('email', None)
        if email:
            User = get_user_model()
            try:
                django_user = User.objects.get(email=email)
            except User.DoesNotExist:
                pass
            else:
                self.verified = django_user.is_verified

        else:
            # no email passed so continue
            return super().dispatch(request, *args, **kwargs)

        if not self.verified:
            return HttpResponseRedirect(reverse('users:problem_register') + f"?email={email}")

        return super().dispatch(request, *args, **kwargs)

    def get_template_names(self):
        if self.request.user.is_authenticated and self.request.user.is_administrator:
            return "users/users/problem_login_admin.html"
        else:
            return "users/problem_login.html"


@method_decorator(never_cache, name='dispatch')
class NewUsers(UserCanAdministerMixin, TemplateView):
    template_name = "admin/new_users.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        User = get_user_model()
        users = User.objects.filter(date_joined__gte=timezone.now() - timedelta(days=7))
        # calclogs = []
        # for user in users:
        #     logs = []
        #     for item in CalcLog.objects.filter(user=user):
        #         logs.append(f"- {item.testsheet} {item.percentage}  {item.created}")
        #     calclogs.append(logs)
        #
        # context['users'] = zip(users, calclogs)
        return context


def get_keycloak_signup_url(email):
    """Construct the Keycloak signup URL with the email pre-filled."""
    base_url = f"{settings.KEYCLOAK_CLIENTS['DEFAULT']['URL']}/realms/{settings.KEYCLOAK_CLIENTS['DEFAULT']['REALM']}/protocol/openid-connect/auth"
    params = {
        'client_id': settings.KEYCLOAK_CLIENTS['DEFAULT']['CLIENT_ID'],
        'response_type': 'code',
        'scope': 'email',
        'redirect_uri': f"{settings.SITE_URL}/keycloak/login-complete/",
        'login_hint': email,
        'action': 'register'
    }
    signup_url = f"{base_url}?{urlencode(params)}"
    return signup_url


@method_decorator(never_cache, name='dispatch')
class UserMigrationView(View):
    http_method_names = ['post', ]

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
        User = get_user_model()
        email = request.POST.get('email')
        password = request.POST.get('password')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
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
            login(request, authenticated_user,
                  backend='django_keycloak_admin.backends.KeycloakPasswordCredentialsBackend')
            messages.success(request, "You have been successfully logged in.")
            return redirect(settings.LOGIN_REDIRECT_URL)
        else:
            messages.error(self.request, "Authentication failed. Please check your credentials.")
            return redirect("/")


def send_sms(recipient_user, message, user=None):
    # Twilio credentials (replace with your actual credentials)
    from twilio.rest import Client
    client = Client(settings.TWILIO_ACCOUNT_ID, settings.TWILIO_AUTH_TOKEN)
    message = client.messages.create(
        body=message,
        from_=settings.TWILIO_PHONE_NUMBER,  # Replace with your Twilio number
        to=recipient_user.mobile
    )

    return message.sid


@method_decorator(never_cache, name='dispatch')
class LoginView(GoNextTemplateMixin, TemplateView):
    template = "users/login.html"

    def get(self, request):
        # TODO: check user is not already logged in
        context = super().get_context_data()
        return render(request, self.template, context)

    def post(self, request):
        # NOTE THAT TEMPORARY PASSWORDS IN KEYCLOAK WILL NOT AUTHENTICATE HERE
        # HAVE TO REMOVE ALL REQUIRED ACTIONS FIRST
        email = request.POST.get('email')
        password = request.POST.get('password')
        next = request.GET.get('next', request.POST.get('next', None))

        try:
            user = authenticate(request, username=email, password=password)
        except Exception as e:
            # get required actions

            messages.error(request, _('Invalid email or password.'))
            return render(request, self.template, {'email': email})
        else:
            if user:

                if is_temporary_password(user):
                    messages.warning(request, _('Your password is temporary. Please change your password.'))
                    return redirect('users:change_password_now')
                else:
                    login(request, user)
                    if next:
                        return redirect(next)
                    else:
                        return redirect(settings.LOGIN_REDIRECT_URL)
            else:
                messages.error(request, _('Invalid email or password.'))
                context = super().get_context_data()
                context['email'] = email
                return render(request, self.template, context)


@method_decorator(never_cache, name='dispatch')
class RegisterViewBase(FormView):
    # form_class = SignUpForm
    template_name = "users/register.html"
    user = None

    def get_form_class(self):
        if not hasattr(self, 'form_class') or self.form_class is None:
            raise NotImplementedError("Define `form_class` in the child class.")
        return self.form_class

    def get_success_url(self):
        return reverse('users:verify_channel', kwargs={'channel_id': self.user.preferred_channel_id})


    # @transaction.atomic
    def form_valid(self, form):
        preferred_channel = form.cleaned_data['preferred_channel']
        email = form.cleaned_data['email']
        mobile = form.cleaned_data.get('mobile')
        password = form.cleaned_data['password']


        User = get_user_model()
        #this code cannot find username=email but when you try to create it, it says can't create duplicate and you see it already there.
        # save not being triggered
        try:
            # print(f"Trying to get user with email {email}")
            user = User.objects.get(username=email)
        except User.DoesNotExist:
            try:
                # print(f"Creating user with email {email}")
                user = User.objects.create_user(
                    username=email,
                    email=email,
                    first_name=form.cleaned_data['first_name'],
                    last_name=form.cleaned_data['last_name'],
                    is_active=False
            )
            except User.DoesNotExist:
                # if there is old data where email != username then will get duplicate error here
                messages.error(self.request, _(f'Failed to create user account - duplicate email {email}. Please try again later.'))
                return HttpResponseRedirect(reverse(LOGIN_REGISTER))
            except Exception as e:
                messages.error(self.request, _(f'Failed to create user account with error {e}. Please try again later.'))
                raise
        else:
            if not user.is_active and USE_KEYCLOAK and user.keycloak_id:
                keycloak_details = get_user_by_id(user.keycloak_id)
                if keycloak_details['emailVerified']:
                    messages.warning(self.request,
                                     _('An account with this email already exists on Skorie. Please log in with the original password.'))
                    return HttpResponseRedirect(reverse(LOGIN_REGISTER) + f"?email={email}")
                else:
                    # as they never finished setting up the user, let's update the password so they can continue
                    update_password(user.keycloak_id, password)
                    logger.warning(f"User {user.email} is registering again. Account in keycloak is not verified.")
            elif user.is_active:
                messages.warning(self.request,
                                 _('An account with this email already exists. Please log in with the original password.'))
                return HttpResponseRedirect(reverse(LOGIN_REGISTER) + f"?email={email}")

        set_current_user(self.request, user.id, "REGISTER")

        if USE_KEYCLOAK and not user.keycloak_id:
            status_code = user.create_keycloak_user_from_user(password)
            if status_code == 409:
                messages.error(self.request, _('You already have an account.'))
                return HttpResponseRedirect(reverse(LOGIN_REGISTER))
            elif status_code != 201:
                messages.error(self.request, _('Failed to create user account. Please try again later.'))
                return HttpResponseRedirect(reverse(LOGIN_REGISTER))

        self.create_comms_channels(CHANNEL_EMAIL, email, user)
        if mobile:
            self.create_comms_channels(preferred_channel, mobile, user)

        user.preferred_channel = self.create_comms_channels(preferred_channel, mobile or email, user)
        user.save(update_fields=['preferred_channel'])

        #TODO: could try signing in - at least put email in login form
        self.user = user
        return HttpResponseRedirect(self.get_success_url())

    def create_comms_channels(self, channel_type, value, user):
        CommsChannel = apps.get_model('users.CommsChannel')
        channel, created = CommsChannel.objects.get_or_create(
                    user=user,
                    channel_type=channel_type,
            value=value)

        return channel


@method_decorator(never_cache, name='dispatch')
class AddCommsChannelViewBase(View):
    '''this can be called after the user has logged in or before.  If before then there needs to be some throttling'''

    def get_form_class(self):
        if not hasattr(self, 'form_class') or self.form_class is None:
            raise NotImplementedError("Define `form_class` in the child class.")
        return self.form_class

    def get(self, request):
        # set form.keycloak_id to user.keycloak_id

        user, user_login_mode = get_current_user(request)

        form = self.get_form_class()
        form.fields['username_code'].initial = user.password

        return render(request, 'users/add_channel.html', {'form': form})


def set_current_user(request, user_id=None, user_login_mode=None):
    '''call with no parameters to clear'''

    if not user_id:
        request.session.pop('user_id', None)
        request.session.pop('user_login_mode', None)

        request.session.pop('forgot_channel', None)
        request.session.pop('forgot_email', None)
        request.session.pop('forgot_password_step', None)
        request.session.pop('verification_code', None)

    else:
        request.session['user_id'] = user_id
        request.session['user_login_mode'] = user_login_mode


def get_current_user(request):
    user = None
    user_login_mode = None

    if request.user.is_authenticated:
        user = request.user
        user_login_mode = "LOGGEDIN"
    else:
        user_id = request.session.get('user_id', None)
        user_login_mode = request.session.get('user_login_mode', None)

        User = get_user_model()
        if user_id and user_login_mode in ["REGISTER", "PROBLEM"]:
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                messages.error(request, _('Failed to locate user account. Please try again with a different email.'))

    return user, user_login_mode


@method_decorator(never_cache, name='dispatch')
class VerifyChannelViewBase(View):

    def get_form_class(self):
        if not hasattr(self, 'form_class') or self.form_class is None:
            raise NotImplementedError("Define `form_class` in the child class.")
        return self.form_class

    def get(self, request, channel_id):
        user, user_login_mode = get_current_user(request)
        CommsChannel = apps.get_model('users.CommsChannel')
        channel = get_object_or_404(CommsChannel, id=channel_id)

        VerificationCode = apps.get_model('users.VerificationCode')
        vc = VerificationCode.create_verification_code(user, channel)
        success = vc.send_verification_code()

        if not success:
            messages.error(request, _('Failed to send verification code. Check your contact method is correct.'))
            return HttpResponseRedirect('users:login')

        form_class = self.get_form_class()
        form = form_class(initial={'channel': channel})

        next = request.GET.get('next', reverse('users:login'))

        context = {'form': form, 'channel': channel}
        if request.user.is_authenticated and request.user.is_administrator:
            context['verification_code'] = vc.code

        return render(request, 'users/verify_channel.html', context)

    def post(self, request, channel_id):
        CommsChannel = apps.get_model('users.CommsChannel')
        VerificationCode = apps.get_model('users.VerificationCode')
        channel = get_object_or_404(CommsChannel, id=channel_id)
        code = request.POST.get('code', None)

        if code:
            success = VerificationCode.verify_code(code, channel)
            if success:
                messages.success(request, _('Contact method has been verified.'))
                url = f"{reverse('users:login')}?" + urlencode({'email': channel.user.email})
                return redirect(url)

        messages.error(request, _('Invalid or expired verification code.'))
        return render(request, 'users/verify_channel.html', {'channel': channel})


@method_decorator(never_cache, name='dispatch')
class ManageCommsChannelsView(View):
    def get(self, request):
        channels = request.user.comms_channels.all()
        return render(request, 'users/manage_channels.html', {'channels': channels})

    def post(self, request):
        # Handle deletion or re-verification if needed
        pass


@method_decorator(never_cache, name='dispatch')
class ChangePasswordNowViewBase(GoNextTemplateMixin, FormView):
    template_name = "users/change_password.html"
    form_class = ChangePasswordNowCurrentForm
    success_url = reverse_lazy("profile")

    def get_form_class(self):
        if not hasattr(self, 'form_class') or self.form_class is None:
            raise NotImplementedError("Define `form_class` in the child class.")
        return self.form_class

    def form_valid(self, form):

        new_password = form.cleaned_data.get("new_password")
        user_id = self.request.user.keycloak_id  # Assume user has a keycloak_id field

        # Update the password in Keycloak
        try:
            update_password(user_id, new_password)
            messages.success(self.request, "Password updated successfully.")
            return super().form_valid(form)
        except Exception as e:
            form.add_error(None, f"Failed to update password: {e}")
            return self.form_invalid(form)


@method_decorator(never_cache, name='dispatch')
class ForgotPassword(CheckLoginRedirectMixin, FormView):
    # TODO: instead of putting vc code into session, put the pk of the record and check properly
    # Recheck vc on last step before changing password - could bypass step 3?
    template_name = "users/forgot_password.html"
    form_class = ForgotPasswordForm
    success_url = reverse_lazy("users:change_password")
    user = None
    channel = None

    def dispatch(self, request, *args, **kwargs):
        # Ensure user is redirected if already logged in
        if request.user.is_authenticated:
            return redirect(self.success_url)
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        step = self.get_step()
        kwargs['step'] = step  # Pass the current step to the form

        # Retrieve session values and set them as initial values in the form
        if step == 1:
            email = self.request.GET.get('email', None)
            if email:
                kwargs['initial'] = {
                    'email': email,
                }
        elif step > 1:
            email = self.request.session.get('forgot_email')
            User = get_user_model()
            self.user = User.objects.filter(username=email).first()
            if self.user:
                kwargs['user'] = self.user  # Pass the user to populate channels in step 2

            kwargs['initial'] = {
                'email': email,
            }
        if step > 2:
            kwargs['initial']['channel'] = self.request.session.get('forgot_channel')

        return kwargs

    def get_step(self):
        # Determine current step based on session
        return self.request.session.get('forgot_password_step', 1)

    def set_step(self, step):
        # Set the current step in session
        self.request.session['forgot_password_step'] = step

    def get(self, request, *args, **kwargs):
        # Reset the process if the user starts over
        self.request.session.pop('forgot_password_step', None)
        self.request.session.pop('forgot_email', None)
        self.request.session.pop('verification_code', None)
        return super().get(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['step'] = self.get_step()  # Add the current step to the context
        context['user'] = self.user
        context['channel'] = self.channel
        context['verification_code'] = self.request.session.get('verification_code')
        return context

    def form_valid(self, form):
        step = self.get_step()
        email = form.cleaned_data['email']
        User = get_user_model()
        user = User.objects.filter(username=email).first()

        if step == 1:
            # Step 1: Check if email exists and save it in session
            email = form.cleaned_data['email']

            if user and not user.is_active:
                form.add_error('email', _(f'This email does not have an account. Please {settings.REGISTER_TERM}.'))
                return self.form_invalid(form)
            elif user:
                self.request.session['forgot_email'] = email
                self.set_step(2)  # Move to Step 2
            else:
                form.add_error('email', _('Email not found.'))
                return self.form_invalid(form)

        elif step == 2:
            # Step 2: Send a verification code to selected channel
            channel_id = form.cleaned_data['channel']
            CommsChannel = apps.get_model('users', 'CommsChannel')
            VerificationCode = apps.get_model('users', 'VerificationCode')

            # going to allow unverified channels
            try:
                channel = CommsChannel.objects.get(id=channel_id)
            except Exception as e:
                logger.warning(f"Channel {channel_id} not found: {e}")
                form.add_error('channel', _('Invalid or unverified channel selected.'))
            else:
                self.channel = channel
                self.request.session['forgot_channel'] = channel_id
                vc = VerificationCode.create_verification_code(user, channel)
                vc.send_verification_code()
                self.request.session['verification_code'] = vc.code
                self.set_step(3)  # Move to Step 3


            # channel = CommsChannel.objects.filter(id=channel_id, verified_at__isnull=False).first()
            # if channel:
            #     self.channel = channel
            #     self.request.session['forgot_channel'] = channel_id  # Store channel in session
            #     vc = VerificationCode.create_verification_code(channel)
            #     vc.send_verification_code()
            #     self.request.session['verification_code'] = vc.code
            #     self.set_step(3)  # Move to Step 3
            # else:
            #     form.add_error('channel', _('Invalid or unverified channel selected.'))
            #     return self.form_invalid(form)

        elif step == 3:
            # Step 3: Verify the code
            input_code = form.cleaned_data['verification_code']
            if input_code == self.request.session.get('verification_code'):
                self.set_step(4)  # Move to Step 4
            else:
                form.add_error('verification_code', _('Invalid verification code.'))
                return self.form_invalid(form)

        elif step == 4:
            # Step 4: Set the new password
            new_password = form.cleaned_data['new_password']
            confirm_password = form.cleaned_data['confirm_password']
            if new_password == confirm_password:
                email = self.request.session.get('forgot_email')

                if user:
                    if not user.keycloak_id:
                        logger.error(f"User {user.pk} does not have a keycloak_id.")
                        form.add_error('confirm_password',
                                       _('There is an issue with your account.  The administrator has been notified.'))
                        return self.form_invalid(form)
                    success = update_password(user.keycloak_id, new_password)
                    #TODO: if channel was not verified set it to verified now
                    if success:
                        messages.success(self.request, _('Your password has been reset successfully.'))
                        # Clear session data after success
                        self.request.session.pop('forgot_email', None)
                        self.request.session.pop('forgot_channel', None)
                        self.request.session.pop('verification_code', None)
                        return redirect('users:login')
                    else:
                        form.add_error('confirm_password',
                                       _('Unable to reset password.  Please try a different password.'))
                        return self.form_invalid(form)

            else:
                form.add_error('confirm_password', _('Passwords do not match.'))
                return self.form_invalid(form)

        newform = self.get_form()
        # Redirect back to form to display the next step
        return self.render_to_response(self.get_context_data(form=newform))


@method_decorator(never_cache, name='dispatch')
class ChangePasswordView(GoNextTemplateMixin, FormView):
    template_name = "users/change_password.html"
    form_class = ChangePasswordForm
    success_url = reverse_lazy("users:user-profile")

    def form_valid(self, form):
        current_password = form.cleaned_data.get("current_password")
        new_password = form.cleaned_data.get("new_password")
        user, user_login_mode = get_current_user(self.request)

        if not verify_login(self.request.user.email, current_password):
            form.add_error('current_password', "Current password is incorrect.")
            return self.form_invalid(form)

        # Update the password in Keycloak
        try:
            update_password(user.keycloak_id, new_password)
            messages.success(self.request, "Password updated successfully.")
            return super().form_valid(form)
        except Exception as e:
            form.add_error(None, f"Failed to update password: {e}")
            return self.form_invalid(form)


def update_users(request):
    # temporary function to update all users with keycloak_id - comment out once used
    User = get_user_model()
    for user in User.objects.filter(keycloak_id__isnull=True):
        try:
            user.keycloak_id = keycloak_admin.get_user_id(user.email)
        except Exception as e:
            print(e)
        else:
            user.save(update_fields=['keycloak_id', ])


class UnverifiedUsersList(UserCanAdministerMixin, ListView):
    model = UserEntity
    template_name = 'users/unverified_users_report.html'
    context_object_name = 'users'  # Name to use in the template

    def get_queryset(self):
        # Calculate one month ago as a timestamp in milliseconds
        one_month_ago = datetime.now() - timedelta(days=30)
        one_month_ago_timestamp = int(one_month_ago.timestamp() * 1000)
        # Query unverified users from the last month
        return UserEntity.objects.using('keycloak_new').filter(
            email_verified=False,
            created_timestamp__gte=one_month_ago_timestamp
        ).order_by('-created_timestamp')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = 'Unverified Users (Last Month)'
        return context

class SendOpt(UserCanAdministerMixin, View):
    def post(self, request):
        User = get_user_model()
        user = User.objects.get(id=request.POST.get('user_id'))
        user.send_verification_code()
        return HttpResponseRedirect(reverse('users:unverified-users'))
