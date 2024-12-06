import json
import logging
import random
import string
from datetime import datetime, timedelta
from urllib.parse import urlencode

from django.db import transaction
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache


from twilio.rest import Client

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

from post_office import mail
from django.contrib.auth import (authenticate, get_user_model, login, logout as log_out,
                                 update_session_auth_hash)
from requests import Response


from tools.mixins import GoNextMixin, GoNextTemplateMixin, CheckLoginRedirectMixin
from .permission_mixins import UserCanAdministerMixin


from .forms import SubscribeForm, ProfileForm,  SignUpForm, CommsChannelForm, VerificationCodeForm, \
    ChangePasswordForm, AddCommsChannelForm, ChangePasswordNowCurrentForm, ForgotPasswordForm, CustomUserCreationForm

from .models import UserContact, VerificationCode, CommsChannel, ModelRoles, Role

logger = logging.getLogger('django')


User = get_user_model()




NOW = timezone.now()
LASTWEEK = NOW - timedelta(days=7)
LASTMONTH = NOW - timedelta(days=31)
YESTERDAY = NOW - timedelta(days=1)


def is_superuser(user):
    return user.is_superuser
def is_organiser(user):
    return user.is_manager
def is_admin(user):
    return user.is_administrator


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
    template_name = 'organiser/add_user.html'

    def form_valid(self, form):
        '''create the keycloak user first then the local user'''
        me = self.request.user

        # now create the django instance
        user = form.save(commit=False)
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

class ManagerUserProfile(LoginRequiredMixin, generic.CreateView):
    form_class = CustomUserCreationForm
    template_name = 'organiser/users/manage_user_profile.html'


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




# user = User.objects.create_user(username=userid, email=user_details['email'],
#                                 first_name=user_details['firstName'], last_name=user_details['lastName'])



def signup_redirect(request):

    next = request.GET.urlencode()

    url = f"/account/login/"

    if 'next' in request.GET.urlencode():
        url += "?{request.GET.urlencode()}"
    elif request.GET.urlencode():
        url += "?next={request.GET.urlencode()}"

    return HttpResponseRedirect(url)



def after_login_redirect(request):
    # using skor.ie emails as temporary emails so don't want subscirbe form displayed
    if request.user.status < User.USER_STATUS_CONFIRMED and not "@skor.ie" in request.user.email:
        url = reverse("subscribe_only")
    else:
        url = "/"

    return HttpResponseRedirect(url)

@method_decorator(never_cache, name='dispatch')
class UserProfileView(LoginRequiredMixin, GoNextMixin, FormView):
    form_class = ProfileForm
    model = User

    def get_template_names(self):

        return  "users/change_profile.html"

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
            initial['where_did_you_hear'] = user.profile['where_did_you_hear'] if 'where_did_you_hear' in user.profile else ''

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

        try:
            django_user = User.objects.get(email=email)
        except User.DoesNotExist:
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

        user = User.objects.get(email=email)

        return False

    def post(self, request, *args, **kwargs):

        email = request.POST.get('email')
        password = request.POST.get('password')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # check if user has signup in new keycloak and is so proceed with login first time
            # Need to redirect to register page - email already filled in
            user = None
        else:
          pass
def send_sms(recipient_user, message, user=None):
    # Twilio credentials (replace with your actual credentials)

    client = Client(settings.TWILIO_ACCOUNT_ID, settings.TWILIO_AUTH_TOKEN)
    message = client.messages.create(
        body=message,
        from_=settings.TWILIO_PHONE_NUMBER,  # Replace with your Twilio number
        to=recipient_user.mobile
    )

    return message.sid


@method_decorator(never_cache, name='dispatch')
class LoginView(TemplateView):
    template = "users/login.html"

    def get(self, request):
        #TODO: check user is not already logged in
        return render(request, self.template)

    def post(self, request):
        # NOTE THAT TEMPORARY PASSWORDS IN KEYCLOAK WILL NOT AUTHENTICATE HERE
        # HAVE TO REMOVE ALL REQUIRED ACTIONS FIRST
        email = request.POST.get('email')
        password = request.POST.get('password')
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
                    return redirect(settings.LOGIN_REDIRECT_URL)
            else:
                messages.error(request, _('Invalid email or password.'))
                return render(request, self.template, {'email': email})

@method_decorator(never_cache, name='dispatch')
class RegisterView(FormView):
    form_class = SignUpForm
    template_name = "users/register.html"
    user = None

    def success_url(self):
        return reverse('users:verify_channel', kwargs={'channel_id': self.user.preferred_channel_id})


    def form_valid(self, form):

            channel_type = form.cleaned_data['channel_type']
            email = form.cleaned_data['email']
            mobile = form.cleaned_data['mobile']
            password = form.cleaned_data['password']

            #TODO: move to using users.add_or_update_user
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                user = User.objects.create(username=email, email=email, first_name=form.cleaned_data['first_name'], last_name=form.cleaned_data['last_name'], is_active=False)
                self.user = user
            else:
                # we already have this user
                self.user = user
                if not user.is_active:
                                    # if user picked mobile, then need to add this channel and verify it
                    if mobile:
                            channel = self.create_comms_channels(channel_type, mobile, user)
                            user.preferred_channel = channel
                    else:
                        channel = self.create_comms_channels('email', email, user)
                        if channel_type == CommsChannel.CHANNEL_EMAIL:
                            user.preferred_channel = channel

                    user.quick_save(update_fields=['preferred_channel'])

                    return HttpResponseRedirect(reverse('users:verify_channel', kwargs={'channel_id': channel.id}))
                elif user.is_active:
                    messages.warning(self.request, _('An account with this email already exists. Please log in with the original password.'))
                    # could try signing in - at least put email in login form
                    return HttpResponseRedirect(reverse('users:login') + f"?email={email}")

            # put current user in session so we can verify them
            set_current_user(self.request, user.id, "REGISTER")



            # Create communication channels - defaults to email
            channel = self.create_comms_channels('email', email, user)
            if  channel_type == CommsChannel.CHANNEL_EMAIL:
                user.preferred_channel = channel


            # Create SMS/WhatsApp channel if phone number is provided
            if mobile:
                channel = self.create_comms_channels(channel_type, mobile, user)
                user.preferred_channel = channel


            user.quick_save(update_fields=['preferred_channel'])

            return HttpResponseRedirect(self.success_url())


    def create_comms_channels(self, channel_type, value, user):

        if channel_type != 'email':
            try:
                channel = CommsChannel.objects.get(user=user, channel_type=channel_type, mobile=value)
            except CommsChannel.DoesNotExist:
                channel = CommsChannel.objects.create(
                    user=user,
                    channel_type=channel_type,
                    mobile=value
                )
        else:
            try:
                channel = CommsChannel.objects.get(user=user, channel_type=channel_type, email=value)
            except CommsChannel.DoesNotExist:
                channel = CommsChannel.objects.create(
                    user=user,
                    channel_type=channel_type,
                    email=value
                )

        return channel


@method_decorator(never_cache, name='dispatch')
class AddCommsChannelView(View):
    '''this can be called after the user has logged in or before.  If before then there needs to be some throttling'''
    def get(self, request):

        # set form.keycloak_id to user.keycloak_id

        user, user_login_mode = get_current_user(request)

        form = AddCommsChannelForm()
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
            user_id = request.session.get('user_id',None)
            user_login_mode = request.session.get('user_login_mode', None)


            if user_id and user_login_mode in ["REGISTER", "PROBLEM"]:
                try:
                    user = User.objects.get(id=user_id)
                except User.DoesNotExist:
                    messages.error(request, _('Failed to locate user account. Please try again with a different email.'))



    return user, user_login_mode

@method_decorator(never_cache, name='dispatch')
class VerifyChannelView(View):

    def get(self, request, channel_id):
        user, user_login_mode = get_current_user(request)

        channel = get_object_or_404(CommsChannel, id=channel_id)

        vc = VerificationCode.create_verification_code(channel)
        success = vc.send_verification_code()

        if not success:

            messages.error(request, _('Failed to send verification code. Check your contact method is correct.'))
            return HttpResponseRedirect('users:login')

        form = VerificationCodeForm(initial={'channel': channel})
        next = request.GET.get('next', reverse('users:login'))

        context = {'form': form, 'channel': channel}
        if request.user.is_authenticated and request.user.is_administrator:
            context['verification_code'] = vc.code

        return render(request, 'users/verify_channel.html', context)

    def post(self, request, channel_id):
        channel = get_object_or_404(CommsChannel, id=channel_id)
        code = request.POST.get('code',None)

        if code:
            success = VerificationCode.verify_code(code, channel)
            if success:
                messages.success(request, _('Contact method has been verified.'))
                url = f"{reverse('users:login')}?"+urlencode({'email': channel.user.email})
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
class ChangePasswordNowView(GoNextTemplateMixin ,FormView):
    template_name = "users/change_password.html"
    form_class = ChangePasswordNowCurrentForm
    success_url = reverse_lazy("profile")


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
    #TODO: instead of putting vc code into session, put the pk of the record and check properly
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
        if step > 1:
            email = self.request.session.get('forgot_email')
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

        if step == 1:
            # Step 1: Check if email exists and save it in session
            email = form.cleaned_data['email']
            user = User.objects.filter(username=email).first()
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
            channel = CommsChannel.objects.filter(id=channel_id, verified_at__isnull=False).first()
            if channel:
                self.channel = channel
                self.request.session['forgot_channel'] = channel_id  # Store channel in session
                vc = VerificationCode.create_verification_code(channel)
                vc.send_verification_code()
                self.request.session['verification_code'] = vc.code
                self.set_step(3)  # Move to Step 3
            else:
                form.add_error('channel', _('Invalid or unverified channel selected.'))
                return self.form_invalid(form)

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
                user = User.objects.filter(username=email).first()
                if user:
                    if not user.keycloak_id:
                        logger.error(f"User {user.pk} does not have a keycloak_id.")
                        form.add_error('confirm_password', _('There is an issue with your account.  The administrator has been notified.'))
                        return self.form_invalid(form)
                    success = update_password(user.keycloak_id, new_password)
                    if success:
                        messages.success(self.request, _('Your password has been reset successfully.'))
                        # Clear session data after success
                        self.request.session.pop('forgot_email', None)
                        self.request.session.pop('forgot_channel', None)
                        self.request.session.pop('verification_code', None)
                        return redirect('users:login')
                    else:
                        form.add_error('confirm_password', _('Unable to reset password.  Please try a different password.'))
                        return self.form_invalid(form)

            else:
                form.add_error('confirm_password', _('Passwords do not match.'))
                return self.form_invalid(form)

        newform = self.get_form()
        # Redirect back to form to display the next step
        return self.render_to_response(self.get_context_data(form=newform))



@method_decorator(never_cache, name='dispatch')
class ChangePasswordView(GoNextTemplateMixin ,FormView):
    template_name = "users/change_password.html"
    form_class = ChangePasswordForm
    success_url = reverse_lazy("profile")


    def form_valid(self, form):
        current_password = form.cleaned_data.get("current_password")
        new_password = form.cleaned_data.get("new_password")
        user = get_current_user(self.request)

        if not verify_login(self.request.user.email, current_password):

            form.add_error('current_password', "Current password is incorrect.")
            return self.form_invalid(form)

        # Update the password in Keycloak
        try:
            update_password(user.id, new_password)
            messages.success(self.request, "Password updated successfully.")
            return super().form_valid(form)
        except Exception as e:
            form.add_error(None, f"Failed to update password: {e}")
            return self.form_invalid(form)


@user_passes_test(is_admin)
def subscribers_list(request):

    users = User.objects.filter(subscribe_news__isnull=False).exclude(unsubscribe_news__isnull=False).values_list('email', flat=True).order_by('-subscribe_news')
    emails = ','.join(users)
    return HttpResponse(emails)

@user_passes_test(is_superuser)
def tidy_contacts(request):
    for user in User.objects.filter(last_login__isnull=True, subscribe_news__isnull=True):
        print(f"Deleting {user}")
        person = user.person
        if person:
            with transaction.atomic():
                user.person = None
                user.save()
                print("removed link to person")
            with transaction.atomic():
                person.delete()
                print("deleted person")


            for item in UserContact.objects.filter(user=user):
                with transaction.atomic():
                    item.delete()
                    print("deleted user contact")

        with transaction.atomic():
            user.is_active=False
            user.save()
            print("set user to inactive deleted user")


class ManageRoles(UserCanAdministerMixin, TemplateView):
    #NOTE: getting stack overflow error when toggling roles in pycharm - not tested in production
    template_name = "admin/manage_roles.html"

    def get_context_data(self, *args, **kwargs):
        context = super().get_context_data(**kwargs)


        context['roles'] = {key: value+" - "+ModelRoles.ROLE_DESCRIPTIONS[key] for key,value in ModelRoles.NON_EVENT_CHOICES}
        # we are adding Competitor so we can remove it when making people judges.  SHouldn't need to but for now...
        context['roles'][ModelRoles.ROLE_COMPETITOR] = "Competitor"
        context['role_list'] = Role.objects.exclude(role_type__in = [ModelRoles.ROLE_COMPETITOR, ModelRoles.ROLE_DEFAULT])


        return context


class ManageUsers(UserCanAdministerMixin, TemplateView):
    #NOTE: getting stack overflow error when toggling roles in pycharm - not tested in production
    template_name = "admin/manage_users.html"

    def get_context_data(self, *args, **kwargs):
        context = super().get_context_data(**kwargs)
        #
        # context['users'] = User.objects.all().order_by('last_name', 'first_name')

        return context
