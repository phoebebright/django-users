import base64
import io
import json
import logging
import random
import string

from datetime import datetime, timedelta
from urllib.parse import urlencode, quote_plus

import difflib
import qrcode
from django.apps import apps
from django.core import signing
from django.core.signing import TimestampSigner, SignatureExpired, BadSignature
from django.db import models, transaction
from django.db.models import Count, Case, When, CharField, Q, Prefetch
from django.db.models.functions import Extract, Concat, Cast, LPad
from django.template import TemplateDoesNotExist
from django.template.loader import get_template
from django.utils.decorators import method_decorator
from django.utils.module_loading import import_string
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_protect

from docserve.mixins import DocServeMixin
from .forms import SubscribeForm, ChangePasswordNowCurrentForm, ForgotPasswordForm, ChangePasswordForm, \
    ContactForm as ContactForm, OrganisationForm, CustomUserCreationForm, SubscriptionPreferencesForm, \
    SignUpForm, AddCommsChannelForm, CommsChannelForm, VerificationCodeForm, PersonForm, SkorieUserCreationForm, \
    ProfileForm, AdminEditContactForm, AdminAddChannelForm

import requests

from django.contrib.auth.decorators import login_required, user_passes_test

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils.translation import gettext_lazy as _
from django.http import HttpResponseRedirect, HttpResponse, Http404, HttpRequest, HttpResponseBadRequest
from django.shortcuts import redirect, get_object_or_404, render
from django.urls import reverse_lazy, reverse
from django.utils import timezone
from django.views import generic, View
from django.conf import settings
from django.views.generic import FormView, TemplateView, DetailView, ListView, UpdateView

from django.contrib.auth import (authenticate, get_user_model, login, logout as log_out,
                                 update_session_auth_hash)

from .tools.permission_mixins import UserCanAdministerMixin
from .tools.views_mixins import GoNextMixin, CheckLoginRedirectMixin
from .utils import normalise_email, get_mail_class

ModelRoles = import_string(settings.MODEL_ROLES_PATH)

User = get_user_model()

mail = get_mail_class()

logger = logging.getLogger('django')

LOGIN_URL = getattr(settings, 'LOGIN_URL', 'users:login')
LOGIN_REGISTER = getattr(settings, 'LOGIN_REGISTER', 'users:register')
CHANNEL_EMAIL = getattr(settings, 'CHANNEL_EMAIL', 'email')  # should never need to change this
VERIFY_ONCE = getattr(settings, 'VERIFY_ONCE',
                      True)  # if True then user will be auto verified  - currently does not handle VERIFY_ONCE = False

from .idp import AuthentikIdP, AuthentikError


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


class AddUser(generic.CreateView):
    '''Creates a Django user backed by a matching Authentik user.

    Inherit and ensure correct permissions are set in the child class.
    Define a success_url that may pass on to a view that delivers the
    initial password — this view only creates the user.
    '''
    new_user = None
    otp_code = None

    template_name = 'django_users/admin/add_user.html'

    def get_template_names(self):
        try:
            get_template(self.template_name)
        except TemplateDoesNotExist:
            template = 'django_users/admin/add_user.html'
        else:
            template = self.template_name
        return [template, ]

    def get_success_url(self):
        mail.send(
            self.user.email,
            template='new_user',
            context={'user': self.new_user, 'otp_code': self.otp_code},
            receiver=self.user,
        )

    def get_form_class(self):
        return SkorieUserCreationForm

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['role'] = self.request.GET.get('role', None)
        return kwargs

    def form_valid(self, form):
        '''Create the IdP user first, then the Django user pointing at it.'''
        me = self.request.user
        data = form.cleaned_data
        password = (data.get('password') or '').replace(' ', '')

        idp = AuthentikIdP()
        try:
            idp_user = idp.create_user(
                email=data['email'],
                first_name=data.get('first_name', ''),
                last_name=data.get('last_name', ''),
            )
        except AuthentikError as exc:
            logger.error("Failed to create Authentik user for %s: %s", data['email'], exc)
            form.add_error(None, _('Could not create user account in IdP.'))
            return self.form_invalid(form)

        if password:
            idp.set_password(idp_user.uuid, password)
        idp.mark_email_verified(idp_user.uuid)

        user = form.save(commit=False)
        if not isinstance(user, User):
            user = user.instance

        user.authentik_id = idp_user.uuid
        self.otp_code = password
        user.attributes = {'temporary_password': self.otp_code}
        user.activation_code = self.otp_code
        user.creator = me
        if not user.username:
            user.username = user.email
        user.save()

        self.new_user = user
        return super().form_valid(form)


class TellUsAbout(LoginRequiredMixin, FormView):
    template_name = "django_users/user_about.html"
    form_class = SubscribeForm
    success_url = '/'

    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

    def get_context_data(self, **kwargs):

        context = super().get_context_data()
        if settings.USE_NEWSLETTER:
            Newsletter = apps.get_model('skorie_news', 'Newsletter')
            context['subcribed2newsletter'] = Newsletter.is_subscribed_to_newsletter(self.request.user)
        context['next'] = "/"
        return context

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
        user.confirm()

        # add contact note
        notify = getattr(settings, "NOTIFY_NEW_USER_EMAILS", False)
        UserContact.add(user=user, method="Subscribe & Interest Form",
                        data=form.cleaned_data, send_mail=notify)

        return super().form_valid(form)

# deprecated - use TellUsAbout
class SubscribeView(TellUsAbout):
    pass

# deprecated - don't use simple subscribe/unsubscribe field
@never_cache
def unsubscribe_only(request):
    if request.user.is_authenticated:
        request.user.update_subscribed(False)

    return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))


@never_cache
def subscribe_only(request):
    if request.user.is_authenticated:
        request.user.update_subscribed(True)

    return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))


@login_required()
def send_test_email(request):
    CommsChannel = apps.get_model('users.CommsChannel')
    to_email = request.user.email
    # can also send a test from another email belonging to this user
    chid = request.POST.get('chid', None)
    if chid:
        channel = CommsChannel.objects.filter(user=request.user, pk=chid, channel_type="email").first()
        if channel:
            to_email = channel.address

    mail.send(
        subject=f"Test Message from {settings.SITE_NAME}",
        message="This is a test message to check that email can be sent to your account. ",
        recipients=[to_email, ],
        sender=settings.DEFAULT_FROM_EMAIL,
        priority='now',
    )

    return HttpResponse("Mail Sent...")


# user = User.objects.create_user(username=userid, email=user_details['email'],
#                                 first_name=user_details['firstName'], last_name=user_details['lastName'])


def logout(request):
    """GET-accepting logout.

    1. Clear the Django session.
    2. Redirect the browser to Authentik's end-session endpoint so the IdP
       session is also terminated and the user is sent back to
       LOGOUT_REDIRECT_URL.

    Falls back to a local-only logout if OIDC_OP_LOGOUT_ENDPOINT is not
    configured.
    """
    nextpage = get_legitimate_redirect(request)
    log_out(request)

    end_session = getattr(settings, "OIDC_OP_LOGOUT_ENDPOINT", "")
    if end_session:
        from urllib.parse import urlencode
        params = {"post_logout_redirect_uri": request.build_absolute_uri(nextpage)}
        return HttpResponseRedirect(f"{end_session}?{urlencode(params)}")

    return HttpResponseRedirect(nextpage)


def login_redirect(request):
    url = reverse(settings.LOGIN_URL)
    if 'next' in request.GET.urlencode():
        url += f"?{request.GET.urlencode()}"
    elif request.GET.urlencode():
        url += f"?next={request.GET.urlencode()}"
    return HttpResponseRedirect(url)


def signup_redirect(request):
    url = reverse(settings.LOGIN_REGISTER)
    if 'next' in request.GET.urlencode():
        url += f"?{request.GET.urlencode()}"
    elif request.GET.urlencode():
        url += f"?next={request.GET.urlencode()}"
    return HttpResponseRedirect(url)


def after_login_redirect(request):
    # using skor.ie emails as temporary emails so don't want subscirbe form displayed
    User = get_user_model()

    if not request.user.is_authenticated:
        logger.error(f"In after_login_redirect and user is not authenticated")

    if request.user.is_authenticated and request.user.status < User.USER_STATUS_CONFIRMED:
        url = reverse("users:tell_us_about")
    else:
        url = "/"

    return HttpResponseRedirect(url)


@method_decorator(never_cache, name='dispatch')
class UserProfileView(LoginRequiredMixin, GoNextMixin, FormView):
    form_class = ProfileForm
    model = User
    user = None

    def get_template_names(self):
        return "django_users/change_profile.html"

    def dispatch(self, request, *args, **kwargs):
        # If user has not completed profile - bounce them there first
        # but only if we have the page set
        self.user = request.user

        goto = reverse(getattr(settings, 'CONFIRM_USER_PAGE', "users:tell_us_about"))
        if not self.user.is_authenticated:
            return HttpResponseRedirect(f"{reverse_lazy(settings.LOGIN_URL)}?next={goto}")

        if goto and self.user.status < self.user.USER_STATUS_CONFIRMED:
            # redirect early if user not allowed
            return redirect(f"{goto}?next={reverse_lazy('users:user-profile')}")  # or any URL name/path

        # otherwise, continue normally
        return super().dispatch(request, *args, **kwargs)

    def get_initial(self):
        initial = super().get_initial()
        user = self.user
        if user.is_authenticated:
            initial['country'] = user.country
            initial['city'] = user.profile['city'] if 'city' in user.profile else ''
        return initial

    def get_context_data(self, **kwargs):
        self.user = self.request.user if self.request.user.is_authenticated else None
        Subscription = apps.get_model('skorie_news.Subscription')
        context = super().get_context_data(**kwargs)
        context['USE_SUBSCRIBE'] = settings.USE_SUBSCRIBE
        if settings.USE_NEWSLETTER:
            context['subscriptions'] = Subscription.objects.filter(user=self.user).order_by('-created')
        context['now'] = timezone.now()
        context['roles'] = self.request.user.user_roles(descriptions=True)

        return context

    def post(self, request, *args, **kwargs):

        form = self.get_form()
        if form.is_valid():
            user = self.user
            user.country = form.cleaned_data['country']
            user.profile['city'] = form.cleaned_data['city']

            user.save()

            return HttpResponseRedirect(self.get_success_url())
        else:
            return self.form_invalid(form)


@method_decorator(never_cache, name='dispatch')
# Troubleshoot, ProblemSignup, ProblemLogin removed on the authentik branch.
# These were Keycloak-specific debugging flows. Authentik's admin UI replaces
# the support paths; for users with login problems, point them at the IdP's
# password-reset flow.


@method_decorator(never_cache, name='dispatch')
class NewUsers(UserCanAdministerMixin, TemplateView):
    template_name = "django_users/admin/new_users.html"

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


# get_keycloak_signup_url and UserMigrationView removed on the authentik branch.
# OIDC discovery handles authorize URLs; old-realm migration is N/A on a fresh
# project.


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


# LoginView removed on the authentik branch. mozilla-django-oidc handles the
# OIDC authorization-code flow; settings.LOGIN_URL should resolve to
# 'oidc_authentication_init' (or be aliased via a one-line view that
# redirects there).


@method_decorator(never_cache, name='dispatch')
class RegisterView(FormView):
    form_class = SignUpForm
    template_name = "django_users/register.html"
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
        email = normalise_email(form.cleaned_data['email'])
        mobile = form.cleaned_data.get('mobile')
        password = form.cleaned_data['password']

        User = get_user_model()
        # this code cannot find username=email but when you try to create it, it says can't create duplicate and you see it already there.
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
                    mobile=mobile or '',
                    is_active=False
                )
            except User.DoesNotExist:
                # if there is old data where email != username then will get duplicate error here
                messages.error(self.request,
                               _(f'Failed to create user account - duplicate email {email}. Please try again later.'))
                return HttpResponseRedirect(reverse(LOGIN_REGISTER))
            except Exception as e:
                messages.error(self.request,
                               _(f'Failed to create user account with error {e}. Please try again later.'))
                raise
        else:
            if not user.is_active and user.authentik_id:
                # User exists in IdP but never finished verification. Reset
                # their password so they can complete registration.
                try:
                    AuthentikIdP().set_password(user.authentik_id, password)
                except AuthentikError as exc:
                    logger.warning("Could not reset IdP password during re-registration of %s: %s",
                                   user.email, exc)
            elif user.is_active:
                messages.warning(self.request,
                                 _('An account with this email already exists. Please log in with the original password.'))
                return HttpResponseRedirect(reverse(LOGIN_URL) + f"?email={quote_plus(email)}")

        set_current_user(self.request, user.id, "REGISTER")

        if not user.authentik_id:
            if user.create_authentik_user_from_user(password, self.request.user) is None:
                messages.error(self.request, _('Failed to create user account. Please try again later.'))
                return HttpResponseRedirect(reverse(LOGIN_REGISTER))

        self.create_comms_channels(CHANNEL_EMAIL, user)
        if mobile and preferred_channel in CommsChannel.MOBILE_CHANNELS:
            self.create_comms_channels(preferred_channel, user)

        user.preferred_channel = self.create_comms_channels(preferred_channel, user)
        user.save(update_fields=['preferred_channel'])

        # TODO: could try signing in - at least put email in login form
        self.user = user
        return HttpResponseRedirect(self.get_success_url())

    def create_comms_channels(self, channel_type, user):
        CommsChannel = apps.get_model('users.CommsChannel')
        channel, created = CommsChannel.objects.get_or_create(
            user=user,
            channel_type=channel_type,
        )
        return channel


@method_decorator(never_cache, name='dispatch')
class AddCommsChannelView(FormView):
    '''This can be called after the user has logged in or before. If before, there needs to be some throttling'''

    form_class = AddCommsChannelForm

    def get(self, request):
        """Handle GET request and render form."""
        form_class = self.get_form_class()
        form = form_class()

        user, user_login_mode = get_current_user(request)
        if user:
            form.fields['username_code'].initial = user.password

        return render(request, 'django_users/add_channel.html', {'form': form})

    def post(self, request):
        """Handle POST request, validate form, and create communication channel."""
        form = self.get_form_class()(request.POST)

        if form.is_valid():
            validated_data = form.cleaned_data
            user, user_login_mode = get_current_user(request)
            if user:
                CommsChannel = apps.get_model('users.CommsChannel')
                channel, created = CommsChannel.objects.get_or_create(
                    user=user,
                    channel_type=validated_data['channel_type'],
                )

                return HttpResponseRedirect(reverse('users:manage-channels'))
            else:
                # Redirect to login if the user is not authenticated
                return HttpResponseRedirect(reverse('users:login'))

        # If form is invalid, re-render the form with errors
        return render(request, 'django_users/add_channel.html', {'form': form})


def set_current_user(request, user_id=None, user_login_mode=None):
    '''call with no parameters to clear
    # user_login_mode - "REGISTER", "PROBLEM", "LOGGEDIN"
    '''
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


#
# @method_decorator(never_cache, name='dispatch')
# class VerifyChannelView(FormView):
#     form_class = VerificationCodeForm
#
#
#     def get(self, request, channel_id):
#         user, user_login_mode = get_current_user(request)
#         CommsChannel = apps.get_model('users.CommsChannel')
#         channel = get_object_or_404(CommsChannel, id=channel_id)
#
#         VerificationCode = apps.get_model('users.VerificationCode')
#         vc = VerificationCode.create_verification_code(user, channel)
#         success = vc.send_verification_code()
#
#         if not success:
#             messages.error(request, _('Failed to send verification code. Check your contact method is correct.'))
#             return HttpResponseRedirect('users:login')
#
#         form_class = self.get_form_class()
#         form = form_class(initial={'channel': channel})
#
#         next = request.GET.get('next', reverse('users:login'))
#
#         context = {'form': form, 'channel': channel}
#         if request.user.is_authenticated and request.user.is_administrator:
#             context['verification_code'] = vc.code
#
#         return render(request, 'django_users/verify_channel.html', context)
#
#     def post(self, request, channel_id):
#         CommsChannel = apps.get_model('users.CommsChannel')
#         VerificationCode = apps.get_model('users.VerificationCode')
#         channel = get_object_or_404(CommsChannel, id=channel_id)
#         code = request.POST.get('code', None)
#
#         if code:
#             success = VerificationCode.verify_code(code, channel)
#             if success:
#                 messages.success(request, _('Contact method has been verified.'))
#                 url = f"{reverse('users:login')}?" + urlencode({'email': channel.user.email})
#                 return redirect(url)
#
#         messages.error(request, _('Invalid or expired verification code.'))
#         return render(request, 'django_users/verify_channel.html', {'channel': channel})
#


@method_decorator(never_cache, name='dispatch')
class VerifyChannelView(FormView):
    template_name = 'django_users/verify_channel.html'
    form_class = VerificationCodeForm

    def _get_models(self):
        CommsChannel = apps.get_model('users', 'CommsChannel')
        VerificationCode = apps.get_model('users', 'VerificationCode')
        return CommsChannel, VerificationCode

    def _get_channel(self, channel_id):
        user, user_login_mode = get_current_user(self.request)
        CommsChannel, _ = self._get_models()
        channel = get_object_or_404(CommsChannel, id=channel_id)

        # Only the owner or an administrator can verify this channel
        if self.request.user.is_authenticated and getattr(self.request.user, "is_administrator", False):
            return channel, user  # admin can act; user returned is current session user (if you need it)
        # else require the pending-login user (from session helper) to match
        if user:
            if channel.user_id == getattr(user, "id", None):
                return channel, user
            else:
                raise get_object_or_404(CommsChannel, id=-1)  # forces 404

        return channel, None

    def _send_code_or_link(self, channel):
        """
        Sends either a magic link (email) or a 6-digit code (email/sms/whatsapp),
        returning a dict for the template context.
        """
        _, VerificationCode = self._get_models()
        purpose = "email_verify"
        USE_MAGIC_LINK = getattr(settings, "VERIFICATION_USE_MAGIC_LINK", False)

        if USE_MAGIC_LINK and channel.channel_type == "email":
            vc, context = VerificationCode.create_for_magic_link(
                user=channel.user, channel=channel, purpose="email_verify"
            )
        else:
            vc, context = VerificationCode.create_for_code(
                user=channel.user, channel=channel, purpose="email_verify"
            )

        sent = vc.send_verification(context, purpose)
        context["sent"] = bool(sent)

        return context

    # GET: show the form (code flow) and send code/link on first load or when ?resend=1
    def get(self, request, channel_id):

        channel, _ = self._get_channel(channel_id)

        if channel.is_verified:

            if request.user.is_authenticated:
                messages.success(request, 'Contact method has already been verified.')
                return redirect('/')
            else:
                messages.success(request, f'Your account is already verified, please {settings.LOGIN_TERM}')
                return redirect('users:login')

        # send on first arrival or explicit resend
        if "resent" not in request.GET or request.GET.get("resend") == "1":
            send_ctx = self._send_code_or_link(channel)
            if not send_ctx["sent"]:
                messages.error(request, 'Failed to send verification. Check your contact method is correct.')
                return redirect('users:login')

            if "magic_link" in send_ctx and send_ctx["magic_link"]:
                # don't have user logged in so fails
                messages.info(request, 'We’ve sent you a verification link. Please check your email.')
                # For magic-link we don't need to show a code form; still render a page with a resend option.
                return render(request, self.template_name, {
                    "channel": channel,
                    "form": None,
                    "magic_link": True,
                })

        form = self.form_class(initial={'channel': channel})
        context = {"form": form, "channel": channel, "magic_link": False}

        return render(request, self.template_name, context)

    # POST: handle 6-digit code submission
    def post(self, request, channel_id):
        channel, _ = self._get_channel(channel_id)
        code = request.POST.get('code') or request.POST.get('verification_code')

        if not code:
            messages.error(request, _('Please enter the verification code.'))
            return render(request, self.template_name, {"channel": channel, "form": self.form_class()})

        _, VerificationCode = self._get_models()
        ok = VerificationCode.verify_code(user=channel.user, channel=channel, code=code, purpose="email_verify")

        if ok:
            messages.success(request, _('Contact method has been verified. Please log in.'))
            return redirect('users:login')
            url = f"{reverse('users:login')}?{urlencode({'email': channel.user.email})}"
            return redirect(url)

        messages.error(request, _('Invalid or expired verification code.'))
        return render(request, self.template_name, {"channel": channel, "form": self.form_class()})

class VerifyForgotPasswordLinkView(View):
    def get(self, request):
        token = request.GET.get("t")
        next_url = reverse("users:forgot_password")  # route to your stepper page

        if not token:
            messages.error(request, "Missing token.")
            return redirect(next_url)

        VerificationCode = apps.get_model('users', 'VerificationCode')
        vc = VerificationCode.verify_token(raw_token=token, purpose="forgot_password")
        if not vc:
            messages.error(request, "Invalid or expired link.")
            return redirect(next_url)

        # success: remember which email/channel this flow is for
        request.session[ForgotPassword.SK_EMAIL] = vc.user.email
        request.session[ForgotPassword.SK_CHANNEL] = str(vc.channel_id)
        request.session[ForgotPassword.SK_VC_PK] = str(vc.pk)
        request.session[ForgotPassword.SK_VERIFIED] = True
        request.session[ForgotPassword.SK_STEP] = 4  # jump to password entry

        messages.success(request, "Your email has been verified. Please set a new password.")
        return redirect(next_url)

@method_decorator(never_cache, name='dispatch')
class ManageCommsChannelsView(View):
    def get(self, request):
        channels = request.user.comms_channels.all()
        return render(request, 'django_users/manage_channels.html', {'channels': channels})

    def post(self, request):
        # Handle deletion or re-verification if needed
        pass


# RECOMMENDED: link users to Authentik's self-service settings page instead
# of using this in-app form. Authentik handles password change, MFA enrolment,
# recovery codes, and active session management at:
#
#     {{ AUTHENTIK_URL }}/if/user/#/settings
#
# Project context-processor exposes AUTHENTIK_URL — see web/context_processors.py.
# The in-app form below stays for cases where you want everything to live
# inside skorie's own UI, but it duplicates what Authentik already provides
# and has to mirror the IdP's password validation rules.
@method_decorator(never_cache, name='dispatch')
class ChangePasswordNowView(GoNextTemplateMixin, FormView):
    template_name = "django_users/change_password.html"
    form_class = ChangePasswordNowCurrentForm

    def get(self, request, *args, **kwargs):
        # only for logged in users - don't want to use standard mixin as this will ask them to login and then return here
        if not request.user.is_authenticated:
            return redirect(reverse('users:forgot_password'))
        return super().get(request, *args, **kwargs)

    def get_success_url(self):
        return "/"

    def get_form_class(self):
        if not hasattr(self, 'form_class') or self.form_class is None:
            raise NotImplementedError("Define `form_class` in the child class.")
        return self.form_class

    def form_valid(self, form):
        user = self.request.user
        new_password = form.cleaned_data["new_password"]

        if not user.authentik_id:
            form.add_error(None, "Cannot update password: user has no IdP account.")
            return self.form_invalid(form)

        try:
            AuthentikIdP().set_password(user.authentik_id, new_password)
        except AuthentikError as exc:
            form.add_error(None, f"Failed to update password: {exc}")
            return self.form_invalid(form)

        messages.success(self.request, "Password updated successfully.")
        return super().form_valid(form)


# RECOMMENDED: redirect anonymous "I forgot my password" users to Authentik's
# password-recovery flow rather than running this in-app reset. Configure a
# Recovery Flow in Authentik admin, then link the Login template to:
#
#     {{ AUTHENTIK_URL }}/if/flow/<recovery-flow-slug>/
#
# That flow sends the email, verifies the code, and lets the user set a new
# password — no password-reset code needs to live in skorie. The view below
# remains for projects that prefer to keep the whole flow in their own UI.
@method_decorator(never_cache, name='dispatch')
class ForgotPassword(CheckLoginRedirectMixin, FormView):
    # TODO: instead of putting vc code into session, put the pk of the record and check properly
    # Recheck vc on last step before changing password - could bypass step 3?
    template_name = "django_users/forgot_password.html"
    form_class = ForgotPasswordForm
    success_url = reverse_lazy("users:change_password")
    user = None
    channel = None

    # session keys we use
    SK_STEP = "forgot_password_step"
    SK_EMAIL = "forgot_email"
    SK_CHANNEL = "forgot_channel"         # channel id (int/uuid)
    SK_VC_PK = "forgot_vc_pk"             # verification code pk (uuid)
    SK_VERIFIED = "forgot_verified"       # bool set by code or magic link

    def dispatch(self, request, *args, **kwargs):
        # Ensure user is redirected if already logged in
        if request.user.is_authenticated:
            return redirect(self.success_url)
        return super().dispatch(request, *args, **kwargs)

    # ---------- step helpers

    def get_step(self):
        return int(self.request.session.get(self.SK_STEP, 1))

    def set_step(self, step):
        self.request.session[self.SK_STEP] = int(step)

    def reset_flow(self):
        for k in (self.SK_STEP, self.SK_EMAIL, self.SK_CHANNEL, self.SK_VC_PK, self.SK_VERIFIED):
            self.request.session.pop(k, None)

    def _models(self):
        CommsChannel = apps.get_model('users', 'CommsChannel')
        VerificationCode = apps.get_model('users', 'VerificationCode')
        return CommsChannel, VerificationCode

    # ---------- DRF-ish plumbing

    def get(self, request, *args, **kwargs):
        # Reset flow on GET land (same as your current behavior)
        self.reset_flow()
        return super().get(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        step = self.get_step()
        kwargs['step'] = step  # Pass the current step to the form

        # set initial values from session
        if step == 1:
            email = self.request.GET.get('email') or self.request.POST.get('email')
            if email:
                kwargs['initial'] = {'email': normalise_email(email)}
        else:
            email = normalise_email(self.request.session.get(self.SK_EMAIL, "")) if self.request.session.get(self.SK_EMAIL) else ""
            kwargs.setdefault('initial', {})
            kwargs['initial']['email'] = email

            if step > 2 and self.request.session.get(self.SK_CHANNEL):
                kwargs['initial']['channel'] = self.request.session.get(self.SK_CHANNEL)

            # You can add 'user' so the form can list channels
            if email:

                self.user = User.objects.filter(email=email).first()
                if self.user:
                    kwargs['user'] = self.user

        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['step'] = self.get_step()
        ctx['verification_sent'] = bool(self.request.session.get(self.SK_VC_PK))
        ctx['magic_link'] = bool(settings.USE_MAGIC_LINK_FOR_FORGOT)
        ctx['user'] = self.user
        return ctx

    # ---------- main stepper

    def form_valid(self, form):
        step = self.get_step()

        if step == 1:
            # Step 1: verify email exists (no enumeration wording leaked to UI)
            email = normalise_email(form.cleaned_data['email'])
            user = User.objects.filter(email=email).first()

            if not user:
                form.add_error('email', f'Email not found. Please {settings.REGISTER_TERM}.')
                return self.form_invalid(form)

            if not user.is_active and user.last_login:
                # previously active but now disabled — escalate
                form.add_error('email', 'This email does not have an active account. Please contact the administrators.')
                return self.form_invalid(form)

            # Persist email and continue
            self.request.session[self.SK_EMAIL] = email
            self.set_step(2)

        elif step == 2:
            # Step 2: choose channel and send code or magic link
            email = normalise_email(self.request.session.get(self.SK_EMAIL, ""))
            user = User.objects.filter(email=email).first()
            if not user:
                form.add_error('email', 'Email not found.')
                return self.form_invalid(form)

            channel_id = form.cleaned_data['channel']
            CommsChannel, VerificationCode = self._models()

            try:
                channel = CommsChannel.objects.get(id=channel_id, user=user)
            except CommsChannel.DoesNotExist:
                form.add_error('channel', 'Invalid or unverified channel selected.')
                return self.form_invalid(form)

            # Store channel id
            self.request.session[self.SK_CHANNEL] = str(channel_id)

            # Create verification
            purpose = "forgot_password"
            if settings.USE_MAGIC_LINK_FOR_FORGOT and channel.channel_type == "email":
                vc, context = VerificationCode.create_for_magic_link(user=user, channel=channel, purpose=purpose)
            else:
                vc, context = VerificationCode.create_for_code(user=user, channel=channel, purpose=purpose)

            # Send (your model uses vc.send_verification(context))
            sent = vc.send_verification(context, purpose)
            if not sent:
                form.add_error(None, 'Failed to send verification. Please check your contact method.')
                return self.form_invalid(form)

            # Store vc pk (NOT the raw code)
            self.request.session[self.SK_VC_PK] = str(vc.pk)

            if settings.USE_MAGIC_LINK_FOR_FORGOT and channel.channel_type == "email":
                # For magic link, go straight to step 3 page that waits for link or offers "enter code" fallback if you want.
                messages.info(self.request, 'We’ve sent you a verification link. Please check your email.')
                # Optionally you could allow a fallback code entry if your email also includes the code.
                self.set_step(3)
            else:
                # Code flow: proceed to code entry step
                messages.info(self.request, 'We’ve sent you a verification code. Please check your email.')
                self.set_step(3)

        elif step == 3:
            # Step 3: verify the code (code flow) OR accept magic-link completion
            CommsChannel, VerificationCode = self._models()

            email = normalise_email(self.request.session.get(self.SK_EMAIL, ""))
            user = User.objects.filter(email=email).first()
            if not user:
                form.add_error('email', 'Session expired. Please start again.')
                return self.form_invalid(form)

            # If magic link was used and already verified, skip code entry
            if self.request.session.get(self.SK_VERIFIED):
                self.set_step(4)
                return self._render_next_step(form)

            # Otherwise verify typed code
            code = form.cleaned_data.get('verification_code')
            channel_id = self.request.session.get(self.SK_CHANNEL)
            try:
                channel = CommsChannel.objects.get(id=channel_id, user=user)
            except CommsChannel.DoesNotExist:
                form.add_error('channel', 'Invalid channel. Please start again.')
                return self.form_invalid(form)

            ok = VerificationCode.verify_code(user=user, channel=channel, code=code, purpose="forgot_password")
            if not ok:
                form.add_error('verification_code', 'Invalid or expired verification code.')
                return self.form_invalid(form)

            # Mark as verified for this flow
            self.request.session[self.SK_VERIFIED] = True
            self.set_step(4)

        elif step == 4:
            # Step 4: set the new password
            email = normalise_email(self.request.session.get(self.SK_EMAIL, ""))
            user = User.objects.filter(email=email).first()
            if not user:
                form.add_error('email', 'Session expired. Please start again.')
                return self.form_invalid(form)

            if not self.request.session.get(self.SK_VERIFIED):
                form.add_error(None, 'Please verify your contact method before changing password.')
                self.set_step(3)
                return self.form_invalid(form)

            new_password = form.cleaned_data['new_password']
            confirm_password = form.cleaned_data['confirm_password']
            if new_password != confirm_password:
                form.add_error('confirm_password', 'Passwords do not match.')
                return self.form_invalid(form)

            # ---- password update via the IdP ----
            if not getattr(user, "authentik_id", None):
                logger.error("User %s does not have an authentik_id.", user.pk)
                form.add_error('confirm_password', 'There is an issue with your account.')
                return self.form_invalid(form)
            try:
                AuthentikIdP().set_password(user.authentik_id, new_password)
                success = True
            except AuthentikError as exc:
                logger.error("Failed to set IdP password for user %s: %s", user.pk, exc)
                success = False

            if success:
                # Keep user logged-in if they're changing their own password while authenticated (rare in this flow)
                if user == self.request.user and self.request.user.is_authenticated:
                    update_session_auth_hash(self.request, user)

                messages.success(self.request,
                                 'Your password has been reset. You can now log in with your new password.')
                # clear flow
                self.reset_flow()
                return redirect(reverse(LOGIN_URL) + f"?email={quote_plus(user.email)}")

            form.add_error('confirm_password', 'Unable to reset password. Please try a different password.')
            return self.form_invalid(form)

            # Re-render with next step’s empty form
        return self._render_next_step(form)

    def _render_next_step(self, form):
        # Rebuild a fresh form for the new step
        newform = self.get_form()
        # Redirect back to form to display the next step
        return self.render_to_response(self.get_context_data(form=newform))


# RECOMMENDED: link the user to Authentik's self-service settings page
# instead of routing them through this view. Authentik covers password
# change, MFA enrolment, recovery codes, and active sessions in one place:
#
#     {{ AUTHENTIK_URL }}/if/user/#/settings
#
# See templates/account/profile.html for an example link, and
# web/context_processors.py for where AUTHENTIK_URL is exposed.
# This in-app form stays for projects that want everything inside their
# own UI; it duplicates what Authentik provides for free.
@method_decorator(never_cache, name='dispatch')
class ChangePasswordView(GoNextTemplateMixin, FormView):
    template_name = "django_users/change_password.html"
    form_class = ChangePasswordForm
    success_url = reverse_lazy("users:user-profile")

    def form_valid(self, form):
        # TODO: should we check for user still being logged in?

        current_password = form.cleaned_data.get("current_password")
        new_password = form.cleaned_data.get("new_password")

        # Your helper returns the canonical user object to update
        user, user_login_mode = get_current_user(self.request)

        # Verify current password by checking against Django's hash. The IdP
        # session-cookie already proves identity for the *current* request;
        # we only need to confirm intent before mutating the password.
        if not user.check_password(current_password):
            form.add_error('current_password', "Current password is incorrect.")
            return self.form_invalid(form)

        if not getattr(user, "authentik_id", None):
            form.add_error(None, "Cannot change password: user has no IdP account.")
            return self.form_invalid(form)

        try:
            AuthentikIdP().set_password(user.authentik_id, new_password)
        except AuthentikError as exc:
            form.add_error(None, f"Failed to update password: {exc}")
            return self.form_invalid(form)

            # # 3) If this code ever runs in a flow where the user isn't authenticated
            # # (e.g., recovery form), sign them in with the new password now.
            # if not self.request.user.is_authenticated:
            #     # Try with username first (works for default Django backends)
            #     auth_user = authenticate(self.request,
            #                              username=getattr(user, "get_username", lambda: user.username)(),
            #                              password=new_password)
            #     if not auth_user and getattr(user, "email", None):
            #         # Fallback for email-based backends
            #         auth_user = authenticate(self.request, email=user.email, password=new_password)
            #     if auth_user:
            #         login(self.request, auth_user)

            messages.success(self.request, "Password updated successfully.")
            return super().form_valid(form)

        except Exception as e:
            form.add_error(None, f"Failed to update password: {e}")
            return self.form_invalid(form)


# update_users (one-off authentik_id backfill) and UnverifiedUsersList
# (read directly from Keycloak's UserEntity table) removed on the authentik
# branch. Authentik's admin UI provides equivalent visibility.


class SendOTP(UserCanAdministerMixin, DocServeMixin, TemplateView):
    template_name = 'django_users/admin/send_otp.html'
    docserve_page = 'admin/users/user_otp.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        User = get_user_model()
        context['recipient'] = User.objects.get(id=kwargs['pk'])
        context['otp'] = ''.join(random.choices(string.digits, k=6))
        context['recipient'].activation_code = context['otp']
        context['recipient'].save(update_fields=['activation_code'])
        return context


class ManageRoles(UserCanAdministerMixin, TemplateView):
    # NOTE: getting stack overflow error when toggling roles in pycharm - not tested in production
    template_name = "django_users/admin/manage_roles.html"

    def get_context_data(self, *args, **kwargs):
        context = super().get_context_data(**kwargs)
        Role = apps.get_model('users.Role')
        # see skorie roles_and_disciplines.py as an example - just defines lists and dicts
        ModelRoles = import_string(settings.MODEL_ROLES_PATH)
        context['roles'] = ModelRoles.ROLE_DESCRIPTIONS
        context['role_list'] = Role.objects.all().select_related('user', 'person')

        context['update_user'] = None

        if 'user_id' in self.kwargs:
            context['user'] = User.objects.get(pk=self.kwargs['user_id'])

        return context


class ManageEventRoles(ManageRoles):

    def get_context_data(self, *args, **kwargs):
        context = super().get_context_data(*args, **kwargs)
        ModelRoles = import_string(settings.MODEL_ROLES_PATH)
        Role = apps.get_model('users.Role')

        context['roles'] = {key: value + " - " + ModelRoles.ROLE_DESCRIPTIONS[key] for key, value in
                            ModelRoles.EVENT_CHOICES}
        context['role_list'] = Role.objects.exclude(role_type__in=[ModelRoles.ROLE_DEFAULT, ])

        return context


class ManageNonEventRoles(ManageRoles):

    def get_context_data(self, *args, **kwargs):
        context = super().get_context_data(*args, **kwargs)
        ModelRoles = import_string(settings.MODEL_ROLES_PATH)
        Role = apps.get_model('users.Role')

        context['roles'] = {key: value + " - " + ModelRoles.ROLE_DESCRIPTIONS[key] for key, value in
                            ModelRoles.NON_EVENT_CHOICES}
        context['role_list'] = Role.objects.exclude(role_type__in=[ModelRoles.ROLE_COMPETITOR, ModelRoles.ROLE_DEFAULT])

        return context


class ManageUsers(UserCanAdministerMixin, TemplateView):
    # NOTE: getting stack overflow error when toggling roles in pycharm - not tested in production
    template_name = "django_users/admin/manage_users.html"

    def get_context_data(self, *args, **kwargs):
        context = super().get_context_data(**kwargs)
        #
        # context['users'] = User.objects.all().order_by('last_name', 'first_name')

        return context


@method_decorator(never_cache, name='dispatch')
class ManageUser(UserCanAdministerMixin, TemplateView):
    # NOTE: getting stack overflow error when toggling roles in pycharm - not tested in production
    template_name = "django_users/admin/admin_user.html"
    docserve_page = 'admin/manage_user'

    def get_context_data(self, *args, **kwargs):
        context = super().get_context_data(**kwargs)
        Competitor = apps.get_model('web.Competitor')
        Entry = apps.get_model('web.Entry')
        Payment = apps.get_model('skorie_payments.Payment')
        DirectEmail = apps.get_model('skorie_news.DirectEmail')
        user = None
        # this has all go very messy - should have a uuid id field but we don't so using authentik_id.
        try:
            if 'pk' in kwargs:
                try:
                    user = User.objects.get(authentik_id=kwargs['pk'])
                except:
                    user = User.objects.get(id=kwargs['pk'])  # don;t use id
            elif 'email' in kwargs:
                logger.warning(f"Using email to call Manage User - deprecated")
                user = User.objects.get(email=kwargs['email'])
        except User.DoesNotExist:
            raise Http404(_("No user found"))

        context['object'] = user

        context['user_status'] = User.check_register_status(email=context['object'].email, requester=self.request.user)

        if settings.USE_NEWSLETTER:
            # context['subscriptions'] = Subscription.objects.filter(user=context['object'])
            # # context['newsletters'] = Newsletter.objects.all()

            # prefetch subscriptions only for this user
            Newsletter = apps.get_model('skorie_news', 'Newsletter')
            user_subs = context['object'].subscription_set.all()

            newsletters = Newsletter.objects.visible().prefetch_related(
                Prefetch("subscriptions", queryset=user_subs, to_attr="user_subs")
            )

            # each Newsletter will have .user_subs = [subscription] or []
            context["newsletter_subs"] = [
                {"newsletter": nl, "subscription": nl.user_subs[0] if nl.user_subs else None}
                for nl in newsletters
            ]
        #context['roles4user'] = context['object'].Role.objects.filter(user=user).order_by('role_type').select_related('organisation','authority','person')
        context['roles4user'] = context['object'].Role.objects.filter(user=user).order_by('role_type')
        context['roles4user_list'] = [r.role_type for r in context['roles4user']]

        context['competitors'] = Competitor.objects.filter(user=context['object'])
        context['entries'] = Entry.objects.my_entries(context['object']).order_by(
            '-created')  # ones created by me - includes ones added for another

        if settings.USE_PAYMENTS:
            context['payments'] = Payment.objects.filter(payer=context['object']).order_by('-created')

        # context['tickets'] = Ticket.objects.filter(submitter_email=context['object'].email)

        # handle update of person attributes
        context['person_form'] = PersonForm(instance=context['object'].person)

        context['contacts'] = context['object'].usercontact_set.all().order_by('-pk')

        # # want to add event roles as well...
        # available roles
        context['roles'] = {key: value + " - " + ModelRoles.ROLE_DESCRIPTIONS[key] for key, value in
                            ModelRoles.NON_EVENT_CHOICES}

        context['emails'] = DirectEmail.objects.filter(receiver=context['object']).order_by('-id')[:10]
        return context


class ManageUserProfile(LoginRequiredMixin, generic.CreateView):
    # form_class = CustomUserCreationForm
    template_name = 'django_users/admin/manage_user_profile.html'

    def get_form_class(self):
        return SkorieUserCreationForm

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['role'] = self.request.GET.get('role', None)
        return kwargs

    def form_valid(self, form):
        # This method is called when valid form data has been POSTed.
        # It should return an HttpResponse.
        user = form.save()  # Save the user and get the instance

        # Custom post-save logic here
        # e.g., sending a confirmation email

        return super().form_valid(form)


class ContactView(FormView):
    form_class = ContactForm
    success_url = reverse_lazy('contact-thanks')
    template_name = "django_users/contact.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        me = self.request.user

        return context

    def form_valid(self, form):

        # contact form where there is not a logged in user includes a question.  If answered correctly "passed" field is set to "yes"
        method = "Contact"
        email = normalise_email(form.cleaned_data['email'])
        user = None
        if self.request.user and self.request.user.is_authenticated:
            user = self.request.user
            method = "Support"

        # if user is logged in, we let them use a different email
        # if they are not logged in, we try to link them to a user to give them higher priority
        if not user:
            try:
                user = User.objects.get(email=email)
                method = "Support2"
            except:
                pass

        # user, _ = User.objects.update_or_create(email=email)

        # allow known users to pass through, otherwise do quick filter for bots
        if not user:
            msg = form.cleaned_data['message'].lower().strip()
            # if 'robot' in msg or 'income' in msg or form.cleaned_data['passed'] != "yes":
            if 'robot' in msg or 'income' in msg:
                logger.warning(f"Dumped contact message from {email} message {json.dumps(form.cleaned_data)} ")
                # no feedback if junk
                return HttpResponseRedirect("/")

            user = User.system_user()

        data = form.cleaned_data
        email = data['email'] or user.email
        email = normalise_email(email)
        # add contact note
        UserContact = apps.get_model('users.UserContact')
        UserContact.add(user=user, method=method, notes=data['message'], data=form.cleaned_data)

        # send email to support
        if settings.CONTACT_FORM_NOTIFICATION_TO:
            subject = f"Contact from {settings.SITE_NAME}"
            message = f"Message from {email}:\n\n{data['message']}"
            mail.send(subject=subject, message=message, sender=settings.DEFAULT_FROM_EMAIL,
                      recipients=settings.CONTACT_FORM_NOTIFICATION_TO)
        #
        # # can only use API if admin - sigh
        # # url = f'{settings.SITE_URL}/helpdesk/api/tickets/'
        # # response = requests.post(url, data={
        # #     'queue': settings.HELPDESK_DEFAULT_QUEUE,
        # #     'title': "Send us a message",
        # #     'description': data['message'],
        # #     'submitter_email': email,
        # # })
        #
        #
        #
        # data['title'] = 'Contact Us Form'
        # data['body'] = data['message']
        # data['priority'] = 1
        #
        # # TicketForm needs id for ForeignKey (not the instance themselves)
        # queue_choices = [(q.id, q.title) for q in Queue.objects.all()]
        #
        # try:
        #     data['queue'] = Queue.objects.get(slug=settings.HELPDESK_DEFAULT_QUEUE).pk
        # except Queue.DoesNotExist:
        #     data['queue'] = Queue.objects.all().first().pk
        #
        # files = {'attachment': data.pop('attachment', None)}
        #
        # ticket_form = TicketForm(
        #     data=data, files=files,
        #     queue_choices=queue_choices )
        # if ticket_form.is_valid():
        #     ticket = ticket_form.save(user=user)
        #     ticket.submitter_email =  data['email']
        #     ticket.save()
        #     # should be in the form - but not working so hacking for now
        #     custom_field = self.request.POST.get('custom_entryid', None)
        #     if custom_field:
        #         ticket.save_custom_field_values({'custom_entryid': custom_field})
        #     # ticket.save_custom_field_values(form.cleaned_data)
        #     # ticket.set_custom_field_values()
        # else:
        #     raise ValidationError(ticket_form.errors)

        return super().form_valid(form)


def update_password_django(user, password):
    user.set_password(password)
    user.save()


class OrganisationUpdateView(LoginRequiredMixin, UpdateView):
    form_class = OrganisationForm
    template_name = 'django_users/organisation_detail.html'
    pk_url_kwarg = 'code'  # Since Organisation uses 'code' as PK

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        organisation = self.object
        context['users'] = User.objects.filter(organisation=organisation)
        # context['gadgets'] = Gadget.objects.filter(organisation=organisation)
        context['user_form'] = self.get_user_form()
        # context['gadget_form'] = GadgetForm()  # Form for adding a new device
        return context

    def get_user_form(self, data=None, instance=None):
        """Returns a user form instance, either blank or with data for validation."""
        return CustomUserCreationForm(data, instance=instance)

    def get_object(self):
        return self.queryset.get(code=self.kwargs['code'])

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()
        organisation = self.object

        if 'add_user' in request.POST:
            user_form = self.get_user_form(request.POST, instance=self.object)
            if user_form.is_valid():
                new_user = user_form.save(commit=False)
                new_user.organisation = organisation
                new_user.set_password(user_form.cleaned_data['password1'])  # Ensure password hashing
                new_user.save()
                return redirect(self.object.get_absolute_url())

        return self.get(request, *args, **kwargs)


class OrganisationListViewBase(ListView):
    model = None
    template_name = "django_users/admin/organisation_list.html"
    context_object_name = "organisations"

# is this used?
@login_required
def qr_login_token(request):
    user = request.user
    payload = {
        'user_id': user.authentik_id,
        'ts': timezone.now().timestamp()
    }
    token = signing.dumps(payload)

    login_url = request.build_absolute_uri(f"/users/lwt/?token={token}")

    # Create QR code
    qr = qrcode.make(login_url)
    buf = io.BytesIO()
    qr.save(buf, format='PNG')
    buf.seek(0)

    return HttpResponse(buf, content_type='image/png')


class QRLogin(LoginRequiredMixin, TemplateView):
    template_name = "django_users/qr_login.html"

    def get_context_data(self, **kwargs):
        me = self.request.user
        context = super().get_context_data(**kwargs)
        payload = {
            'user_id': str(me.authentik_id),
            'ts': timezone.now().timestamp()
        }
        token = signing.dumps(payload)

        login_url = f"{settings.SITE_URL}/ql/?token={token}"

        # Create QR code
        qr = qrcode.make(login_url)
        buf = io.BytesIO()
        qr.save(buf, format='PNG')
        context['qr'] = base64.b64encode(buf.getvalue()).decode()

        return context


def login_with_remote_token(request):
    setting_name = 'REMOTE_LOGIN_SECRET'
    token = request.GET.get("token")
    max_age = 120  # seconds (2 minutes)
    secret = getattr(settings, setting_name, None)

    if not secret:
        return HttpResponse("Missing secret", status=400)
    if not token:
        return HttpResponse("Missing token", status=400)

    signer = TimestampSigner(key=secret)

    try:
        raw = signer.unsign(token, max_age=max_age)

        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")

        payload = json.loads(raw)
        user_id = payload.get('user_id')
        next_url = payload.get('next', '/')

        user = User.objects.get(authentik_id=user_id)
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        return redirect(next_url)

    except SignatureExpired:
        return HttpResponse("Token expired", status=403)
    except BadSignature:
        return HttpResponse("Invalid token signature", status=403)
    except User.DoesNotExist:
        return HttpResponse("User not found", status=404)
    except Exception as e:
        return HttpResponse(f"Error with lwrt: {e}", status=400)

def login_with_token(request, key=None):
    '''handle being sent a token to log a user in (generated with keycloak.generate_login_token or qr token)
    eg. token = generate_login_token(request.user, next='/dashboard/')
        login_url = f"https://app2.example.com/lwt/?token={token}"
    '''
    token = request.GET.get("token")

    try:
        payload = signing.loads(token, key=key, max_age=140)  # 2 and a bit minutes
        user_id = payload.get("user_id")
        next_url = payload.get('next', '/')

        print("Logging in with token")
        user = User.objects.get(authentik_id=user_id)
        print(f"User found: {user}")
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')

        return redirect(next_url)
    except Exception as e:
        return HttpResponse(f"Invalid or expired token with error {e}", status=400)


class UserContactAnalyticsView(TemplateView):
    template_name = 'django_users/admin/user_contact_analytics.html'

    def get_context_data(self, **kwargs):
        UserContact = apps.get_model('users.UserContact')
        context = super().get_context_data(**kwargs)

        # Get date range - default to last 12 weeks
        end_date = timezone.now()
        start_date = end_date - timedelta(weeks=500)

        # Allow filtering by date range via GET parameters
        if self.request.GET.get('start_date'):
            try:
                start_date = datetime.strptime(
                    self.request.GET.get('start_date'),
                    '%Y-%m-%d'
                ).replace(tzinfo=timezone.get_current_timezone())
            except ValueError:
                pass

        if self.request.GET.get('end_date'):
            try:
                end_date = datetime.strptime(
                    self.request.GET.get('end_date'),
                    '%Y-%m-%d'
                ).replace(tzinfo=timezone.get_current_timezone())
            except ValueError:
                pass

        # Query to get contact counts by week, method, and site
        contacts_query = UserContact.objects.filter(
            contact_date__gte=start_date,
            contact_date__lte=end_date
        ).annotate(
            year=Extract('contact_date', 'year'),
            week=Extract('contact_date', 'week')
        ).annotate(
            # Pad week numbers with zeros for proper sorting
            week_str=Cast('week', CharField()),
            week_label=Concat(
                Cast('year', CharField()),
                models.Value('-W'),
                LPad(Cast('week', CharField()), 2, models.Value('0')),
                output_field=CharField()
            )
        )

        # Get the main data grouped by week, method, and site
        contact_data = list(
            contacts_query.values('week_label', 'method', 'site', 'year', 'week')
            .annotate(count=Count('id'))
            .order_by('year', 'week', 'method', 'site')
        )

        # Get summary statistics
        total_contacts = contacts_query.count()

        # Get method breakdown
        method_stats = list(
            contacts_query.values('method')
            .annotate(count=Count('id'))
            .order_by('-count')
        )

        # Get site breakdown
        site_stats = list(
            contacts_query.values('site')
            .annotate(count=Count('id'))
            .order_by('-count')
        )

        # Get weekly totals for trend analysis
        weekly_totals = list(
            contacts_query.values('week_label', 'year', 'week')
            .annotate(count=Count('id'))
            .order_by('year', 'week')
        )

        # Calculate week-over-week growth
        if len(weekly_totals) >= 2:
            current_week = weekly_totals[-1]['count']
            previous_week = weekly_totals[-2]['count']
            week_over_week_change = ((current_week - previous_week) / previous_week * 100) if previous_week > 0 else 0
        else:
            week_over_week_change = 0

        # Get top performers (most active methods and sites)
        top_method = method_stats[0]['method'] if method_stats else 'N/A'
        top_site = site_stats[0]['site'] if site_stats else 'N/A'

        # Add context data
        context.update({
            'contact_data': json.dumps(contact_data),
            'total_contacts': total_contacts,
            'method_stats': json.dumps(method_stats),
            'site_stats': json.dumps(site_stats),
            'weekly_totals': json.dumps(weekly_totals),
            'week_over_week_change': round(week_over_week_change, 1),
            'top_method': top_method,
            'top_site': top_site,
            'start_date': start_date.strftime('%Y-%m-%d'),
            'end_date': end_date.strftime('%Y-%m-%d'),
            'date_range_weeks': (end_date - start_date).days // 7,
        })

        return context


class SubscriptionPreferencesView(LoginRequiredMixin, UpdateView):
    """View for managing subscription preferences"""
    model = get_user_model()
    form_class = SubscriptionPreferencesForm
    template_name = 'django_users/subscription_preferences.html'
    success_url = reverse_lazy('subscription_preferences')

    def get_object(self):
        return self.request.user

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['subscription_history'] = self.request.user.get_subscription_history()[:10]
        context['current_level'] = self.request.user.communication_preference_level
        return context

    def form_valid(self, form):
        messages.success(self.request, 'Your subscription preferences have been updated.')
        return super().form_valid(form)


class UnsubscribeTokenView(TemplateView):
    """Handle unsubscribe via email token"""
    template_name = 'django_users/unsubscribe_confirm.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        token = kwargs.get('token')

        try:
            # You'll need to implement token generation/validation
            user_id, subscription_type = self.decode_unsubscribe_token(token)
            user = get_user_model().objects.get(id=user_id)
            user.unsubscribe_from(subscription_type)

            context.update({
                'success': True,
                'subscription_type': subscription_type,
                'user': user
            })
        except Exception as e:
            context.update({
                'success': False,
                'error': str(e)
            })

        return context

    def decode_unsubscribe_token(self, token):
        # Implement your token decoding logic here
        # Return (user_id, subscription_type)
        pass


def dedupe_role(request, role_ref):
    '''make role_ref the master for this role type and user and delete all others
    NOTE - ignores organisation
    '''
    Role = apps.get_model('users.Role')
    EventRole = apps.get_model('web.EventRole')
    Competitor = apps.get_model('web.Competitor')

    role = Role.objects.get(ref=role_ref)
    qs = Role.objects.filter(user=role.user, role_type=role.role_type).exclude(ref=role_ref)
    print(f"deduping {qs.count()} roles of type {role.role_type} for user {role.user.email} to {role.name}")
    for item in qs:

        similarity = difflib.SequenceMatcher(None, role.name.lower(), item.name.lower()).ratio()
        if similarity >= 0.8:

            for ev in EventRole.objects.filter(role=item):
                ev.role = role
                ev.role_ref = role.ref
                ev.updated = timezone.now()
                ev.save()
                print(f"updating event role {ev.id} to {role.name} of type {role.role_type}/{ev.role_type}")

        else:
            print(f"**ignoring {item.name} as not similar enough to {role.name} - similarity {similarity}")

        if role.role_type == ModelRoles.ROLE_COMPETITOR:

            for competitor in Competitor.objects.filter(role=item):

                similarity = difflib.SequenceMatcher(None, role.name.lower(), item.name.lower()).ratio()
                if similarity >= 0.8:

                    competitor.role = role
                    competitor.updated = timezone.now()
                    competitor.save()
                    print(f"updating competitor {competitor.id} to {role.name} of type {role.role_type}")

                else:
                    print(
                        f"**ignoring {competitor.name} as not similar enough to {role.name} - similarity {similarity}")

        print(f"deactivating role {item.name} of type {item.role_type} for user {item.user.email}")
        item.active = False
        item.updated = timezone.now()
        item.save()
    return HttpResponse("Done")


class AnonUserView(UserCanAdministerMixin, TemplateView):
    '''anonymise user - can only be done if account already marked inactive'''
    template_name = 'django_users/anon_user.html'
    user = None

    def get(self):
        self.user = User.objects.get(id=self.kwargs['pk'])

        if self.user.is_active:
            return HttpResponse("User must be inactive to anonymise")

        return super().get(self.request)

    def get_context_data(self, **kwargs):
        Person = apps.get_model('users.Person')
        Role = apps.get_model('users.Role')
        CommsLog = apps.get_model('users.CommsLog')
        VerificationCode = apps.get_model('users.VerificationCode')

        context = super().get_context_data(**kwargs)
        context['user'] = self.user
        context['person'] = Person.objects.filter(user=self.user)
        context['role'] = Role.objects.filter(user=self.user)
        context['commslog'] = CommsLog.objects.filter(user=self.user)
        context['verification_code'] = VerificationCode.objects.filter(user=self.user)
        context['to_anon'] = ['user', 'person', 'role']
        context['to_delete'] = ['commslog', 'verification_code']
        return context


class UserCountries(UserCanAdministerMixin, TemplateView):
    template_name = "django_users/admin/user_countries.html"


class SubscriptionDataFrameView(TemplateView):
    template_name = 'users/admin/subscribe_list.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Get filtered queryset
        queryset = self.get_filtered_queryset()

        # Create DataFrame from the data
        all_attributes = set()

        # First pass: collect all unique attributes from the JSONField
        for contact in queryset:
            if contact.attributes and isinstance(contact.attributes, dict):
                all_attributes.update(contact.attributes.keys())

        # remove email and city from attributes
        all_attributes.discard('email')
        all_attributes.discard('city')
        all_attributes.discard('mobile')

        context.update({
            'records': queryset,
            'attribute_columns': list(all_attributes),

        })

        return context

    def get_filtered_queryset(self):
        """Get filtered queryset based on request parameters"""
        # Base filter for subscription/interest/form related contacts
        UserContact = apps.get_model('users.UserContact')
        queryset = UserContact.objects.filter(method__icontains='subscribe').select_related('user')

        # Apply filters from request
        method_filter = self.request.GET.get('method')
        site_filter = self.request.GET.get('site')
        date_from = self.request.GET.get('date_from')
        date_to = self.request.GET.get('date_to')

        if method_filter:
            queryset = queryset.filter(method=method_filter)

        if site_filter:
            queryset = queryset.filter(site=site_filter)

        if date_from:
            try:
                from_date = datetime.strptime(date_from, '%Y-%m-%d').date()

            except ValueError:
                # default to last 6 months
                from_date = timezone.now().date() - timezone.timedelta(days=180)

            queryset = queryset.filter(contact_date__date__gte=from_date)

        if date_to:
            try:
                to_date = datetime.strptime(date_to, '%Y-%m-%d').date()

            except ValueError:
                # default to last 6 months
                to_date = timezone.now().date() - timezone.timedelta(days=180)
            queryset = queryset.filter(contact_date__date__lte=to_date)
        return queryset.order_by('-contact_date')

    def normalize_value(self, value):
        """Normalize values for consistent display"""
        if value is None or value == '':
            return ''

        # Handle boolean values directly from JSONField
        if isinstance(value, bool):
            return value

        # Handle string representations of booleans
        if isinstance(value, str):
            lower_val = value.lower().strip()
            if lower_val in ['true', '1', 'yes', 'on', 'checked']:
                return True
            elif lower_val in ['false', '0', 'no', 'off', 'unchecked']:
                return False

        # Handle numeric values
        if isinstance(value, (int, float)):
            if value in [0, 1]:
                return bool(value)
            return value

        return str(value)

    def get_filter_options(self):
        """Get available filter options"""
        # is this used?
        UserContact = apps.get_model('users.UserContact')
        base_queryset = UserContact.objects.filter(
            Q(method__icontains='subscribe') |
            Q(method__icontains='interest') |
            Q(method__icontains='form') |
            Q(method__icontains='newsletter')
        )

        return {
            'methods': list(base_queryset.values_list('method', flat=True).distinct().order_by('method')),
            'sites': list(base_queryset.values_list('site', flat=True).distinct().order_by('site')),
        }


class ConfirmAccount(UserCanAdministerMixin, View):

    def get(self, request, *args, **kwargs):
        user = User.objects.get(id=kwargs['pk'])
        user.confirm(request.user)

        return redirect(reverse('users:admin_user', kwargs={'pk': kwargs['pk']}))


class VerifyMagicLinkView(View):
    """
    Handle verification links sent by email.
    Example URL: /users/verify-email-link/?t=<raw_token>
    """


    def get(self, request, purpose):

        raw_token = request.GET.get("t")
        if not raw_token:
            return HttpResponseBadRequest(_("Missing token"))

        VerificationCode = apps.get_model("users", "VerificationCode")

        # Try to validate and consume the token
        vc = VerificationCode.verify_token(raw_token=raw_token, purpose=purpose)

        if not vc:
            messages.error(request, _("Invalid or expired verification link."))
            return render(request, "django_users/verify_failed.html", status=403)

        # Mark verified — model's verify_token already calls channel.verify()
        channel = vc.channel
        user = vc.user

        # Optionally log the user in (if this is part of a sign-up or login flow)
        auto_login = getattr(settings, "VERIFICATION_AUTO_LOGIN", False)
        if auto_login:
            user.backend = 'django.contrib.auth.backends.ModelBackend'
            login(request, user)
            messages.success(request, _(f"Your link has been verified and you are now logged in."))

            # do we have a next url?
            next = request.GET.get("next", settings.LOGIN_REDIRECT_URL)
            return redirect(next)
        else:
            messages.success(request, _("Your link has been verified."))
            return redirect(settings.LOGIN_URL)




class UserContactBrowse(UserCanAdministerMixin, TemplateView):
    '''this is just looking at the data peole gave when signing up - this should be transferred to the user profile '''

    template_name = "django_users/admin/users/usercontact_list.html"


class SendComms(UserCanAdministerMixin, GoNextTemplateMixin, TemplateView):

    template_name = "django_users/admin/send_comms.html"
    event = None

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        me = self.request.user

        if 'pk' in self.kwargs:
            user = User.objects.get(authentik_id=self.kwargs['pk'])
        elif 'user_id' in self.kwargs:
            user = User.objects.get(pk=self.kwargs['user_id'])
        context['recipient'] = user
        context['recipient_email'] = context['recipient'].email

        # context['templates'] = CommsTemplate.objects.all()
        # hacking together template for now

        template = kwargs.get('template', None)
        context['subject'] = ""
        context['message'] = ""
        if template == 'invite':
            context['subject'] = "Invitation to Skor.ie"
            context['message'] = f'''Dear {user.first_name},\n\nYou have been signed up with Skor.ie by {me.name}.  Your temporary password is {user.activation_code}.  Please log in at {settings.SITE_URL}/login/ and change your password as soon as possible. \nIf this is a mistake please ignore this email and the account will be deleted after 1 week.\n\nBest wishes,\nSkor.ie
            '''





        return context

    def post(self, request, *args, **kwargs):
        recipient = request.POST.get('recipient', None)
        recipient = User.objects.get(pk=recipient)
        subject = request.POST.get('subject', None)
        message = request.POST.get('message', None)

        mail.send(
            recipient.email,
            settings.DEFAULT_FROM_EMAIL,
            subject=subject,
            message=message,
        )

        return HttpResponseRedirect(request.POST.get('next', "/"))


class WhoAmIView(TemplateView):
    template_name = "whoami.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        request = self.request

        session_cookie_name = settings.SESSION_COOKIE_NAME
        csrf_cookie_name = settings.CSRF_COOKIE_NAME

        # Collect all cookie info
        cookies = []
        for name, value in request.COOKIES.items():
            cookies.append({
                "name": name,
                "value": value,
                "is_session_cookie": (name == session_cookie_name),
                "is_csrf_cookie": (name == csrf_cookie_name),
            })

        context.update({
            "authenticated": request.user.is_authenticated,
            "user_id": getattr(request.user, "id", None),
            "username": getattr(request.user, "username", None),

            "host": request.get_host(),
            "scheme": request.scheme,

            "session_cookie_name": session_cookie_name,
            "session_cookie_value": request.COOKIES.get(session_cookie_name),
            "session_key": request.session.session_key,

            "csrf_cookie_name": csrf_cookie_name,
            "csrf_cookie_value": request.COOKIES.get(csrf_cookie_name),
            "csrf_header": request.META.get("HTTP_X_CSRFTOKEN"),

            "origin_header": request.META.get("HTTP_ORIGIN"),
            "referer_header": request.META.get("HTTP_REFERER"),

            "cookies": cookies,
        })

        return context


class ResetSessionView(TemplateView):
    """
    GET  -> show explanation + button
    POST -> clear all cookies + session, then redirect user to login
    """
    template_name = "django_users/session_reset.html"

    def post(self, request, *args, **kwargs):
        # Log out and flush the session
        logger.warning(f"Resetting session for user {request.user.email}")
        logout(request)
        request.session.flush()

        next_url = request.POST.get("next") or "/"
        login_url = reverse(settings.LOGIN_URL)
        response = HttpResponseRedirect(
            f"{login_url}?next={next_url}"
        )


        # Delete *every* cookie we see, under every relevant domain

        for name in list(request.COOKIES.keys()):
            for domain in [None, ".skor.ie", request.get_host(), "skor.ie", "ride.skor.ie"]:
                response.delete_cookie(name, domain=domain, path="/")

        # Debug: what is Django actually telling the browser?
        # can't seem to shift sessionid
        for name, morsel in response.cookies.items():
            if name.lower() == "sessionid":
                logger.warning("Set-Cookie for %s -> %s", name, morsel.OutputString())

        return response

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["next"] = self.request.GET.get("next", "/")
        return context


# ---------------------------------------------------------------------------
# Admin invite + accept (lifted from skorie4 HD-0005)
# ---------------------------------------------------------------------------

class AdminInviteView(LoginRequiredMixin, UserCanAdministerMixin, TemplateView):
    """Admin adds a user via invitation (magic link) or admin-attested OTP.

    Two POST submit buttons (``submit_invite``, ``submit_otp``) pick the
    delivery method. Duplicate-email submissions re-render the same form
    with an "existing user" banner and two alternative actions
    (``submit_add_existing`` to run the post-create hook against the
    existing user, ``submit_otp_existing`` to send an OTP for login).
    """

    template_name = 'django_users/admin/admin_invite.html'

    def get_form_class(self):
        from .forms import get_invite_form_class
        return get_invite_form_class()

    def _render_form(self, form, extra=None):
        ctx = {
            'form': form,
            'next': self.request.POST.get('next') or self.request.GET.get('next', '/'),
        }
        if extra:
            ctx.update(extra)
        return self.render_to_response(ctx)

    def get(self, request, *args, **kwargs):
        FormClass = self.get_form_class()
        form = FormClass(request_user=request.user, initial=request.GET.dict())
        return self._render_form(form)

    def _delivery_from_post(self, request, form):
        if 'submit_invite' in request.POST:
            return 'invite'
        if 'submit_otp' in request.POST:
            return 'otp'
        # Fall back to whatever the form's delivery_method field carries.
        return form.cleaned_data.get('delivery_method') or None

    def _existing_action(self, request):
        if 'submit_add_existing' in request.POST:
            return 'add'
        if 'submit_otp_existing' in request.POST:
            return 'otp'
        return None

    def _split_extra(self, cleaned: dict, base_field_names: set) -> tuple[dict, dict]:
        """Split cleaned form data into core (used by services) and extra
        (project-specific, written into Invite.extra and passed to the
        post-create hook)."""
        core_keys = {'email', 'first_name', 'last_name', 'mobile',
                     'delivery_method', 'personal_note'}
        core = {k: v for k, v in cleaned.items() if k in core_keys}
        extra = {k: v for k, v in cleaned.items() if k not in core_keys}
        return core, extra

    def get_success_redirect(self, user):
        # Override in subclasses to redirect somewhere project-specific.
        return redirect('users:admin_user', pk=user.pk)

    def post(self, request, *args, **kwargs):
        from .services import (
            create_user_with_invite, send_otp_email, get_invite_model,
        )

        FormClass = self.get_form_class()
        form = FormClass(request.POST, request_user=request.user)
        if not form.is_valid():
            return self._render_form(form)

        cleaned = form.cleaned_data
        email = cleaned['email']
        UserModel = get_user_model()
        existing = UserModel.objects.filter(email__iexact=email).first()

        delivery = self._delivery_from_post(request, form)
        existing_action = self._existing_action(request)

        # Duplicate email — re-render with the choice banner.
        if existing and not existing_action:
            return self._render_form(form, extra={'existing_user': existing})

        # Existing user: run the post-create hook against the existing user.
        if existing and existing_action == 'add':
            from django.utils.module_loading import import_string
            from .services import _jsonify
            dotted = getattr(settings, 'INVITE_POST_CREATE', None)
            if dotted:
                hook = import_string(dotted)
                Invite = get_invite_model()
                pseudo_invite = Invite(
                    email=existing.email,
                    first_name=existing.first_name or '',
                    last_name=existing.last_name or '',
                    delivery_method=Invite.DELIVERY_LINK,
                    expires_at=timezone.now() + timedelta(days=1),
                    created_by=request.user,
                    user=existing,
                    extra=_jsonify(dict(cleaned)),
                )
                hook(existing, pseudo_invite, dict(cleaned))
            messages.success(
                request, _("Added %(email)s to the selected scope.") % {'email': existing.email},
            )
            return self.get_success_redirect(existing)

        # Existing user: just send an OTP so they can log in.
        if existing and existing_action == 'otp':
            Invite = get_invite_model()
            invite = Invite.objects.create(
                email=existing.email,
                first_name=existing.first_name or '',
                last_name=existing.last_name or '',
                delivery_method=Invite.DELIVERY_OTP,
                expires_at=timezone.now() + timedelta(
                    hours=getattr(settings, 'OTP_EXPIRY_HOURS', 24),
                ),
                created_by=request.user,
                user=existing,
            )
            send_otp_email(
                invite, personal_note=cleaned.get('personal_note', ''),
                mark_channel_verified=False,
            )
            invite.mark_sent()
            messages.success(
                request, _("Sent login OTP to %(email)s.") % {'email': existing.email},
            )
            return self.get_success_redirect(existing)

        # New user path.
        if not delivery:
            messages.error(request, _("Pick Invite or Approve & Send OTP."))
            return self._render_form(form)

        delivery_method = (
            'link' if delivery == 'invite' else 'otp'
        )
        core, extra = self._split_extra(cleaned, set())
        new_user, invite = create_user_with_invite(
            actor=request.user,
            email=core['email'],
            first_name=core.get('first_name', ''),
            last_name=core.get('last_name', ''),
            mobile=core.get('mobile', ''),
            delivery_method=delivery_method,
            extra=extra,
            personal_note=core.get('personal_note', ''),
        )
        if delivery_method == 'link':
            messages.success(request, _("Invitation sent to %(email)s.") % {'email': new_user.email})
        else:
            messages.success(
                request,
                _("Created %(email)s and sent login OTP (email pre-approved).") % {'email': new_user.email},
            )
        return self.get_success_redirect(new_user)


class AcceptInvite(View):
    """Magic-link landing: verify the token, log the user in, forward them
    to the project's onboarding flow (change_password → tell_us_about by
    default)."""

    template_name = 'django_users/accept_invite.html'

    def get(self, request, token, *args, **kwargs):
        from .services import _get_verification_code_model
        VerificationCode = _get_verification_code_model()

        vc = VerificationCode.verify_token(raw_token=token, purpose='invite')
        if vc is None:
            return render(request, self.template_name, {'ok': False})

        user = vc.user

        # Mark any matching open Invite as accepted.
        from .services import get_invite_model
        Invite = get_invite_model()
        Invite.objects.filter(user=user, accepted_at__isnull=True).update(
            accepted_at=timezone.now(),
        )

        if hasattr(user, 'is_confirmed') and not user.is_confirmed:
            if hasattr(user, 'confirm') and callable(user.confirm):
                user.confirm()

        backend = settings.AUTHENTICATION_BACKENDS[0]
        login(request, user, backend=backend)

        next_url = (
            reverse('users:change_password')
            + '?next=' + reverse('users:tell_us_about')
        )
        return redirect(next_url)


class EnterOTP(TemplateView):
    """OTP landing for users invited via the Approve & Send OTP path."""

    template_name = 'django_users/enter_otp.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.setdefault('email', self.request.GET.get('email', ''))
        return context

    def post(self, request, *args, **kwargs):
        from .services import (
            _get_comms_channel_model, _get_verification_code_model,
            get_invite_model,
        )

        email = (request.POST.get('email') or '').strip().lower()
        code = (request.POST.get('code') or '').strip()

        UserModel = get_user_model()
        user = UserModel.objects.filter(email__iexact=email).first()
        Channel = _get_comms_channel_model()
        VerificationCode = _get_verification_code_model()

        channel = None
        if user and (user.email or '').lower() == (email or '').lower():
            channel = user.comms_channels.filter(
                channel_type=Channel.CHANNEL_EMAIL,
            ).first()

        if not user or not channel or not VerificationCode.verify_code(
            user=user, channel=channel, code=code, purpose='invite',
        ):
            return self.render_to_response({
                'email': email,
                'error': _("Invalid or expired code. Check the email and try again."),
            })

        Invite = get_invite_model()
        Invite.objects.filter(user=user, accepted_at__isnull=True).update(
            accepted_at=timezone.now(),
        )
        if hasattr(user, 'is_confirmed') and not user.is_confirmed:
            if hasattr(user, 'confirm') and callable(user.confirm):
                user.confirm()

        backend = settings.AUTHENTICATION_BACKENDS[0]
        login(request, user, backend=backend)

        next_url = (
            reverse('users:change_password')
            + '?next=' + reverse('users:tell_us_about')
        )
        return redirect(next_url)


# ---- Admin: edit contact + manage comms channels on behalf of a user ----
#
# These views power the per-user admin pages (typically reached from the
# ManageUser / admin_user page). They follow the two-layer verification model
# documented on CommsChannelBase: address ownership lives on User; channel
# opt-in lives on CommsChannel.

def _get_admin_target_user(pk):
    """Resolve admin URL pk to a user, accepting either authentik_id (UUID)
    or Django pk (int)."""
    try:
        return User.objects.get(authentik_id=pk)
    except (User.DoesNotExist, ValueError):
        return User.objects.get(pk=pk)


class AdminEditContact(UserCanAdministerMixin, UpdateView):
    """Admin updates a user's email and/or mobile. ``User.save()`` does
    the cascade — clears ``User.{email,mobile}_verified_at`` and the
    matching ``CommsChannel.verified_at`` when an address changes — so
    this view does not duplicate that work."""

    model = User
    form_class = AdminEditContactForm
    template_name = 'django_users/admin/edit_contact.html'

    def get_object(self, queryset=None):
        return _get_admin_target_user(self.kwargs['pk'])

    def get_success_url(self):
        return reverse('users:admin_user', kwargs={'pk': self.object.pk})

    @transaction.atomic
    def form_valid(self, form):
        original = User.objects.get(pk=form.instance.pk)
        new_email = form.cleaned_data['email']
        new_mobile_obj = form.cleaned_data.get('mobile') or ''
        new_mobile = str(new_mobile_obj) if new_mobile_obj else ''

        email_changed = (original.email or '') != new_email
        mobile_changed = (original.mobile or '') != new_mobile

        # User.save() handles the cascade (see CommsChannelBase docstring).
        response = super().form_valid(form)

        if email_changed and hasattr(self.object, 'change_names_email'):
            self.object.change_names_email()

        if email_changed:
            messages.warning(
                self.request,
                f"Email changed to {self.object.email}. The user must re-verify before it counts as confirmed.",
            )
            if self.object.authentik_id:
                messages.error(
                    self.request,
                    f"This user logs in via Authentik. They will keep logging in with the OLD email "
                    f"until it is changed in Authentik too — the change here was not pushed to the IdP.",
                )
        if mobile_changed:
            messages.warning(
                self.request,
                f"Mobile changed to {self.object.mobile}. The user must re-verify SMS/WhatsApp.",
            )
        if not (email_changed or mobile_changed):
            messages.info(self.request, "No changes made.")

        return response


class AdminAddChannel(UserCanAdministerMixin, FormView):
    """Admin opts a target user into a CommsChannel; row created unverified."""

    form_class = AdminAddChannelForm
    template_name = 'django_users/admin/add_channel.html'

    def dispatch(self, request, *args, **kwargs):
        self.target_user = _get_admin_target_user(kwargs['pk'])
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.target_user
        return kwargs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['object'] = self.target_user
        return context

    def get_success_url(self):
        return reverse('users:admin_user', kwargs={'pk': self.target_user.pk})

    def form_valid(self, form):
        CommsChannel = apps.get_model('users', 'CommsChannel')
        channel_type = form.cleaned_data['channel_type']
        channel, created = CommsChannel.objects.get_or_create(
            user=self.target_user, channel_type=channel_type,
        )
        if created:
            messages.success(
                self.request,
                f"{channel.get_channel_type_display()} channel added. The user must opt in / verify before it counts as active.",
            )
        else:
            messages.info(
                self.request,
                f"{channel.get_channel_type_display()} channel already existed — no change.",
            )
        return HttpResponseRedirect(self.get_success_url())


class AdminDeleteChannel(UserCanAdministerMixin, View):
    """Admin removes a comms channel (hard delete; re-opt-in creates a fresh row)."""

    def post(self, request, pk, channel_pk):
        CommsChannel = apps.get_model('users', 'CommsChannel')
        target = _get_admin_target_user(pk)
        try:
            channel = CommsChannel.objects.get(pk=channel_pk, user=target)
        except CommsChannel.DoesNotExist:
            messages.error(request, "Channel not found for this user.")
            return redirect(reverse('users:admin_user', kwargs={'pk': target.pk}))

        if channel.channel_type == CommsChannel.CHANNEL_EMAIL:
            messages.error(
                request,
                "Email channel cannot be removed here — it is the canonical contact channel for the account.",
            )
            return redirect(reverse('users:admin_user', kwargs={'pk': target.pk}))

        channel_label = channel.get_channel_type_display()
        if target.preferred_channel_id == channel.pk:
            target.preferred_channel = None
            target.quick_save(update_fields=['preferred_channel'])
        channel.delete()
        messages.success(request, f"{channel_label} channel removed.")
        return redirect(reverse('users:admin_user', kwargs={'pk': target.pk}))


class AdminSendChannelVerification(UserCanAdministerMixin, View):
    """Admin triggers the verification round-trip for a user's channel."""

    def post(self, request, pk, channel_pk):
        CommsChannel = apps.get_model('users', 'CommsChannel')
        VerificationCode = apps.get_model('users', 'VerificationCode')
        target = _get_admin_target_user(pk)
        try:
            channel = CommsChannel.objects.get(pk=channel_pk, user=target)
        except CommsChannel.DoesNotExist:
            messages.error(request, "Channel not found for this user.")
            return redirect(reverse('users:admin_user', kwargs={'pk': target.pk}))

        if channel.is_verified:
            messages.info(request, f"{channel.get_channel_type_display()} channel is already verified.")
            return redirect(reverse('users:admin_user', kwargs={'pk': target.pk}))

        try:
            vc, context = VerificationCode.create_for_code(
                user=target, channel=channel, purpose='email_verify',
            )
            sent = vc.send_verification(context, 'email_verify')
        except Exception as exc:
            logger.exception("Failed to send channel verification")
            messages.error(request, f"Could not send verification: {exc}")
            return redirect(reverse('users:admin_user', kwargs={'pk': target.pk}))

        if sent:
            destination = target.email if channel.channel_type == 'email' else target.mobile
            messages.success(
                request,
                f"Verification sent to {destination} via {channel.get_channel_type_display()}.",
            )
        else:
            messages.error(
                request,
                f"Failed to send verification via {channel.get_channel_type_display()}.",
            )
        return redirect(reverse('users:admin_user', kwargs={'pk': target.pk}))


class AdminMarkChannelVerified(UserCanAdministerMixin, View):
    """Admin attests a channel is verified out-of-band; stamps verified_at
    via ``channel.verify()`` (which also dual-stamps the User-level field)."""

    def post(self, request, pk, channel_pk):
        CommsChannel = apps.get_model('users', 'CommsChannel')
        target = _get_admin_target_user(pk)
        try:
            channel = CommsChannel.objects.get(pk=channel_pk, user=target)
        except CommsChannel.DoesNotExist:
            messages.error(request, "Channel not found for this user.")
            return redirect(reverse('users:admin_user', kwargs={'pk': target.pk}))

        if channel.is_verified:
            messages.info(request, f"{channel.get_channel_type_display()} channel was already verified.")
            return redirect(reverse('users:admin_user', kwargs={'pk': target.pk}))

        channel.verify()
        messages.success(
            request,
            f"{channel.get_channel_type_display()} channel marked verified by {request.user.email}.",
        )
        return redirect(reverse('users:admin_user', kwargs={'pk': target.pk}))
