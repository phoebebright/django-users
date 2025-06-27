import random
import string

from django import forms
from django.apps import apps
from django.contrib.auth import password_validation
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.forms import ModelForm, Form
from django.forms.widgets import HiddenInput
from django.utils.translation import gettext_lazy as _
from django_countries.fields import CountryField
from phonenumber_field.formfields import PhoneNumberField





class SubscribeForm(forms.Form):
    '''
    '''
    # subscribe = forms.CharField(widget=forms.HiddenInput())
    subscribe = forms.BooleanField(initial=False, required=False)
    country = CountryField().formfield(required=False)
    city = forms.CharField(max_length=50,  label=_("Nearest City or Town"), required=False)
    where_did_you_hear = forms.CharField(max_length=60, label=_(
        "Where did you hear about us? (Please name any organisation, magazines or websites)"), help_text=_(
        "It really helps us if you tell us the full names of how you found us!"), required=False)

    # mobile =  forms.CharField(max_length=20,  label=_("Mobile Number"), required=False)
    # whatsapp = forms.BooleanField(required=False, label="Whatsapp - Only for Events you are attending or for support")
    # current_level = forms.ChoiceField(choices=User.LEVEL_CHOICES, required=False)

class EmailForm(forms.Form):
    recipient_email = forms.EmailField(label='Recipient\'s Email')
    subject = forms.CharField(label='Subject', max_length=100)
    message = forms.CharField(label='Message', widget=forms.Textarea)

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop('request', None)
        super(EmailForm, self).__init__(*args, **kwargs)

class ProfileForm(Form):
    country = CountryField().formfield()
    city = forms.CharField(
        widget=forms.TextInput(attrs={'class': 'update'}),
        max_length=50,  label=_("Nearest City or Town"))

    where_did_you_hear = forms.CharField(max_length=60,  label=_("Where did you hear about us? (Please name any organisation, magazines or websites)"), help_text=_("It really helps us if you tell us the full names of how you found us!"))
    # mobile =  forms.CharField(max_length=20,  label=_("Mobile Number"),
    #                           help_text=_("Optional - Only for Events you are participating in or for support"),
    # required=False)
    # whatsapp = forms.BooleanField(required=False, label="Whatsapp - Only for Events you are participating in or for support")

class UserMigrationForm(forms.Form):
    email = forms.EmailField(label="Email")
    password = forms.CharField(label="Password", widget=forms.PasswordInput)

class VerificationCodeForm(forms.Form):
    code = forms.CharField(max_length=6, required=True, label=_('Verification Code'))
    channel = forms.UUIDField(widget=forms.HiddenInput(), required=False)

class SignUpForm(forms.Form):

        first_name = forms.CharField(max_length=30, required=True, label=_('First Name'))
        last_name = forms.CharField(max_length=30, required=True, label=_('Last Name'))
        email = forms.EmailField(max_length=254, required=True, label=_('Email Address'))
        mobile = PhoneNumberField(required=False, label=_('Phone Number (for SMS/WhatsApp)'))
        password = forms.CharField(label="Password", widget=forms.PasswordInput)
        preferred_channel = None  # Placeholder for the preferred_channel field

        def __init__(self, *args, **kwargs):
            # Attempt to resolve the CommsChannel model dynamically
            comms_channel_model = apps.get_model('users', 'CommsChannel', require_ready=False)

            super().__init__(*args, **kwargs)

            # Set up the preferred_channel field only if CommsChannel is available
            if comms_channel_model:
                self.fields['preferred_channel'] = forms.ChoiceField(
                    choices=comms_channel_model.CHANNEL_CHOICES,
                    initial='email',
                    label=_('Preferred Communication Channel'),
                    widget=forms.RadioSelect
                )

        def clean_password(self):
            password = self.cleaned_data.get('password')
            try:
                validate_password(password)
            except ValidationError as e:
                raise forms.ValidationError(e.messages)
            return password

        def clean(self):
            cleaned_data = super().clean()
            preferred_channel = cleaned_data.get('preferred_channel')
            mobile = cleaned_data.get('mobile')

            if preferred_channel in ['sms', 'whatsapp'] and not mobile:
                raise forms.ValidationError(_('Phone number is required for SMS or WhatsApp verification.'))

            return cleaned_data


class ForgotPasswordForm(forms.Form):
    email = forms.EmailField(label=_('Email Address'), required=False)
    channel = forms.ChoiceField(label=_('Channel to use'), required=False)
    verification_code = forms.CharField(label=_('Verification Code'), required=False)    # verifications codes are for verifying comms channels NOT for activing the user account
    new_password = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'New Password'}),
        label="New Password",
        required=False
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'Confirm Password'}),
        label="Confirm Password",
        required=False
    )

    def __init__(self, *args, **kwargs):
        # Get the step from kwargs and remove it to avoid errors in parent init
        step = kwargs.pop('step', 1)
        user = kwargs.pop('user', None)  # Optional user to populate channels in step 2
        super().__init__(*args, **kwargs)

        required_fields = {}
        # Set the fields required for the current step
        if step >= 1:
            # Step 1: Only the email field is required and visible
            required_fields['email'] = self.fields['email']
            required_fields['email'].required = True


        if step >= 2 and user:
            # Step 2: Show channel choices based on verified channels
            required_fields['channel'] = self.fields['channel']
            required_fields['channel'].required = True

            # Was going to allow only verified channels but if they receive the message then that
            # effectively verifies the channel so gong to allow all


            required_fields['channel'].choices = [
                (channel.id, f"{channel.channel_type}: {channel.value}")
                for channel in user.comms_channels.all()
            ]

        if step >= 3:
            # Step 3: Only the verification code field is required and visible

            required_fields['verification_code'] = self.fields['verification_code']
            required_fields['verification_code'].required = True

        if step >= 4:
            # Step 4: Show new password and confirm password fields
            required_fields['new_password'] = self.fields['new_password']
            required_fields['confirm_password'] = self.fields['confirm_password']
            required_fields['new_password'].required = True
            required_fields['confirm_password'].required = True


        self.fields = required_fields

    def clean(self):
        # Additional validation logic based on the step (e.g., password match in Step 4)
        cleaned_data = super().clean()
        if 'new_password' in self.fields and 'confirm_password' in self.fields:
            new_password = cleaned_data.get("new_password")
            confirm_password = cleaned_data.get("confirm_password")
            if new_password and confirm_password and new_password != confirm_password:
                self.add_error('confirm_password', _('Passwords do not match.'))
        return cleaned_data

class ChangePasswordNowCurrentForm(forms.Form):

    new_password = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'New Password'}),
        label="New Password",
        required=True
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'Confirm Password'}),
        label="Confirm Password",
        required=True
    )

    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get("new_password")
        confirm_password = cleaned_data.get("confirm_password")

        if new_password and confirm_password and new_password != confirm_password:
            raise ValidationError("New password and confirm password do not match.")

        return cleaned_data


class ChangePasswordForm(forms.Form):
    current_password = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'Current Password'}),
        label="Current Password",
        required=True
    )
    new_password = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'New Password'}),
        label="New Password",
        required=True
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'Confirm Password'}),
        label="Confirm Password",
        required=True
    )

    def clean(self):
        cleaned_data = super().clean()
        current_password = cleaned_data.get("current_password")
        new_password = cleaned_data.get("new_password")
        confirm_password = cleaned_data.get("confirm_password")

        if new_password and confirm_password and new_password != confirm_password:
            raise ValidationError("New password and confirm password do not match.")


        return cleaned_data


class ProfileForm(Form):
    country = CountryField().formfield()
    city = forms.CharField(
        widget=forms.TextInput(attrs={'class': 'update'}),
        max_length=50,  label=_("Nearest City or Town"))

    where_did_you_hear = forms.CharField(max_length=60,  label=_("Where did you hear about us? (Please name any organisation, magazines or websites)"), help_text=_("It really helps us if you tell us the full names of how you found us!"))
    mobile =  forms.CharField(max_length=20,  label=_("Mobile Number"),
                              help_text=_("Optional - Only for Events you are participating in or for support"),
    required=False)
    whatsapp = forms.BooleanField(required=False, label="Whatsapp - Only for Events you are participating in or for support")

class CustomUserCreationFormBase(ModelForm):
    #email = forms.HiddenInput() not working
    #username = forms.HiddenInput()
    password = forms.CharField(
        label=_("Temporary Password"),
        strip=False,
        help_text=_("Suggested temporary password."),
    )

    class Meta:
        model = None
        fields = ( "email", "first_name","last_name")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['first_name'] = forms.CharField(required=True)
        self.fields['last_name'] = forms.CharField(required=True)
        self.fields['mobile'] = PhoneNumberField(required=False)
        self.fields['first_name'].widget.attrs.update({'class': 'update'})
        self.fields['last_name'].widget.attrs.update({'class': 'update'})
        self.fields['mobile'].widget.attrs.update({'class': 'update'})

        random_number = random.randint(100000, 999999)
        random_letter = random.choice(string.ascii_uppercase)
        self.fields['password'].initial  = f"{str(random_number)[:3]}{random_letter}{str(random_number)[3:]}"


    def clean(self):
        return super().clean()


    def save(self, commit=True):
        return super().save(commit=commit)

class OrganisationFormBase(ModelForm):
    class Meta:
        model = None
        fields = '__all__'

class CommsChannelFormBase(forms.ModelForm):
    email = forms.EmailField(label=_('Email'), required=False)
    mobile = PhoneNumberField(label=_('Mobile Number'), required=False)
    class Meta:
        model = None
        fields = ['channel_type', 'email', 'mobile']

class AddCommsChannelFormBase(forms.ModelForm):
    email = forms.EmailField(label=_('Email'), required=False)
    mobile = PhoneNumberField(label=_('Mobile Number'), required=False)
    # need to review why I put this in, but likely to trace same call between steps.  Where should it be set?
    username_code = forms.CharField(widget=HiddenInput(), required=False)

    class Meta:
        model = None
        fields = ['channel_type', 'email', 'mobile']

    def clean(self):
        cleaned_data = super().clean()
        email = cleaned_data.get('email')
        mobile = cleaned_data.get('mobile')

        # Validate that at least one of email or mobile is provided
        if not email and not mobile:
            raise ValidationError(_('You must provide either an email or a mobile number.'))

        return cleaned_data

class ContactFormBase(Form):


    email = forms.EmailField()
    message = forms.CharField( widget=forms.Textarea(attrs={'cols': 80, 'rows': 20}) )
    passed = forms.CharField(widget=forms.HiddenInput())


class PersonFormBase(forms.ModelForm):
    """Form for creating and updating a Person instance."""


    class Meta:
        model = None
        fields = ['formal_name', 'friendly_name', 'sortable_name']


class SupportTicketFormBase(forms.ModelForm):


    class Meta:
        model = None
        fields = ['title', 'notes', 'priority', 'site']
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Brief description of your issue',
                'required': True
            }),
            'notes': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 6,
                'placeholder': 'Please provide detailed information about your issue...',
                'required': True
            }),
            'priority': forms.Select(attrs={
                'class': 'form-control'
            }),
            'site': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Site or location (optional)'
            })
        }

    def clean_title(self):
        title = self.cleaned_data.get('title', '').strip()
        if len(title) < 5:
            raise forms.ValidationError("Title must be at least 5 characters long.")
        return title

    def clean_notes(self):
        notes = self.cleaned_data.get('notes', '').strip()
        if len(notes) < 20:
            raise forms.ValidationError("Please provide more detailed information (at least 20 characters).")
        return notes


class SubscriptionPreferencesForm(forms.ModelForm):
    """Form for managing user subscription preferences"""

    # Custom boolean fields for easier UI management
    subscribe_to_news = forms.BooleanField(
        required=False,
        label="General News & Updates",
        help_text="Receive news about the platform, new features, and general announcements",
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )

    subscribe_to_events = forms.BooleanField(
        required=False,
        label="All Event Updates",
        help_text="Receive updates about all events - openings, deadlines, results",
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )

    subscribe_to_myevents = forms.BooleanField(
        required=False,
        label="My Events Only",
        help_text="Only receive updates for events you've entered",
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )

    class Meta:
        model = None
        fields = []  # We'll handle the subscription fields manually

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance:
            # Set initial values based on current subscription status
            self.fields['subscribe_to_news'].initial = self.instance.is_subscribed_news
            self.fields['subscribe_to_events'].initial = self.instance.is_subscribed_events
            self.fields['subscribe_to_myevents'].initial = self.instance.is_subscribed_myevents

    def save(self, commit=True):
        user = super().save(commit=False)

        # Handle subscription changes
        if self.cleaned_data['subscribe_to_news'] != user.is_subscribed_news:
            if self.cleaned_data['subscribe_to_news']:
                user.subscribe_to('news')
            else:
                user.unsubscribe_from('news')

        if self.cleaned_data['subscribe_to_events'] != user.is_subscribed_events:
            if self.cleaned_data['subscribe_to_events']:
                user.subscribe_to('events')
            else:
                user.unsubscribe_from('events')

        if self.cleaned_data['subscribe_to_myevents'] != user.is_subscribed_myevents:
            if self.cleaned_data['subscribe_to_myevents']:
                user.subscribe_to('myevents')
            else:
                user.unsubscribe_from('myevents')

        if commit:
            user.save()

        return user
