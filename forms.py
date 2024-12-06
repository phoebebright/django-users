import random
import string

from django import forms
from django.contrib.auth import password_validation
from django.contrib.auth.forms import UserCreationForm
from django.core.exceptions import ValidationError
from django.forms import ModelForm, Form
from django.forms.widgets import HiddenInput
from django.utils.translation import gettext_lazy as _
from django_countries.fields import CountryField
from phonenumber_field.formfields import PhoneNumberField

from users.models import CustomUser, Organisation, CommsChannel


class CustomUserCreationForm(ModelForm):
    #email = forms.HiddenInput() not working
    #username = forms.HiddenInput()
    password = forms.CharField(
        label=_("Temporary Password"),
        strip=False,
        help_text=_("Suggested temporary password."),
    )

    class Meta:
        model = CustomUser
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

class OrganisationForm(ModelForm):
    class Meta:
        model = Organisation
        fields = '__all__'


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
    LEVEL_CHOICES = (
        ('trainee_judge', 'Trainee Judge'),
        ('list6', 'List 6'),
        ('list5', 'List 5'),
        ('list4', 'List 4'),
        ('list3', 'List 3'),
        ('list3a', 'List 3a'),
        ('list2', 'List 2'),
        ('list2a', 'List 2a'),
        ('list1', 'List 1'),
    )
    COUNTY_CHOICES = [
        ('Antrim', 'Antrim'),
        ('Armagh', 'Armagh'),
        ('Carlow', 'Carlow'),
        ('Cavan', 'Cavan'),
        ('Clare', 'Clare'),
        ('Cork', 'Cork'),
        ('Donegal', 'Donegal'),
        ('Down', 'Down'),
        ('Dublin', 'Dublin'),
        ('Fermanagh', 'Fermanagh'),
        ('Galway', 'Galway'),
        ('Kerry', 'Kerry'),
        ('Kildare', 'Kildare'),
        ('Kilkenny', 'Kilkenny'),
        ('Laois', 'Laois'),
        ('Leitrim', 'Leitrim'),
        ('Limerick', 'Limerick'),
        ('Londonderry', 'Londonderry'),
        ('Longford', 'Longford'),
        ('Louth', 'Louth'),
        ('Mayo', 'Mayo'),
        ('Meath', 'Meath'),
        ('Monaghan', 'Monaghan'),
        ('Offaly', 'Offaly'),
        ('Roscommon', 'Roscommon'),
        ('Sligo', 'Sligo'),
        ('Tipperary', 'Tipperary'),

        ('Tyrone', 'Tyrone'),
        ('Waterford', 'Waterford'),
        ('Westmeath', 'Westmeath'),
        ('Wexford', 'Wexford'),
        ('Wicklow', 'Wicklow'),

    ]
    username = forms.HiddenInput()
    county = forms.ChoiceField(choices=COUNTY_CHOICES, required=False)
    level = forms.ChoiceField(choices=LEVEL_CHOICES, required=False)


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
        channel_type = forms.ChoiceField(
            choices=CommsChannel.CHANNEL_CHOICES,
            initial='email',
            label=_('Preferred Communication Channel'),
            widget=forms.RadioSelect
        )



        def clean(self):
            cleaned_data = super().clean()
            channel_type = cleaned_data.get('channel_type')
            mobile = cleaned_data.get('mobile')

            if channel_type in ['sms', 'whatsapp'] and not mobile:
                raise forms.ValidationError(_('Phone number is required for SMS or WhatsApp verification.'))

            return cleaned_data

class CommsChannelForm(forms.ModelForm):
    email = forms.EmailField(label=_('Email'), required=False)
    mobile = PhoneNumberField(label=_('Mobile Number'), required=False)
    class Meta:
        model = CommsChannel
        fields = ['channel_type', 'email', 'mobile']





class AddCommsChannelForm(forms.ModelForm):
    email = forms.EmailField(label=_('Email'), required=False)
    mobile = PhoneNumberField(label=_('Mobile Number'), required=False)
    username_code = forms.CharField(widget=HiddenInput(), required=False)

    class Meta:
        model = CommsChannel
        fields = ['channel_type', 'email', 'mobile']


class ForgotPasswordForm(forms.Form):
    email = forms.EmailField(label=_('Email Address'), required=False)
    channel = forms.ChoiceField(label=_('Channel to use'), required=False)
    verification_code = forms.CharField(label=_('Verification Code'), required=False)
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

            # Populate the choices with user's verified channels
            verified_channels = user.comms_channels.filter(verified_at__isnull=False)
            required_fields['channel'].choices = [
                (channel.id, f"{channel.channel_type}: {channel.email or channel.mobile}")
                for channel in verified_channels
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


class ChangePasswordForm(ChangePasswordNowCurrentForm):
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
