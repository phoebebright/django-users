import random
from django import forms
from django.contrib.auth import password_validation
from django.contrib.auth.forms import UserCreationForm
from django.forms import ModelForm, Form
from django.utils.translation import gettext_lazy as _
from django_countries.fields import CountryField

from users.models import CustomUser as User, Organisation


class CustomUserCreationForm(ModelForm):
    #email = forms.HiddenInput() not working
    #username = forms.HiddenInput()
    password = forms.CharField(
        label=_("Temporary Password"),
        strip=False,
        help_text=_("Space is for readability - there is no space in the password.  User will be asked to change their password on first login."),
    )

    class Meta:
        model = User
        fields = ( "email", "first_name","last_name","mobile","whatsapp")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['first_name'] = forms.CharField(required=True)
        self.fields['last_name'] = forms.CharField(required=True)
        self.fields['first_name'].widget.attrs.update({'class': 'update'})
        self.fields['last_name'].widget.attrs.update({'class': 'update'})
        self.fields['mobile'].widget.attrs.update({'class': 'update'})
        self.fields['whatsapp'].widget.attrs.update({'class': 'update'})


        random_number = random.randint(100000, 999999)
        self.fields['password'].initial  = f"{str(random_number)[:3]} {str(random_number)[3:]}"


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

    mobile =  forms.CharField(max_length=20,  label=_("Mobile Number"), required=False)
    whatsapp = forms.BooleanField(required=False, label="Whatsapp - Only for Events you are attending or for support")
    # current_level = forms.ChoiceField(choices=User.LEVEL_CHOICES, required=False)

class EmailForm(forms.Form):
    recipient_email = forms.EmailField(label='Recipient\'s Email')
    subject = forms.CharField(label='Subject', max_length=100)
    message = forms.CharField(label='Message', widget=forms.Textarea)

    # def __init__(self, *args, **kwargs):
    #     self.request = kwargs.pop('request', None)
    #     super(EmailForm, self).__init__(*args, **kwargs)

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

class UserMigrationForm(forms.Form):
    email = forms.EmailField(label="Email")
    password = forms.CharField(label="Password", widget=forms.PasswordInput)
