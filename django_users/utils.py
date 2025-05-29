from django.core import signing
from django.core.mail import send_mail
from django.utils import timezone
from post_office import mail
from django.template.loader import render_to_string
from django.conf import settings
from twilio.rest import Client
from django.utils.translation import gettext_lazy as _
from django.urls import reverse_lazy, reverse

def send_otp(channel, code):
    subject = _('Your One Time Password')
    message = f'Here is your One Time Password: {code} to login to {settings.SITE_NAME}.  You will be asked to enter a new password when you log in.  Login link {settings.SITE_URL}{reverse(settings.LOGIN_URL)}'
    html_message = message
    mail.send(
        channel.value,
        settings.DEFAULT_FROM_EMAIL,
        subject=subject,
        message=message,
        html_message=html_message
    )
    return True

def send_email_verification_code(verificationcode):
    subject = _('Your Verification Code')
    message = render_to_string('registration/email_verification_code.txt', {'code': verificationcode.code})
    html_message = render_to_string('registration/email_verification_code.html', {'code': verificationcode.code})
    mail.send(
        verificationcode.channel.value,
        settings.DEFAULT_FROM_EMAIL,
        subject=subject,
        message=message,
        html_message=html_message
    )
    return True

def send_sms_verification_code(phone_number, code):
    client = Client(settings.TWILIO_ACCOUNT_ID, settings.TWILIO_AUTH_TOKEN)
    message = _('Your verification code is: {code}').format(code=code)
    client.messages.create(
        body=message,
        from_=settings.TWILIO_PHONE_NUMBER,
        to=str(phone_number)
    )
    return True

def send_whatsapp_verification_code(phone_number, code):
    client = Client(settings.TWILIO_ACCOUNT_ID, settings.TWILIO_AUTH_TOKEN)
    message = _('Your verification code is: {code}').format(code=code)
    client.messages.create(
        body=message,
        from_='whatsapp:' + settings.TWILIO_WHATSAPP_NUMBER,
        to='whatsapp:' + str(phone_number)
    )
    return True



def generate_login_token(user, next='/', key=None):
    '''create a token to login to same app on another device (no key needed)
    or on aa related system (key needed that is shared by both apps)
    '''

    payload = {
        'user_id': str(user.keycloak_id),
        'ts': timezone.now().timestamp(),
        'next': next,
    }
    return signing.dumps(payload, key=key)
