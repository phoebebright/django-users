
from django.core.mail import send_mail
from post_office import mail
from django.template.loader import render_to_string
from django.conf import settings
from twilio.rest import Client
from django.utils.translation import gettext_lazy as _

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
