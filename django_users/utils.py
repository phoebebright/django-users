from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from post_office import mail
from django.template.loader import render_to_string
from django.conf import settings
from twilio.rest import Client
from django.utils.translation import gettext_lazy as _
from django.urls import reverse_lazy, reverse

User = get_user_model()

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


def handle_user_merge_or_create(proposed_name, email, phone):
    """
    In a real Keycloak environment, you'd do an API call instead.
    For demonstration, let's just do local Django user logic.
    """
    user = None

    # Try to find by email first
    if email:
        try:
            user = User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            pass

    # Possibly do a phone-based lookup if no user found:
    # (assuming you store phone in user.profile or a custom field)

    if user:
        # Possibly update name if user doesn't have one
        if not user.first_name and proposed_name:
            user.first_name = proposed_name
            user.save()
        return user

    # No existing user found, create a new one
    username = create_unique_username(proposed_name)
    user = User.objects.create_user(
        username=username,
        email=email or ''
    )
    user.first_name = proposed_name or ''
    user.save()

    # If we have a phone field in user.profile, etc., you can store it there
    return user

def create_unique_username(base_name):
    """
    Creates a naive unique username from base_name + random suffix.
    """
    base = re.sub(r'\W+', '', base_name.lower()) if base_name else 'user'
    suffix = uuid.uuid4().hex[:6]
    return f"{base[:20]}_{suffix}"
