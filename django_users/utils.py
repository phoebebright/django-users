from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core import signing
from django.core.mail import send_mail
from django.db.models import Q, F
from django.utils import timezone
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


def get_eligible_users_for_communication(communication_type, event=None):
    """
    Get users eligible for a specific communication type
    This integrates with your existing CommsLog system
    """

    now = timezone.now()

    if communication_type in ['signup_welcome', 'general_news']:
        # General communications - users subscribed to news
        return User.objects.filter(

            Q(unsubscribe_news__isnull=True) | Q(subscribe_news__gt=F('unsubscribe_news')),
            subscribe_news__isnull=False,
        )

    elif communication_type in ['event_opening', 'entries_closing_soon', 'results_announced', 'event_news']:
        # Event-related communications
        eligible_users = User.objects.none()

        # Users subscribed to all news
        news_users = User.objects.filter(

            Q(unsubscribe_news__isnull=True) | Q(subscribe_news__gt=F('unsubscribe_news')),
            subscribe_news__isnull=False,
        )
        eligible_users = eligible_users.union(news_users)

        # Users subscribed to events
        event_users = User.objects.filter(

            Q(unsubscribe_events__isnull=True) | Q(subscribe_events__gt=F('unsubscribe_events')),
            subscribe_events__isnull=False,
        )
        eligible_users = eligible_users.union(event_users)

        # Users subscribed to their events only (if they've entered this event)
        if event:
            myevent_users = User.objects.filter(

                Q(unsubscribe_myevents__isnull=True) | Q(subscribe_myevents__gt=F('unsubscribe_myevents')),
                subscribe_myevents__isnull=False,
                # Add your event entry relationship here
                # entries__event=event  # Adjust based on your Entry model
            )
            eligible_users = eligible_users.union(myevent_users)

        return eligible_users

    elif communication_type in ['event_entry_confirmation', 'payment_confirmation']:
        # Personal event communications - only for users entered in the event
        if event:
            return User.objects.filter(
                Q(

                    Q(unsubscribe_news__isnull=True) | Q(subscribe_news__gt=F('unsubscribe_news')),
                    subscribe_news__isnull=False,
                ) |
                Q(

                    Q(unsubscribe_events__isnull=True) | Q(subscribe_events__gt=F('unsubscribe_events')),
                    subscribe_events__isnull=False,
                ) |
                Q(

                    Q(unsubscribe_myevents__isnull=True) | Q(subscribe_myevents__gt=F('unsubscribe_myevents')),
                    subscribe_myevents__isnull=False,
                ),
                # entries__event=event  # Adjust based on your Entry model
            )

    return User.objects.none()


def get_subscription_analytics():
    """
    Get subscription analytics for agency reporting
    """

    total_users = User.objects.count()

    # Current subscriptions
    news_subscribers = User.objects.filter(

        Q(unsubscribe_news__isnull=True) | Q(subscribe_news__gt=F('unsubscribe_news')),
        subscribe_news__isnull=False,
    ).count()

    event_subscribers = User.objects.filter(

        Q(unsubscribe_events__isnull=True) | Q(subscribe_events__gt=F('unsubscribe_events')),
        subscribe_events__isnull=False,
    ).count()

    myevent_subscribers = User.objects.filter(

        Q(unsubscribe_myevents__isnull=True) | Q(subscribe_myevents__gt=F('unsubscribe_myevents')),
        subscribe_myevents__isnull=False,
    ).count()

    # Recent activity (last 30 days)
    thirty_days_ago = timezone.now() - timedelta(days=30)
    recent_subscriptions = User.objects.filter(
        Q(subscribe_news__gte=thirty_days_ago) |
        Q(subscribe_events__gte=thirty_days_ago) |
        Q(subscribe_myevents__gte=thirty_days_ago)
    ).count()

    recent_unsubscriptions = User.objects.filter(
        Q(unsubscribe_news__gte=thirty_days_ago) |
        Q(unsubscribe_events__gte=thirty_days_ago) |
        Q(unsubscribe_myevents__gte=thirty_days_ago)
    ).count()

    return {
        'total_users': total_users,
        'news_subscribers': news_subscribers,
        'event_subscribers': event_subscribers,
        'myevent_subscribers': myevent_subscribers,
        'recent_subscriptions': recent_subscriptions,
        'recent_unsubscriptions': recent_unsubscriptions,
        'news_rate': round((news_subscribers / total_users) * 100, 2) if total_users > 0 else 0,
        'event_rate': round((event_subscribers / total_users) * 100, 2) if total_users > 0 else 0,
        'myevent_rate': round((myevent_subscribers / total_users) * 100, 2) if total_users > 0 else 0,
    }
