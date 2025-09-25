import logging
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core import signing

from django.db.models import Q, F
from django.utils import timezone
from django.apps import apps
from django.template.loader import render_to_string
from django.conf import settings
from twilio.rest import Client
from django.utils.translation import gettext_lazy as _
from django.urls import reverse_lazy, reverse
from django.utils.module_loading import import_string

logger = logging.getLogger('django')

def get_mail_class():
    """
    Load the configured mail class from settings.APP_MAIL_CLASS.
    Defaults to django.core.mail if not set.
    """
    dotted = getattr(settings, "EMAIL_WRAPPER", "django.core.mail")
    return import_string(dotted)


def send_otp(channel, code):
    context = {'verification_code': code,
               'login_url': settings.SITE_URL + reverse(settings.LOGIN_URL)}
    template = 'send_otp',
    # we have not fully transitioned to using channels, so fallback to user.email
    if channel.value < ' ':
        to_email = channel.user.email
        logger.error(f"Channel id has no value {channel.id} ")
    else:
        to_email = channel.value

    mail = get_mail_class()
    mail.send(
        to_email,
        settings.DEFAULT_FROM_EMAIL,
        template=template,
        context=context,
        receiver=channel.user,
    )

    return True


def send_email_verification_code(verificationcode):
    template = 'email_verification_code'
    context = {'code': verificationcode.code}

    # we have not fully transitioned to using channels, so fallback to user.email
    if verificationcode.channel.value <= ' ':
        to_email = verificationcode.channel.user.email
        logger.error(f"Channel id has no value {verificationcode.channel.id} ")
    else:
        to_email = verificationcode.channel.value

    mail = get_mail_class()
    mail.send(
        to_email,
        settings.DEFAULT_FROM_EMAIL,
        template=template,
        context=context,
        receiver=verificationcode.user,
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
    User = get_user_model()
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
    User = get_user_model()
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
