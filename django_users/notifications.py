from django.core.mail import mail_admins

from config import settings
from tools.decorators import notifications_on


@notifications_on
def on_new_user_unverified(instance, message, request=None, user=None):


    mail_admins(f"User signing up {instance} for {settings.SITE_NAME}", f"email: {instance.email}, name: {instance.full_name}", fail_silently=True)

@notifications_on
def on_new_user_verified(instance, message, request=None, user=None):


    mail_admins(f"User verified {instance} for {settings.SITE_NAME}", f"email: {instance.email}, name: {instance.full_name}", fail_silently=True)
