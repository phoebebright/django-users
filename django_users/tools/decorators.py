from functools import wraps

from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.decorators import user_passes_test
from django.core.exceptions import PermissionDenied
from django.utils import timezone


def activate_event_timezone(method):
    @wraps(method)
    def wrapper(request, *args, **kwargs):
        from web.models import Event
        event = Event.objects.get(ref=kwargs['event_ref'])

        if event.timezone:
            timezone.activate(event.timezone)
        else:
            timezone.deactivate()
        return method(request, *args, **kwargs)

    return wrapper

def registered_required(function=None, redirect_field_name=REDIRECT_FIELD_NAME, login_url=None):
    """
    Equivalent to login_required - makes sure user is logged in as a registered user
    ie. not anonymous and with an activated account

    """
    actual_decorator = user_passes_test(
        lambda u: u.is_registered,
        login_url=login_url,
        redirect_field_name=redirect_field_name
    )
    if function:
        return actual_decorator(function)
    return actual_decorator



#TODO: NOT WORKING
def event_organiser(function=None, redirect_field_name=REDIRECT_FIELD_NAME, login_url=None):
    """
    Equivalent to login_required - makes sure user is logged in as a registered user
    ie. not anonymous and with an activated account

    """
    actual_decorator = user_passes_test(
        #lambda u: not u.is_manager,
        lambda u: not u.is_anon,
        login_url=login_url,
        redirect_field_name=redirect_field_name
    )
    if function:
        return actual_decorator(function)
    return actual_decorator




def notifications_on(method):
    @wraps(method)
    def wrapper( *args, **kwargs):
        if not settings.NOTIFICATIONS:
            return False

        return method( *args, **kwargs)

    return wrapper
