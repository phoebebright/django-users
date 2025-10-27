# django_users/checks.py
from django.conf import settings
from django.core.checks import register, Error, Tags

@register(Tags.compatibility)
def check_new_user_email_template(app_configs, **kwargs):
    """
    Ensure NEW_USER_EMAIL_TEMPLATE is defined in settings.py
    This is the id value in CommsTemplate to use to send a new user email
    """
    errors = []
    if not hasattr(settings, "NEW_USER_EMAIL_TEMPLATE"):
        errors.append(
            Error(
                "The setting NEW_USER_EMAIL_TEMPLATE is missing.",
                hint="Add NEW_USER_EMAIL_TEMPLATE = 23 to your settings.py where 23 is the id value in CommsTemplate to use to send a new user email.",
                id="django_users.E001",
            )
        )
    elif not isinstance(settings.NEW_USER_EMAIL_TEMPLATE, int):
        errors.append(
            Error(
                "NEW_USER_EMAIL_TEMPLATE must be a int.",
                hint="Example: NEW_USER_EMAIL_TEMPLATE = 23",
                id="django_users.E002",
            )
        )
    return errors
