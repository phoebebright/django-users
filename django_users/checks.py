# django_users/checks.py
from django.conf import settings
from django.core.checks import register, Error, Tags

@register(Tags.compatibility)
def check_new_user_email_id(app_configs, **kwargs):
    """
    Ensure NEW_USER_EMAIL_ID is defined in settings.py
    """
    errors = []
    if not hasattr(settings, "NEW_USER_EMAIL_ID"):
        errors.append(
            Error(
                "The setting NEW_USER_EMAIL_ID is missing.",
                hint="Add NEW_USER_EMAIL_ID = 'something@example.com' to your settings.py",
                id="django_users.E001",
            )
        )
    elif not isinstance(settings.NEW_USER_EMAIL_ID, str):
        errors.append(
            Error(
                "NEW_USER_EMAIL_ID must be a string.",
                hint="Example: NEW_USER_EMAIL_ID = 'noreply@example.com'",
                id="django_users.E002",
            )
        )
    return errors
