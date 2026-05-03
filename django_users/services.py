"""Invite-flow services.

Generic, project-agnostic orchestration for the admin-invite + accept flows:

* ``create_user_with_invite`` — single entry point used by AdminInviteView
  and any per-event invite views in consuming projects. Creates the Django
  user (and the IdP record, if Authentik is configured), persists an
  ``Invite`` row, issues a VerificationCode for the chosen delivery
  method, dispatches the email, and runs the project's
  ``INVITE_POST_CREATE`` hook for project-specific linkage.

* ``send_invite_email`` / ``send_otp_email`` — re-issue a VerificationCode
  against an existing Invite and fire the templated email. Used for
  resends and by ``create_user_with_invite``.

Project-specific concerns (Role assignment, EventRole creation, course-
module enrolment, etc.) live entirely behind the ``INVITE_POST_CREATE``
hook so this module stays usable across projects.

Settings (host project sets these):

    INVITE_MODEL          'users.Invite'                     # required
    INVITE_POST_CREATE    'users.hooks.on_user_invited'      # optional
    INVITE_LINK_EXPIRY_DAYS  7    # default 7
    OTP_EXPIRY_HOURS         24   # default 24
    EMAIL_WRAPPER         'skorie_news.mail.mail'            # optional;
                                                              defaults to django.core.mail
"""
from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from django.apps import apps
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.db import transaction
from django.urls import reverse
from django.utils import timezone
from django.utils.module_loading import import_string

from .idp import AuthentikError, AuthentikIdP
from .utils import get_mail_class

logger = logging.getLogger(__name__)


# ---- resolution helpers ----------------------------------------------------

def get_invite_model():
    """Return the concrete ``Invite`` model declared by the project."""
    label = getattr(settings, 'INVITE_MODEL', None)
    if not label:
        raise ImproperlyConfigured(
            "settings.INVITE_MODEL must be set to the project's concrete "
            "Invite model, e.g. 'users.Invite'."
        )
    return apps.get_model(label)


def _get_post_create_hook():
    dotted = getattr(settings, 'INVITE_POST_CREATE', None)
    return import_string(dotted) if dotted else None


def _get_verification_code_model():
    """Find the concrete VerificationCode by walking installed models for a
    subclass of VerificationCodeBase. Cheap (runs once per call site)."""
    from .models import VerificationCodeBase
    for model in apps.get_models():
        if issubclass(model, VerificationCodeBase) and not model._meta.abstract:
            return model
    raise ImproperlyConfigured(
        "No concrete subclass of VerificationCodeBase is registered."
    )


def _get_comms_channel_model():
    from .models import CommsChannelBase
    for model in apps.get_models():
        if issubclass(model, CommsChannelBase) and not model._meta.abstract:
            return model
    raise ImproperlyConfigured(
        "No concrete subclass of CommsChannelBase is registered."
    )


def _ensure_email_channel(user):
    Channel = _get_comms_channel_model()
    channel = user.comms_channels.filter(channel_type=Channel.CHANNEL_EMAIL).first()
    if channel is None:
        channel = Channel.objects.create(
            user=user, channel_type=Channel.CHANNEL_EMAIL, value=user.email,
        )
    return channel


# ---- IdP sync (best-effort) ------------------------------------------------

def _sync_to_authentik(user, *, first_name: str, last_name: str) -> None:
    """Best-effort: create the user in Authentik and store the resulting
    UUID on ``user.authentik_id``. If Authentik isn't configured or the
    call fails, we log and continue — OIDC login on first visit will
    reconcile."""
    if not getattr(settings, 'AUTHENTIK', None):
        return
    if not hasattr(user, 'authentik_id') or user.authentik_id:
        return
    try:
        ak_user = AuthentikIdP().create_user(
            email=user.email, first_name=first_name, last_name=last_name,
        )
    except (AuthentikError, ImproperlyConfigured) as exc:
        logger.warning("Authentik create_user failed for %s: %s", user.email, exc)
        return
    user.authentik_id = ak_user.uuid
    user.save(update_fields=['authentik_id'])


# ---- ttl helpers -----------------------------------------------------------

def _link_ttl_minutes() -> int:
    days = getattr(settings, 'INVITE_LINK_EXPIRY_DAYS', 7)
    return int(days) * 24 * 60


def _otp_ttl_minutes() -> int:
    hours = getattr(settings, 'OTP_EXPIRY_HOURS', 24)
    return int(hours) * 60


# ---- email dispatch --------------------------------------------------------

def _site_url(path: str) -> str:
    base = getattr(settings, 'SITE_URL', '').rstrip('/')
    return f"{base}{path}"


def send_invite_email(invite, *, personal_note: str = '') -> None:
    """Issue a fresh magic-link VerificationCode against the invite's user
    and dispatch the ``user_invite`` email template."""
    if invite.user is None:
        raise ValueError("Invite.user must be set before sending email.")
    VerificationCode = _get_verification_code_model()
    channel = _ensure_email_channel(invite.user)

    ttl = _link_ttl_minutes()
    vc, ctx = VerificationCode.create_for_magic_link(
        user=invite.user, channel=channel, purpose='invite', ttl_minutes=ttl,
    )

    mail = get_mail_class()
    mail.send(
        invite.email,
        getattr(settings, 'DEFAULT_FROM_EMAIL', None),
        template='user_invite',
        context={
            'user': invite.user,
            'invite': invite,
            'inviter': invite.created_by,
            'magic_link': ctx['magic_link'],
            'expiry_minutes': ctx['expiry_minutes'],
            'personal_note': personal_note or '',
        },
        receiver=invite.user,
        user=invite.created_by,
    )


def send_otp_email(invite, *, personal_note: str = '',
                   mark_channel_verified: bool = False) -> None:
    """Issue a fresh OTP VerificationCode against the invite's user and
    dispatch the ``user_otp`` email template.

    When ``mark_channel_verified`` is True, the email channel is marked
    verified at send time — used when the admin attests the email is valid
    (Approve & Send OTP path)."""
    if invite.user is None:
        raise ValueError("Invite.user must be set before sending email.")
    VerificationCode = _get_verification_code_model()
    channel = _ensure_email_channel(invite.user)

    if mark_channel_verified and channel.verified_at is None:
        channel.verified_at = timezone.now()
        channel.save(update_fields=['verified_at'])

    ttl = _otp_ttl_minutes()
    vc, ctx = VerificationCode.create_for_code(
        user=invite.user, channel=channel, purpose='invite', ttl_minutes=ttl,
    )

    mail = get_mail_class()
    mail.send(
        invite.email,
        getattr(settings, 'DEFAULT_FROM_EMAIL', None),
        template='user_otp',
        context={
            'user': invite.user,
            'invite': invite,
            'inviter': invite.created_by,
            'otp_code': ctx['code'],
            'expiry_minutes': ctx['expiry_minutes'],
            'login_url': _site_url(reverse('users:enter_otp')),
            'personal_note': personal_note or '',
        },
        receiver=invite.user,
        user=invite.created_by,
    )


# ---- json safety -----------------------------------------------------------

def _jsonify(value):
    """Recursively coerce a value into something json.dumps can serialise.

    Django Model instances → their pk; QuerySets / Manager / lists →
    list of jsonified items; dicts → dicts of jsonified values; tuples →
    lists. Anything else passes through unchanged.
    """
    from django.db.models import Manager, QuerySet
    from django.db.models import Model

    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Model):
        return value.pk
    if isinstance(value, (QuerySet, Manager)):
        return [_jsonify(v) for v in value.all()]
    if isinstance(value, dict):
        return {k: _jsonify(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonify(v) for v in value]
    return str(value)


# ---- main entry point ------------------------------------------------------

def create_user_with_invite(
    *,
    actor,
    email: str,
    first_name: str = '',
    last_name: str = '',
    mobile: str = '',
    delivery_method: str | None = None,
    extra: dict[str, Any] | None = None,
    personal_note: str = '',
):
    """Create a Django user, persist an Invite, dispatch delivery, and run
    the project's post-create hook.

    Returns ``(user, invite)``.
    """
    Invite = get_invite_model()
    User = get_user_model()
    extra = dict(extra or {})

    delivery = delivery_method or Invite.DELIVERY_LINK
    if delivery not in (Invite.DELIVERY_LINK, Invite.DELIVERY_OTP):
        raise ValueError(f"Unknown delivery_method: {delivery!r}")

    ttl = _link_ttl_minutes() if delivery == Invite.DELIVERY_LINK else _otp_ttl_minutes()

    with transaction.atomic():
        user = User.objects.create(
            email=email, username=email,
            first_name=first_name, last_name=last_name,
        )
        if mobile and hasattr(user, 'mobile'):
            user.mobile = mobile
        # Mark unconfirmed if the project's user model supports it.
        unconfirmed = getattr(User, 'USER_STATUS_UNCONFIRMED', None)
        if unconfirmed is not None and hasattr(user, 'status'):
            user.status = unconfirmed
        if hasattr(user, 'creator'):
            user.creator = actor
        user.set_unusable_password()
        user.save()

        _sync_to_authentik(user, first_name=first_name, last_name=last_name)

        invite = Invite.objects.create(
            email=email, first_name=first_name, last_name=last_name,
            mobile=mobile or '', delivery_method=delivery,
            expires_at=timezone.now() + timedelta(minutes=ttl),
            created_by=actor, user=user, extra=_jsonify(extra),
        )

        post_create = _get_post_create_hook()
        if post_create is not None:
            # Hook receives the rich form data (Model instances, QuerySets)
            # while Invite.extra holds a JSON-safe snapshot.
            post_create(user, invite, extra)

    if delivery == Invite.DELIVERY_LINK:
        send_invite_email(invite, personal_note=personal_note)
    else:
        send_otp_email(
            invite, personal_note=personal_note, mark_channel_verified=True,
        )

    invite.mark_sent()
    return user, invite
