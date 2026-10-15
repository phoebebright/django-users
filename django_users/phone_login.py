"""Log in on a phone by scanning a QR code shown to a user who is already logged in.

Replaces the QR half of ``QRLogin`` / ``login_with_token``, closing the gaps
that matter once the phone is a real way in:

- **Single use.** The token carries a random nonce, and redeeming it claims the
  nonce in the cache with an atomic ``cache.add``. Needs a cache shared by every
  worker (Redis, Memcached); with a per-process cache a code could be used once
  per process.
- **A short window.** ``DJANGO_USERS_PHONE_LOGIN_MAX_AGE`` seconds, two minutes
  by default.
- **Its own salt.** Nothing else the site signs can be replayed as a login.
- **Dies with the password.** The token carries an HMAC of the user's session
  auth hash, so changing the password cancels any code still on a screen.
- **By primary key**, so it works with or without Keycloak.
- **Never in a URL the server sees.** The QR link carries the token after ``#``,
  which browsers do not send, so it stays out of access logs. The phone page
  posts it back (see ``PhoneLoginView``).

Redeeming is a separate, deliberate POST from a confirmation page, so a link
preview or a scanner that fetches the URL cannot spend the code.

Session values named in ``DJANGO_USERS_PHONE_LOGIN_SESSION_KEYS`` are copied to
the phone's new session - e.g. the organisation an admin is currently viewing -
so the phone opens where the computer is. They travel signed but readable, so
list only values that are not secret.
"""
import secrets

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core import signing
from django.core.cache import cache
from django.utils.crypto import constant_time_compare, salted_hmac
from django.utils.translation import gettext_lazy as _

TOKEN_SALT = "django_users.phone_login"
DEFAULT_MAX_AGE = 120
_USED_KEY = "django_users:phone_login:used:{nonce}"
_HASH_CHARS = 16


class PhoneLoginError(Exception):
    """Why a code cannot be used, in words for the person holding the phone."""

    def __init__(self, message):
        super().__init__(message)
        self.message = message


def max_age() -> int:
    return getattr(settings, "DJANGO_USERS_PHONE_LOGIN_MAX_AGE", DEFAULT_MAX_AGE)


def carried_session_keys():
    return tuple(getattr(settings, "DJANGO_USERS_PHONE_LOGIN_SESSION_KEYS", ()))


def _password_fingerprint(user) -> str:
    """Changes when the password does. An HMAC of the session auth hash, not a
    slice of it, because the token's payload is readable by whoever holds it."""
    return salted_hmac(TOKEN_SALT, user.get_session_auth_hash()).hexdigest()[:_HASH_CHARS]


def make_token(user, next_url: str, session=None) -> str:
    session = session or {}
    payload = {
        "u": str(user.pk),
        "n": secrets.token_urlsafe(12),
        "h": _password_fingerprint(user),
        "next": next_url,
        "s": {key: session[key] for key in carried_session_keys() if key in session},
    }
    return signing.dumps(payload, salt=TOKEN_SALT, compress=True)


def read_token(token: str) -> dict:
    """Check a code without spending it.

    Returns ``{"user", "next", "session", "nonce"}``; raises `PhoneLoginError`.
    """
    try:
        payload = signing.loads(token or "", salt=TOKEN_SALT, max_age=max_age())
    except signing.SignatureExpired:
        raise PhoneLoginError(_("This code has expired. Show a new one on your computer and scan it again."))
    except signing.BadSignature:
        raise PhoneLoginError(_("This code is not valid. Show a new one on your computer and scan it again."))

    user = get_user_model().objects.filter(pk=payload.get("u"), is_active=True).first()
    if user is None or not constant_time_compare(_password_fingerprint(user), payload.get("h", "")):
        raise PhoneLoginError(_("This code is no longer valid. Show a new one on your computer and scan it again."))
    if cache.get(_USED_KEY.format(nonce=payload["n"])):
        raise PhoneLoginError(_("This code has already been used. Show a new one on your computer to log in again."))
    return {
        "user": user,
        "next": payload.get("next") or "/",
        # Only the keys this site still carries, whatever the token says.
        "session": {k: v for k, v in (payload.get("s") or {}).items() if k in carried_session_keys()},
        "nonce": payload["n"],
    }


def redeem_token(token: str) -> dict:
    """Spend a code. Same return as `read_token`; a second redeem fails."""
    details = read_token(token)
    # Atomic in a shared cache: of two phones racing with one code, one wins.
    # Kept a little past the window so the claim outlives the token itself.
    if not cache.add(_USED_KEY.format(nonce=details["nonce"]), 1, timeout=max_age() + 60):
        raise PhoneLoginError(_("This code has already been used. Show a new one on your computer to log in again."))
    return details
