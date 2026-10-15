"""Limit on failed sign-ins, used by ``LoginView``.

Two counters, both counting failed attempts only: one per email address and
one per client IP. Once either reaches its limit, further attempts are refused
without checking the password until the window ends, so a correct password is
refused too. Successful sign-ins never count.

Settings (host project)::

    LOGIN_RATELIMIT_EMAIL = '5/15m'   # failures per email; None turns it off
    LOGIN_RATELIMIT_IP    = '30/h'    # failures per IP; None turns it off

    # django-ratelimit's own settings:
    RATELIMIT_USE_CACHE   = 'default' # must be a shared cache (Redis or
                                      # memcached) once the host runs more than
                                      # one process; checks.py warns otherwise
    RATELIMIT_IP_META_KEY = 'django_users.login_limits.forwarded_client_ip'
                                      # behind nginx; safe with uwsgi_pass or
                                      # proxy_pass (see forwarded_client_ip)

The counts use django-ratelimit's fixed windows, so a blocked user waits until
the current window ends: at most the full period.

The limit fails open: if the cache is unreachable, the attempt is allowed and
the error logged, so a cache outage never stops everyone signing in.
"""

from __future__ import annotations

import ipaddress
import logging

from django.conf import settings
from django.core.cache import caches
from django.core.exceptions import ImproperlyConfigured
from django_ratelimit import ALL
from django_ratelimit.core import _get_ip, _get_window, _make_cache_key, _split_rate, get_usage

logger = logging.getLogger(__name__)

DEFAULT_EMAIL_RATE = "5/15m"
DEFAULT_IP_RATE = "30/h"

GROUP_EMAIL = "django_users.login.email"
GROUP_IP = "django_users.login.ip"


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def forwarded_client_ip(request) -> str:
    """Client IP, allowing for a reverse proxy in front of the app.

    Point ``RATELIMIT_IP_META_KEY`` at this. A public REMOTE_ADDR is the client
    (nginx ``uwsgi_pass`` with ``uwsgi_params`` passes it through), and
    X-Forwarded-For is then whatever the client sent, so it is ignored. A
    loopback or private REMOTE_ADDR means a proxy made the request (nginx
    ``proxy_pass``): the client is the last X-Forwarded-For entry, the one the
    proxy added (``$proxy_add_x_forwarded_for``); earlier entries come from
    the client and can be made up.
    """
    remote = request.META.get("REMOTE_ADDR", "")
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded and not _is_public(remote):
        return forwarded.split(",")[-1].strip()
    return remote


def login_rates() -> dict[str, str | None]:
    """The active rate for each limit; None means that limit is off."""
    return {
        GROUP_EMAIL: getattr(settings, "LOGIN_RATELIMIT_EMAIL", DEFAULT_EMAIL_RATE),
        GROUP_IP: getattr(settings, "LOGIN_RATELIMIT_IP", DEFAULT_IP_RATE),
    }


def _public_client_ip(request) -> str | None:
    """The client IP, or None when it isn't a public address.

    A loopback or private address belongs to the proxy, not the client: the
    host hasn't set RATELIMIT_IP_META_KEY, or the proxy isn't forwarding the
    client address. Every user would then share one IP counter and one
    person's failures would lock everyone out, so the IP limit is skipped.

    An address that can't be read (with no proxy in front, X-Forwarded-For is
    whatever the client sends) also skips only the IP limit; letting the
    error escape would fail open and skip the email limit too.
    """
    try:
        ip = _get_ip(request)
    except (ValueError, ImproperlyConfigured):
        return None
    return ip if _is_public(ip) else None


def _counters(request, email: str):
    """(group, rate, value) for each limit that is switched on.

    IP first, so a check can stop at a blocked IP before it creates a cache
    key for every email address that IP tries.
    """
    rates = login_rates()
    if rates[GROUP_IP]:
        ip = _public_client_ip(request)
        if ip:
            yield GROUP_IP, rates[GROUP_IP], ip
    if rates[GROUP_EMAIL]:
        yield GROUP_EMAIL, rates[GROUP_EMAIL], email or ""


def _usages(request, email: str, increment=False):
    """django-ratelimit's usage dict for each counter that is working.

    Skips a counter when get_usage returns None (the limit is off via
    RATELIMIT_ENABLE, or the cache failed with RATELIMIT_FAIL_OPEN) or its
    cache-failure marker, limit 0 (the cache failed without it).
    """
    for group, rate, value in _counters(request, email):
        usage = get_usage(request, group=group, key=lambda _group, _request: value,
                          rate=rate, increment=increment)
        if usage and usage["limit"]:
            yield usage


def login_wait_seconds(request, email: str) -> int | None:
    """Seconds until the sign-in limit for this email or IP resets, or None.

    Reads the counters without adding to them.
    """
    try:
        for usage in _usages(request, email):
            if usage["count"] >= usage["limit"]:
                return max(usage["time_left"], 1)
    except Exception as exc:
        logger.warning("Sign-in rate limit check failed, allowing the attempt: %s", exc)
    return None


def record_failed_login(request, email: str) -> bool:
    """Add one to the email and IP counters.

    Returns True when this failure reached a limit, so the caller can log the
    lockout once rather than on every refused attempt after it.
    """
    try:
        # A list, not a generator: any() must not stop before every counter
        # has been incremented.
        return any([usage["count"] == usage["limit"]
                    for usage in _usages(request, email, increment=True)])
    except Exception as exc:
        logger.warning("Could not record a failed sign-in for the rate limit: %s", exc)
        return False


def clear_login_limit(email: str) -> None:
    """Reset the email counter once the account owner has proved who they are.

    Called when a password reset completes, so the reset that the 429 page
    offers really does let them back in. The IP counter is left alone.
    django-ratelimit has no reset call, so this rebuilds its cache key the way
    get_usage does (hence the django-ratelimit<5 pin).
    """
    rate = login_rates()[GROUP_EMAIL]
    if not rate:
        return
    try:
        _limit, period = _split_rate(rate)
        key = _make_cache_key(GROUP_EMAIL, _get_window(email, period), rate, email, ALL)
        caches[getattr(settings, "RATELIMIT_USE_CACHE", "default")].delete(key)
    except Exception as exc:
        logger.warning("Could not clear the sign-in limit for an email: %s", exc)
