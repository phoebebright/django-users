"""Checking a redirect target taken from the request (``next``, Referer...).

Following such a value unchecked is an open redirect: a link to our login page
with ``?next=https://evil.example`` signs the user in for real, then hands them
to a look-alike site. Every redirect to a request-supplied URL goes through
``safe_next``.
"""

from __future__ import annotations

from django.utils.http import url_has_allowed_host_and_scheme


def safe_next(request, url: str | None, fallback: str | None = "/") -> str | None:
    """``url`` if it stays on this site, otherwise ``fallback``.

    Same-site paths and absolute URLs on this host pass. Anything else falls
    back: another host, scheme-relative ``//host``, ``/\\host``, ``javascript:``,
    and plain ``http://`` when the request itself came over HTTPS.
    """
    url = (url or "").strip()
    if url and url_has_allowed_host_and_scheme(
        url, allowed_hosts={request.get_host()}, require_https=request.is_secure()
    ):
        return url
    return fallback
