"""Attribution middleware.

Captures ?ref=CODE from any incoming request and sets a cookie so that a
later signup can be attributed to the referrer. Host apps must then call
`services.attribute(user, request.COOKIES.get(referrals.conf.cookie_name()))`
from their signup flow.

This middleware is independent of the rest of the module and can be used
without a configured BonusPolicy — it only writes a cookie.
"""

from . import conf


class ReferralAttributionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        param = conf.query_param()
        code = request.GET.get(param)
        if code:
            cookie_name = conf.cookie_name()
            if request.COOKIES.get(cookie_name):
                # First touch wins — don't overwrite
                return response
            max_age = conf.cookie_window_days() * 24 * 60 * 60
            response.set_cookie(
                cookie_name,
                code.strip()[:64],
                max_age=max_age,
                httponly=True,
                samesite="Lax",
            )
        return response
