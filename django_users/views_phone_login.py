"""Log in on a phone from a QR code on a computer. See `django_users.phone_login`.

Mount both views from the same urls module (``django_users.urls`` does, as
``qr-login`` and ``phone_login``); the QR page builds the phone's link from its
own namespace, so it works wherever that module is included.

Settings:
    DJANGO_USERS_PHONE_LOGIN_MAX_AGE       seconds a code lasts (120)
    DJANGO_USERS_PHONE_LOGIN_DEFAULT_NEXT  where the phone lands with no ?next= ("/")
    DJANGO_USERS_PHONE_LOGIN_SESSION_KEYS  session keys copied to the phone (())
"""
import base64
import io

import qrcode
from django.conf import settings
from django.contrib.auth import login
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.utils.http import url_has_allowed_host_and_scheme
from django.views import View
from django.views.decorators.cache import never_cache
from django.views.generic import TemplateView

from .phone_login import PhoneLoginError, make_token, max_age, read_token, redeem_token


def safe_next(request, candidate):
    if candidate and url_has_allowed_host_and_scheme(
        candidate, allowed_hosts={request.get_host()}, require_https=request.is_secure(),
    ):
        return candidate
    return getattr(settings, "DJANGO_USERS_PHONE_LOGIN_DEFAULT_NEXT", "/")


@method_decorator(never_cache, name="dispatch")
class PhoneLoginQRView(LoginRequiredMixin, TemplateView):
    """Show a QR code that logs the phone that scans it in as this user."""
    template_name = "django_users/phone_login_qr.html"
    phone_url_name = "phone_login"

    def phone_url(self, token):
        namespace = self.request.resolver_match.namespace
        name = f"{namespace}:{self.phone_url_name}" if namespace else self.phone_url_name
        # The token goes after '#', which browsers never send to the server.
        return f"{self.request.build_absolute_uri(reverse(name))}#{token}"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        token = make_token(
            self.request.user,
            safe_next(self.request, self.request.GET.get("next")),
            session=self.request.session,
        )
        buf = io.BytesIO()
        qrcode.make(self.phone_url(token)).save(buf, format="PNG")
        context.update({
            "qr_png": base64.b64encode(buf.getvalue()).decode(),
            "max_age": max_age(),
        })
        return context


@method_decorator(never_cache, name="dispatch")
class PhoneLoginView(View):
    """The phone's side.

    GET serves the page, which reads the token from the URL fragment. It posts
    ``action=check`` to learn whose code it is (nothing is spent), shows "Log in
    as …?", and the button posts ``action=login``, which spends the code.
    Splitting the two is what stops a link preview, or a scanner app that
    fetches the URL, from using up a single-use code.
    """
    template_name = "django_users/phone_login_confirm.html"

    def get(self, request):
        return render(request, self.template_name)

    def post(self, request):
        token = request.POST.get("token", "")
        if request.POST.get("action") == "check":
            try:
                details = read_token(token)
            except PhoneLoginError as exc:
                return JsonResponse({"error": str(exc.message)}, status=400)
            return JsonResponse({"email": details["user"].email})

        try:
            details = redeem_token(token)
        except PhoneLoginError as exc:
            return render(request, self.template_name, {"error": exc.message}, status=400)
        login(request, details["user"], backend="django.contrib.auth.backends.ModelBackend")
        # After login(), which starts a fresh session.
        for key, value in details["session"].items():
            request.session[key] = value
        return redirect(safe_next(request, details["next"]))
