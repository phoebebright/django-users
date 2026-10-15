"""Log in on a phone from a QR code (django_users.phone_login).

The properties that make it safe to offer, each tested:
- only a logged-in user can make a code, and the QR never puts it in a URL the
  server receives (it goes after '#');
- serving the phone page, and checking a code, do not log in - a link preview
  must not spend the code;
- confirming logs the phone in and lands on the page the code was made for;
- a code works once, and not after its window;
- changing the password, or deactivating the user, cancels a code;
- `next` cannot send the phone to another site;
- only the configured session keys travel to the phone.
"""
import base64
import io
import re
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import Client, TestCase
from django.urls import reverse

from django_users.phone_login import make_token

User = get_user_model()


class PhoneLoginTests(TestCase):
    PASSWORD = "testpass123"

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            username="phone", email="phone@test.com", password=cls.PASSWORD)

    def setUp(self):
        cache.clear()
        self.phone = Client()
        self.url = reverse("users:phone_login")

    def check(self, token, client=None):
        return (client or self.phone).post(self.url, {"action": "check", "token": token})

    def confirm(self, token, client=None):
        return (client or self.phone).post(self.url, {"action": "login", "token": token})

    def logged_in_as(self, client):
        return client.session.get("_auth_user_id")

    def test_qr_page_needs_a_logged_in_user(self):
        self.assertEqual(Client().get(reverse("users:qr-login")).status_code, 302)

    def test_qr_carries_the_code_after_the_hash(self):
        desktop = Client()
        desktop.login(username="phone", password=self.PASSWORD)
        response = desktop.get(reverse("users:qr-login"))
        self.assertEqual(response.status_code, 200)
        self.assertIn("no-store", response["Cache-Control"])

        png = re.search(r"data:image/png;base64,([A-Za-z0-9+/=]+)", response.content.decode()).group(1)
        try:
            import zxingcpp
            from PIL import Image
        except ImportError:
            self.skipTest("zxing-cpp not installed - cannot read the QR back")
        link = zxingcpp.read_barcodes(Image.open(io.BytesIO(base64.b64decode(png))))[0].text
        page, _, token = link.partition("#")
        self.assertTrue(page.endswith(self.url))
        self.assertRedirects(self.confirm(token), "/landing/", fetch_redirect_response=False)

    def test_serving_the_page_and_checking_do_not_log_in(self):
        self.assertEqual(self.phone.get(self.url).status_code, 200)
        response = self.check(make_token(self.user, "/landing/"))
        self.assertEqual(response.json(), {"email": self.user.email})
        self.assertIsNone(self.logged_in_as(self.phone))

    def test_confirming_logs_in_and_lands_on_next(self):
        response = self.confirm(make_token(self.user, "/somewhere/"))
        self.assertRedirects(response, "/somewhere/", fetch_redirect_response=False)
        self.assertEqual(self.logged_in_as(self.phone), str(self.user.pk))

    def test_code_works_once(self):
        token = make_token(self.user, "/landing/")
        self.confirm(token)
        second = Client()
        self.assertEqual(self.confirm(token, second).status_code, 400)
        self.assertIsNone(self.logged_in_as(second))
        self.assertEqual(self.check(token, Client()).status_code, 400)

    def test_code_expires(self):
        token = make_token(self.user, "/landing/")
        with mock.patch("django_users.phone_login.max_age", return_value=-1):
            self.assertEqual(self.confirm(token).status_code, 400)
        self.assertIsNone(self.logged_in_as(self.phone))

    def test_changing_password_cancels_the_code(self):
        token = make_token(self.user, "/landing/")
        self.user.set_password("a-new-password-456")
        self.user.save()
        self.assertEqual(self.confirm(token).status_code, 400)

    def test_inactive_user_cannot_log_in(self):
        token = make_token(self.user, "/landing/")
        User.objects.filter(pk=self.user.pk).update(is_active=False)
        self.assertEqual(self.confirm(token).status_code, 400)

    def test_tampered_or_missing_code_is_refused(self):
        token = make_token(self.user, "/landing/")
        self.assertEqual(self.confirm(token[:-2] + "xx").status_code, 400)
        self.assertEqual(self.confirm("").status_code, 400)
        self.assertIsNone(self.logged_in_as(self.phone))

    def test_next_cannot_leave_the_site(self):
        response = self.confirm(make_token(self.user, "https://evil.example.com/"))
        self.assertRedirects(response, "/landing/", fetch_redirect_response=False)

    def test_only_configured_session_keys_travel(self):
        token = make_token(self.user, "/landing/", session={
            "selected_org": "ORG1", "unrelated_key": "stays behind",
        })
        self.confirm(token)
        self.assertEqual(self.phone.session.get("selected_org"), "ORG1")
        self.assertNotIn("unrelated_key", self.phone.session)
