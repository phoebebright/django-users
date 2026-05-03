from django.http import HttpResponse
from django.test import RequestFactory, TestCase

from django_users.referrals import conf
from django_users.referrals.middleware import ReferralAttributionMiddleware


class MiddlewareTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def _run(self, request):
        mw = ReferralAttributionMiddleware(lambda r: HttpResponse("ok"))
        return mw(request)

    def test_sets_cookie_when_ref_param_present(self):
        request = self.factory.get("/?ref=ABC123")
        response = self._run(request)
        self.assertIn(conf.cookie_name(), response.cookies)
        self.assertEqual(response.cookies[conf.cookie_name()].value, "ABC123")

    def test_no_cookie_when_ref_param_absent(self):
        request = self.factory.get("/")
        response = self._run(request)
        self.assertNotIn(conf.cookie_name(), response.cookies)

    def test_first_touch_wins_does_not_overwrite(self):
        request = self.factory.get("/?ref=NEW")
        request.COOKIES[conf.cookie_name()] = "FIRST"
        response = self._run(request)
        self.assertNotIn(conf.cookie_name(), response.cookies)
