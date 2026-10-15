"""``safe_next``: only same-site URLs survive as a redirect target."""

from django.test import RequestFactory, SimpleTestCase

from django_users.redirects import safe_next


class SafeNextTests(SimpleTestCase):

    def setUp(self):
        self.request = RequestFactory().get("/")

    def test_same_site_path_is_kept(self):
        self.assertEqual(safe_next(self.request, "/course/abc/?tab=2"), "/course/abc/?tab=2")

    def test_same_host_absolute_url_is_kept(self):
        self.assertEqual(safe_next(self.request, "http://testserver/course/"), "http://testserver/course/")

    def test_surrounding_spaces_are_stripped(self):
        self.assertEqual(safe_next(self.request, "  /course/  "), "/course/")

    def test_off_site_and_unsafe_values_fall_back(self):
        for url in ["https://evil.example", "//evil.example", "/\\evil.example",
                    "HTTP://evil.example", " https://evil.example", "javascript:alert(1)",
                    "", None]:
            with self.subTest(url=url):
                self.assertEqual(safe_next(self.request, url), "/")

    def test_fallback_is_configurable(self):
        self.assertIsNone(safe_next(self.request, "https://evil.example", fallback=None))

    def test_plain_http_refused_on_a_secure_request(self):
        request = RequestFactory().get("/", secure=True)
        self.assertEqual(safe_next(request, "http://testserver/course/"), "/")
        self.assertEqual(safe_next(request, "https://testserver/course/"), "https://testserver/course/")
