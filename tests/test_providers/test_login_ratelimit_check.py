"""``check_login_ratelimit_cache``: the sign-in limit needs a shared cache."""

from django.test import SimpleTestCase, override_settings

from django_users.checks import check_login_ratelimit_cache

LOCMEM = {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
REDIS = {"BACKEND": "django_redis.cache.RedisCache", "LOCATION": "redis://localhost:6379/4"}


def _ids():
    return [message.id for message in check_login_ratelimit_cache(None)]


class LoginRateLimitCacheCheckTests(SimpleTestCase):

    @override_settings(CACHES={"default": LOCMEM})
    def test_warns_for_per_process_cache(self):
        self.assertEqual(_ids(), ["django_users.W010"])

    @override_settings(CACHES={"default": LOCMEM, "ratelimit": REDIS}, RATELIMIT_USE_CACHE="ratelimit")
    def test_quiet_for_shared_cache(self):
        self.assertEqual(_ids(), [])

    @override_settings(CACHES={"default": LOCMEM}, RATELIMIT_USE_CACHE="ratelimit")
    def test_warns_when_cache_alias_missing(self):
        self.assertEqual(_ids(), ["django_users.W011"])

    @override_settings(CACHES={"default": LOCMEM}, LOGIN_RATELIMIT_EMAIL=None, LOGIN_RATELIMIT_IP=None)
    def test_quiet_when_both_limits_off(self):
        self.assertEqual(_ids(), [])
