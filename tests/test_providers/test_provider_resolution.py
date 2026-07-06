"""Truth table for ``get_auth_provider()`` / ``get_idp()`` and the
back-compat wrappers, across every combination of the three settings that
influence resolution:

  * ``AUTH_PROVIDER`` (explicit; always wins)
  * ``USE_KEYCLOAK`` (legacy skorie_users flag -> 'keycloak')
  * ``AUTHENTIK`` dict presence (legacy authentik-era fallback -> 'authentik')
"""

from django.test import SimpleTestCase, override_settings

from django_users.idp import (
    AuthentikIdP,
    VALID_AUTH_PROVIDERS,
    authentik_enabled,
    get_auth_provider,
    get_idp,
    keycloak_enabled,
)

AUTHENTIK_CONFIG = {
    "URL": "https://authentik.example.com",
    "API_TOKEN": "test-token",
    "VERIFY_SSL": False,
}

KEYCLOAK_CONFIG = {
    "USERS": {
        "CLIENT_ID": "users-client",
        "CLIENT_SECRET": "users-secret",
        "URL": "https://keycloak.example.com",
        "REALM": "example",
    }
}


class GetAuthProviderTests(SimpleTestCase):
    """Resolution order: AUTH_PROVIDER > USE_KEYCLOAK > AUTHENTIK dict > django."""

    def test_default_is_django(self):
        # Base test settings define none of the three knobs.
        self.assertEqual(get_auth_provider(), "django")

    @override_settings(AUTH_PROVIDER="django")
    def test_explicit_django(self):
        self.assertEqual(get_auth_provider(), "django")

    @override_settings(AUTH_PROVIDER="keycloak")
    def test_explicit_keycloak(self):
        self.assertEqual(get_auth_provider(), "keycloak")

    @override_settings(AUTH_PROVIDER="authentik")
    def test_explicit_authentik(self):
        self.assertEqual(get_auth_provider(), "authentik")

    @override_settings(AUTH_PROVIDER="django", USE_KEYCLOAK=True, AUTHENTIK=AUTHENTIK_CONFIG)
    def test_explicit_beats_both_legacy_signals(self):
        # An explicit AUTH_PROVIDER wins even when both legacy signals are on:
        # hosts define config dicts unconditionally so switching provider is a
        # one-line change.
        self.assertEqual(get_auth_provider(), "django")

    @override_settings(USE_KEYCLOAK=True)
    def test_legacy_use_keycloak(self):
        self.assertEqual(get_auth_provider(), "keycloak")

    @override_settings(USE_KEYCLOAK=True, AUTHENTIK=AUTHENTIK_CONFIG)
    def test_legacy_use_keycloak_beats_authentik_dict(self):
        self.assertEqual(get_auth_provider(), "keycloak")

    @override_settings(AUTHENTIK=AUTHENTIK_CONFIG)
    def test_legacy_authentik_dict(self):
        self.assertEqual(get_auth_provider(), "authentik")

    @override_settings(USE_KEYCLOAK=False, AUTHENTIK=None)
    def test_falsey_legacy_signals_mean_django(self):
        self.assertEqual(get_auth_provider(), "django")

    def test_valid_providers_constant(self):
        self.assertEqual(VALID_AUTH_PROVIDERS, ("django", "keycloak", "authentik"))


class EnabledWrapperTests(SimpleTestCase):
    """authentik_enabled()/keycloak_enabled() are thin wrappers over the resolver."""

    @override_settings(AUTH_PROVIDER="authentik", AUTHENTIK=AUTHENTIK_CONFIG)
    def test_authentik_enabled_true(self):
        self.assertIs(authentik_enabled(), True)
        self.assertIs(keycloak_enabled(), False)

    @override_settings(AUTH_PROVIDER="keycloak")
    def test_keycloak_enabled_true(self):
        self.assertIs(keycloak_enabled(), True)
        self.assertIs(authentik_enabled(), False)

    def test_both_false_under_django(self):
        self.assertIs(authentik_enabled(), False)
        self.assertIs(keycloak_enabled(), False)


class GetIdPTests(SimpleTestCase):
    """get_idp() returns the adapter matching the provider, or None for django."""

    def test_django_returns_none(self):
        self.assertIsNone(get_idp())

    @override_settings(AUTH_PROVIDER="authentik", AUTHENTIK=AUTHENTIK_CONFIG)
    def test_authentik_returns_authentik_adapter(self):
        self.assertIsInstance(get_idp(), AuthentikIdP)

    @override_settings(AUTH_PROVIDER="keycloak", KEYCLOAK_CLIENTS=KEYCLOAK_CONFIG)
    def test_keycloak_returns_keycloak_adapter(self):
        try:
            import keycloak  # noqa: F401
        except ImportError:
            self.skipTest("python-keycloak not installed")
        from django_users.idp_keycloak import KeycloakIdP
        self.assertIsInstance(get_idp(), KeycloakIdP)
