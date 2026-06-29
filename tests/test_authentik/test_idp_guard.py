"""Tests for the ``authentik_enabled()`` guard added across the IdP call sites.

The uncommitted change on this branch introduced ``django_users.idp.authentik_enabled``
and threaded ``and authentik_enabled()`` / early-return guards through api.py,
models.py, services.py and views.py so the library degrades gracefully when
Authentik is not configured (instead of crashing in ``AuthentikIdP.__init__``).

``idp.py`` is the only changed module that imports cleanly in isolation (it
depends solely on ``django.conf.settings`` + ``httpx`` — no models, no GeoDjango),
so this is where the new logic is unit-tested. The call-site guards in
api/models/views/services exercise the host app's custom user model, DRF
permission mixins and URL routing, and belong in the host project's test suite;
see the module note at the bottom.
"""

from django.test import SimpleTestCase, override_settings

from django_users.idp import AuthentikError, AuthentikIdP, authentik_enabled


# A representative, well-formed AUTHENTIK settings dict.
AUTHENTIK_CONFIG = {
    "URL": "https://authentik.example.com",
    "API_TOKEN": "test-token",
    "VERIFY_SSL": False,
}


class AuthentikEnabledTests(SimpleTestCase):
    """Truth table for ``authentik_enabled()``.

    Returns True only when an AUTHENTIK settings dict is present AND the
    ``USE_KEYCLOAK`` escape hatch is not set.
    """

    # ---- enabled -----------------------------------------------------

    @override_settings(AUTHENTIK=AUTHENTIK_CONFIG, USE_KEYCLOAK=False)
    def test_enabled_when_authentik_configured_and_keycloak_off(self):
        self.assertTrue(authentik_enabled())

    @override_settings(AUTHENTIK=AUTHENTIK_CONFIG)
    def test_enabled_when_authentik_configured_and_keycloak_unset(self):
        # USE_KEYCLOAK not defined at all — getattr default (False) applies.
        self.assertTrue(authentik_enabled())

    # ---- disabled via USE_KEYCLOAK ----------------------------------

    @override_settings(AUTHENTIK=AUTHENTIK_CONFIG, USE_KEYCLOAK=True)
    def test_disabled_when_keycloak_flag_set_even_if_authentik_present(self):
        # USE_KEYCLOAK short-circuits before AUTHENTIK is consulted.
        self.assertFalse(authentik_enabled())

    @override_settings(USE_KEYCLOAK=True)
    def test_disabled_when_keycloak_flag_set_and_no_authentik(self):
        self.assertFalse(authentik_enabled())

    # ---- disabled via missing/empty AUTHENTIK -----------------------

    def test_disabled_when_authentik_absent(self):
        # Base test settings define neither AUTHENTIK nor USE_KEYCLOAK.
        self.assertFalse(authentik_enabled())

    @override_settings(AUTHENTIK=None)
    def test_disabled_when_authentik_none(self):
        self.assertFalse(authentik_enabled())

    @override_settings(AUTHENTIK={})
    def test_disabled_when_authentik_empty_dict(self):
        self.assertFalse(authentik_enabled())

    # ---- return type -------------------------------------------------

    @override_settings(AUTHENTIK=AUTHENTIK_CONFIG)
    def test_returns_plain_bool(self):
        # Callers use it in boolean conjunctions; guard against truthy non-bools.
        self.assertIs(authentik_enabled(), True)

    def test_returns_plain_bool_when_disabled(self):
        self.assertIs(authentik_enabled(), False)


class AuthentikIdPInstantiationGuardTests(SimpleTestCase):
    """Why the guard exists: ``AuthentikIdP()`` raises when unconfigured.

    These tests pin the failure mode that ``authentik_enabled()`` protects
    every call site from — instantiating the adapter without settings blows up,
    so the new guards must run *before* construction.
    """

    def test_init_raises_when_authentik_absent(self):
        # No AUTHENTIK in settings → no URL/token → AuthentikError.
        with self.assertRaises(AuthentikError):
            AuthentikIdP()

    @override_settings(AUTHENTIK={})
    def test_init_raises_when_authentik_empty(self):
        with self.assertRaises(AuthentikError):
            AuthentikIdP()

    @override_settings(AUTHENTIK={"API_TOKEN": "tok"})
    def test_init_raises_when_url_missing(self):
        with self.assertRaises(AuthentikError):
            AuthentikIdP()

    @override_settings(AUTHENTIK={"URL": "https://authentik.example.com"})
    def test_init_raises_when_token_missing(self):
        with self.assertRaises(AuthentikError):
            AuthentikIdP()

    @override_settings(AUTHENTIK=AUTHENTIK_CONFIG)
    def test_init_succeeds_when_fully_configured(self):
        idp = AuthentikIdP()
        self.assertEqual(idp.base_url, "https://authentik.example.com")
        self.assertEqual(idp.api_token, "test-token")

    @override_settings(AUTHENTIK={"URL": "https://authentik.example.com/", "API_TOKEN": "t"})
    def test_init_strips_trailing_slash_from_url(self):
        idp = AuthentikIdP()
        self.assertEqual(idp.base_url, "https://authentik.example.com")


# ---------------------------------------------------------------------------
# Coverage note (per Django dev rules — minimum coverage checklist):
#
#   * Happy path        — authentik_enabled() True when configured;
#                         AuthentikIdP() constructs when configured.
#   * Error/validation  — AuthentikIdP() raises AuthentikError on missing
#                         URL/token/dict (the failure the guard prevents).
#   * Business-rule edge — USE_KEYCLOAK short-circuits before AUTHENTIK is read;
#                         None vs {} vs missing AUTHENTIK all read as disabled.
#
# NOT covered here (require the host app: custom user model, GeoDjango/GDAL,
# DRF permission mixins, URL routing) and should be added to the host project's
# suite:
#   * api.py        GenerateRecoveryLink / SetTemporaryPassword / CreateUser
#                   return HTTP 400 when not authentik_enabled().
#                   NB: api.CreateUser uses a bare ``HTTP_400_BAD_REQUEST`` —
#                   confirm it is imported, else that branch NameErrors.
#   * models.py     create_authentik_user_from_user() returns None;
#                   find_by_email lookup returns None; CommsChannel verify and
#                   update_email_verified_in_idp() skip the IdP call.
#   * services.py   _sync_to_authentik() returns early (no AuthentikIdP call).
#   * views.py      AddUser / ChangePasswordNowView / ForgotPassword /
#                   ChangePasswordView add a form error and re-render.
# ---------------------------------------------------------------------------
