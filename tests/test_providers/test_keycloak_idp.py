"""KeycloakIdP adapter tests with python-keycloak mocked out.

Mirrors tests/test_authentik/test_idp_guard.py's instantiation-guard suite,
plus behaviour tests for the adapter methods over a mocked KeycloakAdmin /
KeycloakOpenID so no Keycloak server (or even the real python-keycloak
package) is needed.
"""

import sys
import types
from unittest import mock

from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase, override_settings

KEYCLOAK_CONFIG = {
    "USERS": {
        "CLIENT_ID": "users-client",
        "CLIENT_SECRET": "users-secret",
        "URL": "https://keycloak.example.com/",
        "REALM": "example",
    }
}


class _FakeKeycloakError(Exception):
    def __init__(self, *args, response_code=None, **kwargs):
        super().__init__(*args)
        self.response_code = response_code


class _FakeKeycloakAuthenticationError(_FakeKeycloakError):
    pass


def _install_fake_python_keycloak():
    """Register a fake `keycloak` package in sys.modules and return the
    mock KeycloakAdmin / KeycloakOpenID classes for assertions."""
    admin_cls = mock.MagicMock(name="KeycloakAdmin")
    openid_cls = mock.MagicMock(name="KeycloakOpenID")

    pkg = types.ModuleType("keycloak")
    pkg.KeycloakAdmin = admin_cls
    pkg.KeycloakOpenID = openid_cls

    exceptions = types.ModuleType("keycloak.exceptions")
    exceptions.KeycloakError = _FakeKeycloakError
    exceptions.KeycloakAuthenticationError = _FakeKeycloakAuthenticationError
    pkg.exceptions = exceptions

    sys.modules["keycloak"] = pkg
    sys.modules["keycloak.exceptions"] = exceptions
    return admin_cls, openid_cls


class KeycloakIdPTestBase(SimpleTestCase):
    def setUp(self):
        self._saved_modules = {
            name: sys.modules.get(name) for name in ("keycloak", "keycloak.exceptions")
        }
        self.admin_cls, self.openid_cls = _install_fake_python_keycloak()
        self.admin = self.admin_cls.return_value
        self.openid = self.openid_cls.return_value

    def tearDown(self):
        for name, module in self._saved_modules.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module

    def make_idp(self, **kwargs):
        from django_users.idp_keycloak import KeycloakIdP
        return KeycloakIdP(**kwargs)


@override_settings(KEYCLOAK_CLIENTS=KEYCLOAK_CONFIG)
class KeycloakIdPInstantiationGuardTests(KeycloakIdPTestBase):
    def test_init_succeeds_when_fully_configured(self):
        idp = self.make_idp()
        self.assertEqual(idp.realm, "example")

    def test_init_strips_trailing_slash_from_url(self):
        idp = self.make_idp()
        self.assertEqual(idp.base_url, "https://keycloak.example.com")

    @override_settings(KEYCLOAK_CLIENTS={})
    def test_init_raises_when_users_client_missing(self):
        with self.assertRaises(ImproperlyConfigured):
            self.make_idp()

    @override_settings(KEYCLOAK_CLIENTS={"USERS": {"CLIENT_ID": "x"}})
    def test_init_raises_when_keys_missing(self):
        with self.assertRaises(ImproperlyConfigured):
            self.make_idp()

    @override_settings(KEYCLOAK_CLIENTS={"USERS": {
        "CLIENT_ID": "", "CLIENT_SECRET": "s", "URL": "https://kc", "REALM": "r"}})
    def test_init_raises_when_values_empty(self):
        with self.assertRaises(ImproperlyConfigured):
            self.make_idp()

    def test_init_raises_cleanly_when_package_missing(self):
        # Simulate python-keycloak not installed.
        sys.modules.pop("keycloak", None)
        sys.modules.pop("keycloak.exceptions", None)

        class _Block:
            def find_spec(self, name, path=None, target=None):
                if name == "keycloak" or name.startswith("keycloak."):
                    raise ImportError(f"{name} blocked")

        blocker = _Block()
        sys.meta_path.insert(0, blocker)
        try:
            with self.assertRaises(ImproperlyConfigured) as ctx:
                self.make_idp()
            self.assertIn("python-keycloak is not installed", str(ctx.exception))
        finally:
            sys.meta_path.remove(blocker)

    def test_clients_are_lazy(self):
        self.make_idp()
        self.admin_cls.assert_not_called()
        self.openid_cls.assert_not_called()


@override_settings(KEYCLOAK_CLIENTS=KEYCLOAK_CONFIG)
class KeycloakIdPBehaviourTests(KeycloakIdPTestBase):
    USER_DATA = {
        "id": "11111111-2222-3333-4444-555555555555",
        "username": "alice@example.com",
        "email": "alice@example.com",
        "firstName": "Alice",
        "lastName": "Example",
        "enabled": True,
        "emailVerified": False,
        "requiredActions": [],
    }

    def test_find_by_email_returns_dataclass(self):
        self.admin.get_user_id.return_value = self.USER_DATA["id"]
        self.admin.get_user.return_value = dict(self.USER_DATA)

        user = self.make_idp().find_by_email("alice@example.com")

        self.assertEqual(user.id, self.USER_DATA["id"])
        self.assertEqual(user.email, "alice@example.com")
        self.assertFalse(user.email_verified)

    def test_find_by_email_returns_none_when_absent(self):
        self.admin.get_user_id.return_value = None
        self.assertIsNone(self.make_idp().find_by_email("nobody@example.com"))

    def test_create_user_payload_shape(self):
        # The create payload must keep the exact shape production Keycloak
        # accepts (username mirrors email, enabled, no required actions).
        self.admin.create_user.return_value = self.USER_DATA["id"]
        self.admin.get_user.return_value = dict(self.USER_DATA)

        self.make_idp().create_user(email="alice@example.com",
                                    first_name="Alice", last_name="Example")

        self.admin.create_user.assert_called_once_with({
            "email": "alice@example.com",
            "username": "alice@example.com",
            "enabled": True,
            "firstName": "Alice",
            "lastName": "Example",
            "requiredActions": [],
        })

    def test_create_user_tolerates_409(self):
        # Existing email: production behaviour is to fetch and reuse the
        # existing Keycloak user rather than fail.
        self.admin.create_user.side_effect = _FakeKeycloakError(response_code=409)
        self.admin.get_user_id.return_value = self.USER_DATA["id"]
        self.admin.get_user.return_value = dict(self.USER_DATA)

        user = self.make_idp().create_user(email="alice@example.com")
        self.assertEqual(user.id, self.USER_DATA["id"])

    def test_set_password_is_permanent(self):
        self.make_idp().set_password(self.USER_DATA["id"], "new-password")
        self.admin.set_user_password.assert_called_once_with(
            user_id=self.USER_DATA["id"], password="new-password", temporary=False)

    def test_set_temporary_password_returns_generated(self):
        pw = self.make_idp().set_temporary_password(self.USER_DATA["id"], length=12)
        self.assertEqual(len(pw), 12)
        self.admin.set_user_password.assert_called_once_with(
            user_id=self.USER_DATA["id"], password=pw, temporary=True)

    def test_mark_email_verified_payload(self):
        # Same payload as legacy verify_user_without_email.
        self.make_idp().mark_email_verified(self.USER_DATA["id"])
        self.admin.update_user.assert_called_once_with(
            user_id=self.USER_DATA["id"],
            payload={"emailVerified": True, "enabled": True, "requiredActions": []})

    def test_verify_login_true_on_token(self):
        self.openid.token.return_value = {"access_token": "tok"}
        self.assertIs(self.make_idp().verify_login("alice@example.com", "pw"), True)
        self.openid.token.assert_called_once_with(username="alice@example.com", password="pw")

    def test_verify_login_false_on_auth_error(self):
        self.openid.token.side_effect = _FakeKeycloakAuthenticationError()
        self.assertIs(self.make_idp().verify_login("alice@example.com", "bad"), False)

    def test_is_temporary_password(self):
        self.admin.get_credentials.return_value = [
            {"type": "password", "temporary": True}]
        self.assertIs(self.make_idp().is_temporary_password(self.USER_DATA["id"]), True)

        self.admin.get_credentials.return_value = [
            {"type": "password", "temporary": False}]
        self.assertIs(self.make_idp().is_temporary_password(self.USER_DATA["id"]), False)

    def test_logout_swallows_errors(self):
        # Session may already be gone; production logged and continued.
        self.admin.user_logout.side_effect = _FakeKeycloakError()
        self.make_idp().logout(self.USER_DATA["id"])  # must not raise

    def test_errors_raise_idperror_subclass(self):
        from django_users.idp import IdPError
        from django_users.idp_keycloak import KeycloakError
        self.admin.set_user_password.side_effect = _FakeKeycloakError("boom")
        with self.assertRaises(KeycloakError) as ctx:
            self.make_idp().set_password(self.USER_DATA["id"], "pw")
        self.assertIsInstance(ctx.exception, IdPError)
