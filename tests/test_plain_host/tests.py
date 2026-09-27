"""The package on a plain-Django host shaped like BuiltAir (decision 003).

Each test is a fault found moving BuiltAir onto 3.1.1 (BuiltAir HD-0154).
Every one stopped a non-skorie host working, and none showed on a skorie host:
- A. saving a user recursed forever on a field-tracking user model (.only());
- B. issuing or verifying a code raised LookupError, because `django_users`
  is not an installed app;
- C. the profile page redirected through skorie's users:tell_us_about;
- D. forgot-password read an undeclared setting;
- E. verification read user.idp_id, which the Basic user base lacked.
"""
from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from users.models import CommsChannel, VerificationCode

User = get_user_model()


class PlainHostTests(TestCase):
    PASSWORD = "testpass123"

    def make_user(self, email="plain@test.com"):
        return User.objects.create_user(email=email, password=self.PASSWORD)

    def test_A_users_can_be_created_and_resaved(self):
        user = self.make_user()
        user.email = "changed@test.com"
        user.save()   # the path that loads the previous row
        user.refresh_from_db()
        self.assertEqual(user.email, "changed@test.com")

    def test_A_changing_email_clears_its_verification(self):
        from django.utils import timezone
        user = self.make_user()
        User.objects.filter(pk=user.pk).update(email_verified_at=timezone.now())
        user.refresh_from_db()
        user.email = "new@test.com"
        user.save()
        user.refresh_from_db()
        self.assertIsNone(user.email_verified_at)

    def test_B_E_code_is_issued_and_verified(self):
        user = self.make_user()
        channel = CommsChannel.objects.get(user=user, channel_type="email")  # made on create
        row, info = VerificationCode.create_for_code(user, channel)
        self.assertTrue(row.code_hash)
        self.assertTrue(VerificationCode.verify_code(user=user, channel=channel, code=info["code"]))

    def test_E_idp_id_is_none_on_plain_django(self):
        self.assertIsNone(self.make_user().idp_id)

    def test_E_channel_verify(self):
        user = self.make_user()
        channel = CommsChannel.objects.get(user=user, channel_type="email")  # made on create
        channel.verify()
        user.refresh_from_db()
        self.assertIsNotNone(user.email_verified_at)

    def test_C_profile_page_without_a_confirm_page(self):
        self.make_user()
        client = Client()
        client.login(email="plain@test.com", password=self.PASSWORD)
        self.assertEqual(client.get(reverse("users:user-profile")).status_code, 200)

    def test_C_profile_page_sends_anonymous_to_login(self):
        response = Client().get(reverse("users:user-profile"))
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response["Location"].startswith("/users/login/"))

    def test_D_forgot_password_without_the_magic_link_setting(self):
        self.assertEqual(Client().get(reverse("users:forgot_password")).status_code, 200)


class LoginNormalisationTests(TestCase):
    """3.1.3: login looked up the account with a DNS deliverability check, and an
    address that failed it made login a 500. BuiltAir's own password-reset tests
    use pwtest.com, which accepts no mail, and caught it."""
    PASSWORD = "testpass123"

    def setUp(self):
        User.objects.create_user(email="someone@pwtest.com", password=self.PASSWORD)

    def test_login_does_not_ask_dns(self):
        from unittest import mock
        import django_users.utils as utils
        with mock.patch.object(utils, "validate_email", wraps=utils.validate_email) as spy:
            response = Client().post(reverse("users:login"), {
                "email": "someone@pwtest.com", "password": self.PASSWORD})
        self.assertEqual(response.status_code, 302)
        self.assertFalse(spy.call_args.kwargs["check_deliverability"])

    def test_an_unusable_address_is_a_failed_login_not_a_500(self):
        response = Client().post(reverse("users:login"), {"email": "not an email", "password": "x"})
        self.assertEqual(response.status_code, 200)
        response = Client().post(reverse("users:login"), {"password": "x"})
        self.assertEqual(response.status_code, 200)

    def test_new_addresses_are_still_checked(self):
        from unittest import mock
        import django_users.utils as utils
        with mock.patch.object(utils, "validate_email") as fake:
            fake.return_value.normalized = "new@pwtest.com"
            utils.normalise_email("new@pwtest.com")
        self.assertTrue(fake.call_args.kwargs["check_deliverability"])
