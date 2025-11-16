# users/tests/test_views.py

from django.test import TestCase, Client
from django.urls import reverse
from unittest.mock import patch, MagicMock
from django.utils import timezone
from users.models import CustomUser, CommsChannel, VerificationCode
from django.conf import settings


class SignUpViewTest(TestCase):
    def setUp(self):
        self.client = Client()

    @patch('users.views.create_keycloak_user')
    @patch('users.views.send_email_verification_code')
    def test_signup_with_email(self, mock_send_email, mock_keycloak):
        mock_keycloak.return_value = ('keycloak-id', 201)
        form_data = {
            'first_name': 'Test',
            'last_name': 'User',
            'email': 'user@example.com',
            'password1': 'password123',
            'password2': 'password123',
            'preferred_channel': 'email',
        }
        response = self.client.post(reverse('users:signup'), data=form_data)
        self.assertEqual(response.status_code, 302)  # Redirect after successful signup
        user = CustomUser.objects.get(email='user@example.com')
        self.assertFalse(user.is_active)
        self.assertEqual(user.keycloak_id, 'keycloak-id')
        mock_send_email.assert_called_once()
        mock_keycloak.assert_called_once()

    @patch('users.views.create_keycloak_user')
    @patch('users.views.send_sms_verification_code')
    def test_signup_with_sms(self, mock_send_sms, mock_keycloak):
        mock_keycloak.return_value = ('keycloak-id', 201)
        form_data = {
            'first_name': 'Test',
            'last_name': 'User',
            'email': 'user@example.com',
            'password1': 'password123',
            'password2': 'password123',
            'preferred_channel': 'sms',
            'phone_number': '+1234567890',
        }
        response = self.client.post(reverse('users:signup'), data=form_data)
        self.assertEqual(response.status_code, 302)
        user = CustomUser.objects.get(email='user@example.com')
        self.assertFalse(user.is_active)
        mock_send_sms.assert_called_once()
        mock_keycloak.assert_called_once()

    @patch('users.views.create_keycloak_user')
    def test_signup_keycloak_failure(self, mock_keycloak):
        mock_keycloak.return_value = (None, 500)
        form_data = {
            'first_name': 'Test',
            'last_name': 'User',
            'email': 'user@example.com',
            'password1': 'password123',
            'password2': 'password123',
            'preferred_channel': 'email',
        }
        response = self.client.post(reverse('users:signup'), data=form_data)
        self.assertEqual(response.status_code, 200)  # Rendered signup page with error
        self.assertContains(response, 'Failed to create user account. Please try again later.')
        self.assertFalse(CustomUser.objects.filter(email='user@example.com').exists())

    @patch('users.views.create_keycloak_user')
    @patch('users.views.send_sms_verification_code')
    def test_signup_creates_sms_channel_when_phone_provided(self, mock_send_sms, mock_create_keycloak_user):
        mock_create_keycloak_user.return_value = ('keycloak_id', 201)
        form_data = {
            'first_name': 'Charlie',
            'last_name': 'Brown',
            'email': 'charlie@example.com',
            'password1': 'strongpassword123',
            'password2': 'strongpassword123',
            'preferred_channel': 'email',
            'phone_number': '+1234567890',
        }
        response = self.client.post(reverse('users:signup'), data=form_data)
        self.assertEqual(response.status_code, 302)
        user = CustomUser.objects.get(email='charlie@example.com')
        self.assertEqual(user.preferred_channel, 'email')
        self.assertTrue(CommsChannel.objects.filter(user=user, channel_type='sms').exists())
        mock_send_sms.assert_not_called()  # Because preferred channel is email

class VerificationViewTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = CustomUser.objects.create_user(
            username='user@example.com',
            email='user@example.com',
            password='password123',
            is_active=False
        )
        self.channel = CommsChannel.objects.create(
            user=self.user,
            channel_type='email',
            value='user@example.com'
        )
        self.code = '123456'
        self.verification_code = VerificationCode.objects.create(
            user=self.user,
            channel=self.channel,
            code=self.code,
            expires_at=timezone.now() + timezone.timedelta(minutes=10)
        )

    @patch('users.views.set_keycloak_user_email_verified')
    def test_successful_verification(self, mock_keycloak_email_verified):
        response = self.client.post(reverse('users:verify', args=[self.user.id]), data={'code': self.code})
        self.user.refresh_from_db()
        self.channel.refresh_from_db()
        self.assertTrue(self.user.is_active)
        self.assertIsNotNone(self.channel.verified_at)
        self.assertRedirects(response, reverse('home'))
        mock_keycloak_email_verified.assert_called_once_with(self.user.keycloak_id)

    def test_verification_with_invalid_code(self):
        response = self.client.post(reverse('users:verify', args=[self.user.id]), data={'code': '000000'})
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_active)
        self.assertContains(response, 'Invalid or expired verification code.')

    def test_verification_with_expired_code(self):
        self.verification_code.expires_at = timezone.now() - timezone.timedelta(minutes=1)
        self.verification_code.save()
        response = self.client.post(reverse('users:verify', args=[self.user.id]), data={'code': self.code})
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_active)
        self.assertContains(response, 'Invalid or expired verification code.')

    @patch('users.views.send_email_verification_code')
    def test_resend_verification_code(self, mock_send_email):
        response = self.client.post(reverse('users:verify', args=[self.user.id]), data={'resend_code': '1'})
        self.assertRedirects(response, reverse('users:verify', args=[self.user.id]))
        mock_send_email.assert_called_once()
        self.assertContains(response, 'A new verification code has been sent.')

class AddCommsChannelViewTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = CustomUser.objects.create_user(
            username='user@example.com',
            email='user@example.com',
            password='password123',
            is_active=True
        )
        self.client.login(username='user@example.com', password='password123')

    @patch('users.views.send_sms_verification_code')
    def test_add_sms_channel(self, mock_send_sms):
        form_data = {
            'channel_type': 'sms',
            'value': '+1234567890',
        }
        response = self.client.post(reverse('users:add_channel'), data=form_data)
        self.assertEqual(response.status_code, 302)
        channel = CommsChannel.objects.get(user=self.user, channel_type='sms')
        self.assertIsNotNone(channel)
        mock_send_sms.assert_called_once()
        self.assertRedirects(response, reverse('users:verify_channel', args=[channel.id]))

    def test_add_invalid_channel(self):
        form_data = {
            'channel_type': 'invalid',
            'value': 'user@example.com',
        }
        response = self.client.post(reverse('users:add_channel'), data=form_data)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Select a valid choice')

class VerifyChannelViewTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = CustomUser.objects.create_user(
            username='user@example.com',
            email='user@example.com',
            password='password123',
            is_active=True
        )
        self.client.login(username='user@example.com', password='password123')
        self.channel = CommsChannel.objects.create(
            user=self.user,
            channel_type='sms',
            value='+1234567890'
        )
        self.code = '654321'
        self.verification_code = VerificationCode.objects.create(
            user=self.user,
            channel=self.channel,
            code=self.code,
            expires_at=timezone.now() + timezone.timedelta(minutes=10)
        )

    def test_successful_channel_verification(self):
        response = self.client.post(reverse('users:verify_channel', args=[self.channel.id]), data={'code': self.code})
        self.channel.refresh_from_db()
        self.assertIsNotNone(self.channel.verified_at)
        self.assertRedirects(response, reverse('users:user-profile'))
        self.assertContains(response, 'Communication channel has been verified.')

    def test_channel_verification_with_invalid_code(self):
        response = self.client.post(reverse('users:verify_channel', args=[self.channel.id]), data={'code': '000000'})
        self.channel.refresh_from_db()
        self.assertIsNone(self.channel.verified_at)
        self.assertContains(response, 'Invalid or expired verification code.')

class CustomLoginViewTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.active_user = CustomUser.objects.create_user(
            username='active@example.com',
            email='active@example.com',
            password='password123',
            is_active=True
        )
        self.inactive_user = CustomUser.objects.create_user(
            username='inactive@example.com',
            email='inactive@example.com',
            password='password123',
            is_active=False
        )

    def test_login_active_user(self):
        response = self.client.post(reverse('login'), data={
            'username': 'active@example.com',
            'password': 'password123'
        })
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('home'))

    def test_login_inactive_user(self):
        response = self.client.post(reverse('login'), data={
            'username': 'inactive@example.com',
            'password': 'password123'
        })
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('users:verify', args=[self.inactive_user.id]))
        self.assertContains(response, 'Your account is inactive. Please verify your account.')
