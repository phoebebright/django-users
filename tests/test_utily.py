# users/tests/test_utils.py

from django.test import TestCase
from unittest.mock import patch, MagicMock

from django.utils import timezone

from users.utils import send_email_verification_code, send_whatsapp_verification_code
from django.test import TestCase, Client
from django.urls import reverse
from users.models import CustomUser, CommsChannel, VerificationCode
from django.core.cache import cache

class SendEmailVerificationCodeTest(TestCase):
    @patch('users.utils.mail.send')
    def test_send_email_verification_code(self, mock_mail_send):
        email = 'user@example.com'
        code = '123456'
        send_email_verification_code(email, code)
        mock_mail_send.assert_called_once()
        args, kwargs = mock_mail_send.call_args
        self.assertEqual(kwargs['recipient_list'], [email])
        self.assertIn(code, kwargs['message'])

from unittest.mock import patch
from users.utils import send_sms_verification_code

class SendSMSVerificationCodeTest(TestCase):
    @patch('users.utils.Client')
    def test_send_sms_verification_code(self, mock_twilio_client):
        phone_number = '+1234567890'
        code = '123456'
        mock_twilio_instance = MagicMock()
        mock_twilio_client.return_value = mock_twilio_instance

        send_sms_verification_code(phone_number, code)

        mock_twilio_instance.messages.create.assert_called_once()
        args, kwargs = mock_twilio_instance.messages.create.call_args
        self.assertEqual(kwargs['to'], phone_number)
        self.assertIn(code, kwargs['body'])

class SendWhatsAppVerificationCodeTest(TestCase):
    @patch('users.utils.Client')
    def test_send_whatsapp_verification_code(self, mock_twilio_client):
        phone_number = '+1234567890'
        code = '123456'
        mock_twilio_instance = MagicMock()
        mock_twilio_client.return_value = mock_twilio_instance

        send_whatsapp_verification_code(phone_number, code)

        mock_twilio_instance.messages.create.assert_called_once()
        args, kwargs = mock_twilio_instance.messages.create.call_args
        self.assertEqual(kwargs['to'], f'whatsapp:{phone_number}')
        self.assertIn(code, kwargs['body'])



class RateLimitingTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = CustomUser.objects.create_user(
            username='user@example.com',
            email='user@example.com',
            password='password123',
            is_active=False
        )

    def test_resend_verification_code_rate_limiting(self):
        url = reverse('users:verify', args=[self.user.id])
        for _ in range(5):
            response = self.client.post(url, data={'resend_code': '1'})
            self.assertNotEqual(response.status_code, 429)  # Not rate limited yet

        # Next request should be rate limited
        response = self.client.post(url, data={'resend_code': '1'})
        self.assertEqual(response.status_code, 429)
        self.assertContains(response, 'Too many requests', status_code=429)

        # Clear cache for other tests
        cache.clear()

class ExpiredVerificationCodeTest(TestCase):
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
            expires_at=timezone.now() - timezone.timedelta(minutes=1)  # Already expired
        )

    def test_verification_with_expired_code(self):
        response = self.client.post(reverse('users:verify', args=[self.user.id]), data={'code': self.code})
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_active)
        self.assertContains(response, 'Invalid or expired verification code.')

class DuplicateSignUpTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user_data = {
            'username': 'user@example.com',
            'email': 'user@example.com',
            'password': 'password123',
            'is_active': False
        }
        self.user = CustomUser.objects.create_user(**self.user_data)

    def test_signup_with_existing_email_inactive_user(self):
        form_data = {
            'first_name': 'Test',
            'last_name': 'User',
            'email': self.user.email,
            'password1': 'password123',
            'password2': 'password123',
            'preferred_channel': 'email',
        }
        response = self.client.post(reverse('users:signup'), data=form_data)
        self.assertRedirects(response, reverse('users:verify', args=[self.user.id]))
        self.assertContains(response, 'An account with this email already exists but is not verified.')

    def test_signup_with_existing_email_active_user(self):
        self.user.is_active = True
        self.user.save()
        form_data = {
            'first_name': 'Test',
            'last_name': 'User',
            'email': self.user.email,
            'password1': 'password123',
            'password2': 'password123',
            'preferred_channel': 'email',
        }
        response = self.client.post(reverse('users:signup'), data=form_data)
        self.assertRedirects(response, reverse('login'))
        self.assertContains(response, 'An account with this email already exists. Please log in.')
