# users/tests/test_forms.py

from django.test import TestCase
from users.forms import SignUpForm, CommsChannelForm


class SignUpFormTest(TestCase):
    def test_valid_form_email(self):
        form_data = {
            'first_name': 'Test',
            'last_name': 'User',
            'email': 'user@example.com',
            'password1': 'password123',
            'password2': 'password123',
            'preferred_channel': 'email',
        }
        form = SignUpForm(data=form_data)
        self.assertTrue(form.is_valid())

    def test_valid_form_sms(self):
        form_data = {
            'first_name': 'Test',
            'last_name': 'User',
            'email': 'user@example.com',
            'password1': 'password123',
            'password2': 'password123',
            'preferred_channel': 'sms',
            'phone_number': '+1234567890',
        }
        form = SignUpForm(data=form_data)
        self.assertTrue(form.is_valid())

    def test_missing_phone_number_for_sms(self):
        form_data = {
            'first_name': 'Test',
            'last_name': 'User',
            'email': 'user@example.com',
            'password1': 'password123',
            'password2': 'password123',
            'preferred_channel': 'sms',
        }
        form = SignUpForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn('phone_number', form.errors)

    def test_form_with_preferred_channel_and_phone(self):
        form_data = {
            'first_name': 'Alice',
            'last_name': 'Smith',
            'email': 'alice@example.com',
            'password1': 'strongpassword123',
            'password2': 'strongpassword123',
            'preferred_channel': 'sms',
            'phone_number': '+1234567890',
        }
        form = SignUpForm(data=form_data)
        self.assertTrue(form.is_valid())

    def test_form_missing_phone_number_for_sms(self):
        form_data = {
            'first_name': 'Bob',
            'last_name': 'Jones',
            'email': 'bob@example.com',
            'password1': 'strongpassword123',
            'password2': 'strongpassword123',
            'preferred_channel': 'sms',
        }
        form = SignUpForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn('phone_number', form.errors)

class CommsChannelFormTest(TestCase):
    def test_valid_email_channel_form(self):
        form_data = {
            'channel_type': 'email',
            'value': 'user@example.com',
        }
        form = CommsChannelForm(data=form_data)
        form_valid = form.is_valid()
        self.assertTrue(form_valid)

    def test_valid_sms_channel_form(self):
        form_data = {
            'channel_type': 'sms',
            'value': '+1234567890',
        }
        form = CommsChannelForm(data=form_data)
        self.assertTrue(form.is_valid())

    def test_invalid_channel_type(self):
        form_data = {
            'channel_type': 'invalid',
            'value': 'user@example.com',
        }
        form = CommsChannelForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn('channel_type', form.errors)
