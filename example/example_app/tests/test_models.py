
from django.test import TestCase
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from ..models import Role, Person, CommsChannel, VerificationCode


User = get_user_model()

class RoleModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create(username='testuser')
        self.person = Person.objects.create(name='John Doe', user=self.user)


    def test_create_role(self):
        role, created = Role.get_or_create(role_type='A', user=self.user, person=self.person, name='Admin Role')
        self.assertTrue(created)
        self.assertEqual(role.user, self.user)
        self.assertEqual(role.person, self.person)
        self.assertEqual(role.name, 'Admin Role')

    def test_role_deletion_without_eventrole(self):
        role, _ = Role.get_or_create(role_type='A', user=self.user, person=self.person, name='Admin Role')
        role_id = role.id
        role.delete()
        with self.assertRaises(Role.DoesNotExist):
            Role.objects.get(id=role_id)


    def test_reactivate_role(self):
        role, _ = Role.get_or_create(role_type='A', user=self.user, person=self.person, name='Admin Role', active=False)
        role.active = True
        role.save()
        updated_role = Role.objects.get(id=role.id)
        self.assertTrue(updated_role.active)

    def test_user_person_consistency(self):
        another_person = Person.objects.create(name='Jane Doe')
        with self.assertRaises(ValidationError):
            Role.objects.create(role_type='A', user=self.user, person=another_person, name='Inconsistent Role')



'''
Test Code:

python
Copy code
# tests.py
from django.test import TestCase
from unittest.mock import patch, MagicMock
from .models import User

class UserModelTests(TestCase):

    @patch('your_app.models.KeycloakAdmin')
    def test_create_keycloak_user_success(self, mock_keycloak_admin):
        # Setup mock
        mock_admin_instance = mock_keycloak_admin.return_value
        mock_admin_instance.get_user_id.return_value = 'mock-keycloak-id'

        # Create a user instance
        user = User(username='testuser', email='test@example.com')
        user.set_password('password123')

        # Call the method
        user.create_keycloak_user('password123')

        # Assertions
        mock_keycloak_admin.assert_called_once()
        mock_admin_instance.create_user.assert_called_once()
        mock_admin_instance.get_user_id.assert_called_with('testuser')
        self.assertEqual(user.keycloak_id, 'mock-keycloak-id')

    @patch('your_app.models.KeycloakAdmin')
    def test_create_keycloak_user_exception(self, mock_keycloak_admin):
        # Setup mock to raise an exception
        mock_admin_instance = mock_keycloak_admin.return_value
        mock_admin_instance.create_user.side_effect = Exception('Keycloak error')

        # Create a user instance
        user = User(username='testuser', email='test@example.com')
        user.set_password('password123')

        # Call the method and assert exception handling
        with self.assertLogs('your_app.models', level='ERROR') as log:
            user.create_keycloak_user('password123')
            self.assertIn('Error creating Keycloak user', log.output[0])
            self.assertIsNone(user.keycloak_id)
Explanation:

Mocking KeycloakAdmin: We mock the KeycloakAdmin class to prevent actual calls to Keycloak.
Testing Success Case: We simulate successful user creation and check that keycloak_id is set.
Testing Exception Handling: We simulate an exception and verify that it's logged and that keycloak_id remains None.
2. Testing update_keycloak_email_verified Method
Objective:

Verify that the method updates the emailVerified attribute in Keycloak.
Ensure proper exception handling.
Test Cases:

Test Successful Update: The method should call the Keycloak API to update emailVerified.
Test Exception Handling: The method should handle exceptions gracefully.
Test Code:

python
Copy code
    @patch('your_app.models.KeycloakAdmin')
    def test_update_keycloak_email_verified_success(self, mock_keycloak_admin):
        # Setup mock
        mock_admin_instance = mock_keycloak_admin.return_value

        # Create a user instance with a keycloak_id
        user = User(username='testuser', keycloak_id='mock-keycloak-id')

        # Call the method
        user.update_keycloak_email_verified()

        # Assertions
        mock_admin_instance.update_user.assert_called_once_with('mock-keycloak-id', {'emailVerified': True})

    @patch('your_app.models.KeycloakAdmin')
    def test_update_keycloak_email_verified_exception(self, mock_keycloak_admin):
        # Setup mock to raise an exception
        mock_admin_instance = mock_keycloak_admin.return_value
        mock_admin_instance.update_user.side_effect = Exception('Keycloak error')

        # Create a user instance with a keycloak_id
        user = User(username='testuser', keycloak_id='mock-keycloak-id')

        # Call the method and assert exception handling
        with self.assertLogs('your_app.models', level='ERROR') as log:
            user.update_keycloak_email_verified()
            self.assertIn('Error updating Keycloak emailVerified status', log.output[0])
Explanation:

Mocking KeycloakAdmin: We mock the update_user method.
Testing Success Case: We ensure update_user is called with correct parameters.
Testing Exception Handling: We simulate an exception and check that it's logged.
3. Testing send_verification_code Method
Objective:

Verify that a verification code is generated and saved.
Ensure that the code is sent via the correct method (email or SMS).
Test Cases:

Test Email Verification Code Sending: The method should generate a code and call the email sending function.
Test SMS Verification Code Sending: The method should generate a code and call the SMS sending function.
Test Code:

python
Copy code
    @patch('your_app.models.send_verification_email')
    def test_send_verification_code_email(self, mock_send_email):
        # Create a user instance
        user = User(username='testuser', email='test@example.com')

        # Call the method
        user.send_verification_code('email')

        # Assertions
        self.assertIsNotNone(user.verification_code)
        mock_send_email.assert_called_once_with('test@example.com', user.verification_code)

    @patch('your_app.models.send_verification_sms')
    def test_send_verification_code_sms(self, mock_send_sms):
        # Create a user instance
        user = User(username='testuser', mobile='+123456789')

        # Call the method
        user.send_verification_code('sms')

        # Assertions
        self.assertIsNotNone(user.verification_code)
        mock_send_sms.assert_called_once_with('+123456789', user.verification_code)
Explanation:

Mocking Email/SMS Functions: We mock send_verification_email and send_verification_sms to avoid actual sending.
Testing Code Generation: We check that verification_code is set.
Testing Correct Function Calls: We ensure the correct function is called based on the method.
4. Testing verify_code Method
Objective:

Verify that the method correctly validates the verification code.
Ensure that the user's verification status is updated.
Confirm that the Keycloak emailVerified status is updated.
Test Cases:

Test Successful Verification (Email): Correct code leads to email verification and user activation.
Test Successful Verification (SMS): Correct code leads to mobile verification and user activation.
Test Incorrect Code: Incorrect code should not verify the user.
Test Code:

python
Copy code
    @patch('your_app.models.KeycloakAdmin')
    def test_verify_code_email_success(self, mock_keycloak_admin):
        # Setup mock
        mock_admin_instance = mock_keycloak_admin.return_value

        # Create a user instance
        user = User(username='testuser', email='test@example.com', verification_code='123456', is_active=False)
        user.save()

        # Call the method
        result = user.verify_code('123456', 'email')

        # Assertions
        self.assertTrue(result)
        self.assertIsNotNone(user.email_verified)
        self.assertTrue(user.is_active)
        self.assertEqual(user.verification_code, '')
        mock_admin_instance.update_user.assert_called_once_with(user.keycloak_id, {'emailVerified': True})

    @patch('your_app.models.KeycloakAdmin')
    def test_verify_code_sms_success(self, mock_keycloak_admin):
        # Similar to the email test but for SMS verification

    def test_verify_code_incorrect(self):
        # Create a user instance
        user = User(username='testuser', verification_code='123456')

        # Call the method with incorrect code
        result = user.verify_code('654321', 'email')

        # Assertions
        self.assertFalse(result)
        self.assertIsNone(user.email_verified)
        self.assertFalse(user.is_active)
Explanation:

Testing Successful Verification: We ensure that the correct code updates the user's verification status and activates the account.
Testing Incorrect Code: We check that the method returns False and no status is updated.
Mocking Keycloak Update: We mock update_keycloak_email_verified to prevent actual API calls.
5. Testing resend_verification_code Method
Objective:

Verify that a new verification code is generated and sent.
Test Code:

python
Copy code
    @patch('your_app.models.send_verification_email')
    def test_resend_verification_code(self, mock_send_email):
        # Create a user instance with an existing code
        user = User(username='testuser', email='test@example.com', verification_code='123456')

        # Call the method
        user.resend_verification_code('email')

        # Assertions
        self.assertNotEqual(user.verification_code, '123456')  # New code generated
        mock_send_email.assert_called_once_with('test@example.com', user.verification_code)
Explanation:

Testing Code Regeneration: We check that a new code is generated.
Testing Sending Mechanism: We ensure the correct sending function is called.
6. Testing is_verified Method
Objective:

Verify that the method correctly returns the user's verification status.
Test Code:

python
Copy code
    def test_is_verified_true(self):
        user = User(username='testuser', email_verified=timezone.now())
        self.assertTrue(user.is_verified())

    def test_is_verified_false(self):
        user = User(username='testuser')
        self.assertFalse(user.is_verified())
Explanation:

Testing Verified User: We set email_verified and expect is_verified() to return True.
Testing Unverified User: With no verification timestamps, is_verified() should return False.
7. Testing update_keycloak_password Method
Objective:

Verify that the method updates the user's password in Keycloak.
Test Code:

python
Copy code
    @patch('your_app.models.KeycloakAdmin')
    def test_update_keycloak_password(self, mock_keycloak_admin):
        # Setup mock
        mock_admin_instance = mock_keycloak_admin.return_value

        # Create a user instance with keycloak_id
        user = User(username='testuser', keycloak_id='mock-keycloak-id')

        # Call the method
        user.update_keycloak_password('newpassword123')

        # Assertions
        mock_admin_instance.set_user_password.assert_called_once_with('mock-keycloak-id', 'newpassword123', temporary=False)
Explanation:

Testing Password Update: We ensure that set_user_password is called with correct parameters.
8. Testing deactivate_user Method
Objective:

Verify that the user is deactivated in both Django and Keycloak.
Test Code:

python
Copy code
    @patch('your_app.models.KeycloakAdmin')
    def test_deactivate_user(self, mock_keycloak_admin):
        # Setup mock
        mock_admin_instance = mock_keycloak_admin.return_value

        # Create an active user instance with keycloak_id
        user = User(username='testuser', keycloak_id='mock-keycloak-id', is_active=True)
        user.save()

        # Call the method
        user.deactivate_user()

        # Assertions
        self.assertFalse(user.is_active)
        mock_admin_instance.update_user.assert_called_once_with('mock-keycloak-id', {'enabled': False})
Explanation:

Testing Deactivation: We check that the user's is_active status is set to False and that Keycloak is updated.
Additional Considerations
Test Setup and Teardown:

Use setUp and tearDown methods to create and clean up any test data needed for your tests.
Mocking External Services:

Always mock external dependencies to prevent tests from failing due to external factors and to speed up test execution.
Testing Asynchronous Tasks:

If you use Celery for asynchronous tasks, consider using django-celery-results and configuring Celery to run tasks synchronously during testing.
python
Copy code
# settings.py
CELERY_TASK_ALWAYS_EAGER = True
Logging:

Use assertLogs to verify that exceptions are logged appropriately.
Edge Cases:

Test edge cases, such as missing data or invalid inputs, to ensure your methods handle them gracefully.
Test Coverage:

Use coverage tools to ensure that your tests cover all the code paths in your methods.
Example of Full Test Class
Here's how your tests.py might look with all the tests included:

python
Copy code
# tests.py
from django.test import TestCase
from unittest.mock import patch, MagicMock
from django.utils import timezone
from .models import User

class UserModelTests(TestCase):

    @patch('your_app.models.KeycloakAdmin')
    def test_create_keycloak_user_success(self, mock_keycloak_admin):
        # ... (as above)

    @patch('your_app.models.KeycloakAdmin')
    def test_create_keycloak_user_exception(self, mock_keycloak_admin):
        # ... (as above)

    @patch('your_app.models.KeycloakAdmin')
    def test_update_keycloak_email_verified_success(self, mock_keycloak_admin):
        # ... (as above)

    @patch('your_app.models.KeycloakAdmin')
    def test_update_keycloak_email_verified_exception(self, mock_keycloak_admin):
        # ... (as above)

    @patch('your_app.models.send_verification_email')
    def test_send_verification_code_email(self, mock_send_email):
        # ... (as above)

    @patch('your_app.models.send_verification_sms')
    def test_send_verification_code_sms(self, mock_send_sms):
        # ... (as above)

    @patch('your_app.models.KeycloakAdmin')
    def test_verify_code_email_success(self, mock_keycloak_admin):
        # ... (as above)

    def test_verify_code_incorrect(self):
        # ... (as above)

    @patch('your_app.models.send_verification_email')
    def test_resend_verification_code(self, mock_send_email):
        # ... (as above)

    def test_is_verified_true(self):
        # ... (as above)

    def test_is_verified_false(self):
        # ... (as above)

    @patch('your_app.models.KeycloakAdmin')
    def test_update_keycloak_password(self, mock_keycloak_admin):
        # ... (as above)

    @patch('your_app.models.KeycloakAdmin')
    def test_deactivate_user(self, mock_keycloak_admin):
        # ... (as above)

'''

class CommsChannelModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='user@example.com',
            password='password123'
        )

    def test_create_comms_channel(self):
        channel = CommsChannel.objects.create(
            user=self.user,
            channel_type='email',
            value='user@example.com'
        )
        self.assertEqual(channel.user, self.user)
        self.assertEqual(channel.channel_type, 'email')
        self.assertEqual(channel.value, 'user@example.com')
        self.assertIsNone(channel.verified_at)

    def test_channel_is_verified_method(self):
        channel = CommsChannel.objects.create(
            user=self.user,
            channel_type='email',
            value='user@example.com',
            verified_at=timezone.now()
        )
        self.assertTrue(channel.is_verified())

    def test_channel_is_not_verified(self):
        channel = CommsChannel.objects.create(
            user=self.user,
            channel_type='email',
            value='user@example.com'
        )
        self.assertFalse(channel.is_verified())

    def test_unique_together_constraint(self):
        CommsChannel.objects.create(
            user=self.user,
            channel_type='email',
            value='user@example.com'
        )
        with self.assertRaises(Exception):
            CommsChannel.objects.create(
                user=self.user,
                channel_type='email',
                value='user@example.com'
            )

class VerificationCodeModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='user@example.com',
            password='password123'
        )
        self.channel = CommsChannel.objects.create(
            user=self.user,
            channel_type='email',
            value='user@example.com'
        )

    def test_create_verification_code(self):
        code = '123456'
        expires_at = timezone.now() + timezone.timedelta(minutes=10)
        verification_code = VerificationCode.objects.create(
            user=self.user,
            channel=self.channel,
            code=code,
            expires_at=expires_at
        )
        self.assertEqual(verification_code.user, self.user)
        self.assertEqual(verification_code.channel, self.channel)
        self.assertEqual(verification_code.code, code)
        self.assertEqual(verification_code.expires_at, expires_at)
        self.assertEqual(verification_code.attempts, 0)

    def test_verification_code_is_expired(self):
        code = VerificationCode.objects.create(
            user=self.user,
            channel=self.channel,
            code='123456',
            expires_at=timezone.now() - timezone.timedelta(minutes=1)
        )
        self.assertTrue(code.is_expired())

    def test_verification_code_is_not_expired(self):
        code = VerificationCode.objects.create(
            user=self.user,
            channel=self.channel,
            code='123456',
            expires_at=timezone.now() + timezone.timedelta(minutes=10)
        )
        self.assertFalse(code.is_expired())
