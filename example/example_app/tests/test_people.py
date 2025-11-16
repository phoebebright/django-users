# users/tests/test_user_person_role.py

from django.test import TestCase
from django.core.exceptions import ValidationError
from django.apps import apps
from django.conf import settings
from django.utils.module_loading import import_string

from ..models import Person, CustomUser, Role, Organisation, PersonOrganisation


class UserPersonRoleRulesTests(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.Person = Person
        cls.CustomUser = CustomUser
        cls.Role = Role
        cls.Organisation = Organisation
        cls.PersonOrganisation = PersonOrganisation

        # Import your ModelRoles helper so we can use real role codes
        cls.ModelRoles = import_string(settings.MODEL_ROLES_PATH)
        clsDisciplines = import_string(settings.DISCIPLINES_PATH)


        # Simple org for tests
        cls.org = cls.Organisation.objects.create(
            name="Test Club",
            code="TEST",
            scoring_type='D',
        )

    def test_user_auto_gets_person_on_save(self):
        """Creating a user without person should create and link a Person."""
        user = self.CustomUser.objects.create_user(
            email="user1@example.com",
            password="pass",
            organisation=self.org,
        )

        self.assertIsNotNone(user.person)
        self.assertEqual(user.person.formal_name, "user1")  # from email prefix by create_from_user
        self.assertEqual(user.person.user, user)  # primary/back-link set

    def test_role_with_user_only_infers_person_from_user(self):
        """Role(user=X, person=None) should auto-set person=user.person."""
        user = self.CustomUser.objects.create_user(
            email="user2@example.com",
            password="pass",
            organisation=self.org,
        )
        role = self.Role.objects.create(
            user=user,
            role_type=self.ModelRoles.ROLE_MANAGER,
            name="Manager without person",
        )

        role.refresh_from_db()
        self.assertEqual(role.person, user.person)

    def test_role_with_person_only_infers_user_if_single_user_for_person(self):
        """
        If a Person has exactly one CustomUser, Role(person=P, user=None)
        should auto-set user to that CustomUser.
        """
        # Create a user with a person
        user = self.CustomUser.objects.create_user(
            email="user3@example.com",
            password="pass",
            organisation=self.org,
        )
        person = user.person

        # Sanity check: this person has exactly one user
        self.assertEqual(self.CustomUser.objects.filter(person=person).count(), 1)

        role = self.Role.objects.create(
            person=person,
            role_type=self.ModelRoles.ROLE_MANAGER,
            name="Manager from person only",
        )

        role.refresh_from_db()
        self.assertEqual(role.user, user)
        self.assertEqual(role.person, person)

    def test_role_does_not_infer_user_when_person_has_multiple_users(self):
        """
        If a Person has multiple users, Role with person only should NOT
        auto-infer a user (to avoid guessing wrong).
        """
        # Manually create a person
        person = self.Person.objects.create(
            formal_name="Multi User Person",
            friendly_name="Multi",
            sortable_name="person multi",
        )

        # Attach two users to the same person
        user1 = self.CustomUser.objects.create_user(
            email="multi1@example.com",
            password="pass",
            organisation=self.org,
        )
        user2 = self.CustomUser.objects.create_user(
            email="multi2@example.com",
            password="pass",
            organisation=self.org,
        )

        # Repoint both users to the same person to simulate cleanup state
        user1.person = person
        user1.save()
        user2.person = person
        user2.save()

        # Now create a role with only person
        role = self.Role.objects.create(
            person=person,
            role_type=self.ModelRoles.ROLE_MANAGER,
            name="Ambiguous user role",
        )

        role.refresh_from_db()
        # We should *not* have auto-inferred a user in this ambiguous case
        self.assertIsNone(role.user)
        self.assertEqual(role.person, person)

    def test_role_raises_if_user_and_person_disagree(self):
        """
        If both user and person are set and user.person != person,
        saving the role must raise ValidationError.
        """
        # Create two distinct users, each with their own person
        user1 = self.CustomUser.objects.create_user(
            email="u1@example.com", password="pass", organisation=self.org
        )
        user2 = self.CustomUser.objects.create_user(
            email="u2@example.com", password="pass", organisation=self.org
        )

        # Guard sanity
        self.assertNotEqual(user1.person, user2.person)

        role = self.Role(
            user=user1,
            person=user2.person,  # mismatched on purpose
            role_type=self.ModelRoles.ROLE_MANAGER,
            name="Bad combo",
        )

        with self.assertRaises(ValidationError):
            role.save()

    def test_role_infers_organisation_from_user_when_missing(self):
        """
        If Role has a user with an organisation and organisation is None,
        it should default organisation from the user.
        """
        user = self.CustomUser.objects.create_user(
            email="user4@example.com",
            password="pass",
            organisation=self.org,
        )

        role = self.Role.objects.create(
            user=user,
            role_type=self.ModelRoles.ROLE_MANAGER,
            name="Org from user",
        )

        role.refresh_from_db()
        self.assertEqual(role.organisation, self.org)

    def test_role_does_not_overwrite_existing_organisation_from_user(self):
        """
        If Role already has an organisation set, saving should not overwrite
        it with user.organisation.
        """
        other_org = self.Organisation.objects.create(
            name="Other Org",
            code="OTHER",
            scoring_type='D',
        )

        user = self.CustomUser.objects.create_user(
            email="user5@example.com",
            password="pass",
            organisation=self.org,
        )

        role = self.Role.objects.create(
            user=user,
            organisation=other_org,
            role_type=self.ModelRoles.ROLE_MANAGER,
            name="Preserve org",
        )

        role.refresh_from_db()
        self.assertEqual(role.organisation, other_org)

    def test_person_can_have_multiple_users_and_roles_link_to_specific_user(self):
        """
        A Person may have multiple users, and Roles can be attached to any of
        those users, provided Role.person matches Role.user.person.
        """
        # One person
        person = self.Person.objects.create(
            formal_name="Real Human",
            friendly_name="Human",
            sortable_name="human real",
        )

        # Two logins for same person
        user_admin = self.CustomUser.objects.create_user(
            email="admin@example.com",
            password="pass",
            organisation=self.org,
        )
        user_comp = self.CustomUser.objects.create_user(
            email="comp@example.com",
            password="pass",
            organisation=self.org,
        )

        user_admin.person = person
        user_admin.save()
        user_comp.person = person
        user_comp.save()

        # Admin role on admin user
        role_admin = self.Role.objects.create(
            person=person,
            user=user_admin,
            role_type=self.ModelRoles.ROLE_ADMINISTRATOR,
            name="Admin role",
        )

        # Manager/competitor role on competitor user
        role_comp = self.Role.objects.create(
            person=person,
            user=user_comp,
            role_type=self.ModelRoles.ROLE_COMPETITOR,
            name="Competitor role",
        )

        self.assertEqual(role_admin.person, person)
        self.assertEqual(role_comp.person, person)
        self.assertEqual(role_admin.user, user_admin)
        self.assertEqual(role_comp.user, user_comp)
