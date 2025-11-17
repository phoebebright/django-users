# users/tests/test_user_person_role.py
from django.contrib.auth import get_user_model
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import TestCase, RequestFactory
from django.core.exceptions import ValidationError
from django.apps import apps
from django.conf import settings
from django.utils.module_loading import import_string

from ..models import Person, CustomUser, Role, Organisation, PersonOrganisation


class CurrentOrganisationTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.User = get_user_model()
        cls.Person = apps.get_model("users", "Person")
        cls.Organisation = apps.get_model("users", "Organisation")
        cls.PersonOrganisation = apps.get_model("users", "PersonOrganisation")

        # Organisations
        cls.org1 = cls.Organisation.objects.create(code="ORG1", name="Org One")
        cls.org2 = cls.Organisation.objects.create(code="ORG2", name="Org Two")
        cls.org3 = cls.Organisation.objects.create(code="ORG3", name="Org Three")

        # User with a single org membership (org1)
        cls.user_single = cls.User.objects.create_user(
            email="single@example.com",
            password="testpass123",
        )
        # Make sure we have a Person instance
        person_single = cls.user_single.person
        cls.PersonOrganisation.objects.create(person=person_single, organisation=cls.org1)

        # User with two org memberships (org1, org2)
        cls.user_multi = cls.User.objects.create_user(
            email="multi@example.com",
            password="testpass123",
        )
        person_multi = cls.user_multi.person
        cls.PersonOrganisation.objects.create(person=person_multi, organisation=cls.org1)
        cls.PersonOrganisation.objects.create(person=person_multi, organisation=cls.org2)

        # User with no org memberships
        cls.user_none = cls.User.objects.create_user(
            email="none@example.com",
            password="testpass123",
        )

        cls.factory = RequestFactory()

    # ----- helpers ----------------------------------------------------------

    def _request_with_session_for_user(self, user):
        """
        Build a request with a working session and attached user.
        """
        request = self.factory.get("/")
        # Attach session
        middleware = SessionMiddleware(lambda r: None)
        middleware.process_request(request)
        request.session.save()

        request.user = user
        return request

    # ----- organisations property ------------------------------------------

    def test_organisations_property_single(self):
        """User with one membership should see exactly one organisation."""
        orgs = list(self.user_single.organisations)
        self.assertEqual(len(orgs), 1)
        self.assertEqual(orgs[0], self.org1)

    def test_organisations_property_multiple(self):
        """User with multiple memberships should see all of them."""
        orgs = list(self.user_multi.organisations.order_by("code"))
        self.assertEqual(orgs, [self.org1, self.org2])

    def test_organisations_property_none(self):
        """User with no memberships should return an empty queryset."""
        orgs = list(self.user_none.organisations)
        self.assertEqual(orgs, [])

    # ----- get_current_organisation: default behaviour ---------------------

    def test_get_current_org_single_user_auto_sets_session(self):
        """
        For a user with a single organisation and no session set, get_current_organisation
        should return that org and populate the session.
        """
        user = self.user_single
        request = self._request_with_session_for_user(user)

        org = user.get_current_organisation(request)

        self.assertEqual(org, self.org1)
        # Session should now contain the org code
        self.assertEqual(
            request.session[user.SESSION_KEY_CURRENT_ORG],
            self.org1.code,
        )

    def test_get_current_org_multi_user_without_session_uses_default(self):
        """
        For a user with multiple orgs and no session:
        - get_current_organisation should fall back to get_default_organisation()
        - by default we expect None (since there is no single obvious org)
        """
        user = self.user_multi
        request = self._request_with_session_for_user(user)

        org = user.get_current_organisation(request)

        # With the default implementation we discussed, multi-org users have no clear default.
        # If you later change get_default_organisation to prefer org1, you'll update this assert.
        self.assertIsNone(org)
        self.assertNotIn(user.SESSION_KEY_CURRENT_ORG, request.session)

    def test_get_current_org_no_memberships_returns_none(self):
        """User with no memberships should get None and no session key."""
        user = self.user_none
        request = self._request_with_session_for_user(user)

        org = user.get_current_organisation(request)

        self.assertIsNone(org)
        self.assertNotIn(user.SESSION_KEY_CURRENT_ORG, request.session)

    # ----- set_current_organisation + read-back ----------------------------

    def test_set_and_get_current_org_for_multi_user(self):
        """
        Explicitly setting current org should store it in the session and
        get_current_organisation should return it.
        """
        user = self.user_multi
        request = self._request_with_session_for_user(user)

        # Precondition: user belongs to org2
        self.assertIn(self.org2, list(user.organisations))

        user.set_current_organisation(request, self.org2)

        # Session should now have org2
        self.assertEqual(
            request.session[user.SESSION_KEY_CURRENT_ORG],
            self.org2.code,
        )

        org = user.get_current_organisation(request)
        self.assertEqual(org, self.org2)

    def test_set_current_org_clears_when_none(self):
        """
        Setting current organisation to None should remove the key from session.
        """
        user = self.user_single
        request = self._request_with_session_for_user(user)

        # Set a current org first
        user.set_current_organisation(request, self.org1)
        self.assertIn(user.SESSION_KEY_CURRENT_ORG, request.session)

        # Now clear it
        user.set_current_organisation(request, None)
        self.assertNotIn(user.SESSION_KEY_CURRENT_ORG, request.session)

    # ----- invalid / non-member org in session -----------------------------

    def test_get_current_org_ignores_session_org_user_does_not_belong_to(self):
        """
        If the session holds an org code that the user is not a member of,
        get_current_organisation should ignore it and fall back to default logic.
        """
        user = self.user_single
        request = self._request_with_session_for_user(user)

        # Put an invalid org code into the session
        request.session[user.SESSION_KEY_CURRENT_ORG] = self.org3.code  # user_single not a member of org3

        org = user.get_current_organisation(request)

        # Should ignore org3 and fall back to default (org1 for single-org user)
        self.assertEqual(org, self.org1)
        self.assertEqual(
            request.session[user.SESSION_KEY_CURRENT_ORG],
            self.org1.code,
        )

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
