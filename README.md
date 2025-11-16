Django-users shares the common functionality used in particular by skorie but potentially other projects as well.

Note this is not (yet?) a standard app.  It expects you to create your own users app and use these base models.  In order to use the templates, add this to settings:



    def app_templates_dir(app_label: str) -> Path:
        pkg = importlib.import_module(app_label)
        return Path(pkg.__file__).resolve().parent / "templates"
    
    USERS_TEMPLATES_DIR = app_templates_dir("django-users") 

then update TEMPLTES

    TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        # Search order: project templates first, then your app’s templates dir
        "DIRS": [
            BASE_DIR / "templates",
            USERS_TEMPLATES_DIR,            <---------------------  add this
        ],

Can be run with or without keycloak


## Testing 

As we don't have the final models in django_users we have created an example app to run the tests so we have the final models.  There might be a better way...

## Settings

This will run without any additional settings but the following settings can be added:


    USE_KEYCLOAK = getattr(settings, 'USE_KEYCLOAK', False)

    LOGIN_URL = getattr(settings, 'LOGIN_URL', 'users:login')
    LOGIN_REGISTER = getattr(settings, 'LOGIN_REGISTER', 'users:register')
    # define this url locally in your project
    LOGIN_REDIRECT_URL = "after_login_redirect" 

    VERIFICATION_CODE_EXPIRY_MINUTES = 5
    VERIFY_ONCE = True    # if user is verified in one system sharing a realm  then will be auto everified on a second - if you want each client to verify their users then set to False

    NOTIFY_NEW_USER_EMAILS = "phoebebright310@gmail.com"

    USERS_BIG = False  # if True then will use a paged method to display users table (for large numbers of users)


Make sure that django model authentication is your first choice, eg.

    AUTHENTICATION_BACKENDS = (
        "django.contrib.auth.backends.ModelBackend",      # MODELBACKEND must be first
        'django_keycloak_admin.backends.KeycloakAuthorizationCodeBackend',
        'django_keycloak_admin.backends.KeycloakPasswordCredentialsBackend',  
    )

## Setting up without Keycloak

1. copy users directory from another system
2. copy users template directory from another system
3. add to requirements: git+https://github.com/phoebebright/django-users
4. install
5. add to settings.py:


```python
INSTALLED_APPS = [
    ...
    'users',
    ...
]

USE_KEYCLOAK = False
```

6. check there is a login and register url

from django_users.api import ChangePassword, resend_activation, CheckEmailInKeycloak, SetTemporaryPassword, \
    CheckEmailInKeycloakPublic, toggle_role, CreateUser
from users.api import UserProfileUpdate, CheckEmail, OrganisationViewSet, UserViewset, CommsChannelViewSet, \
    UserListViewset, SendOTP2User, InternalRoleViewSet, RoleViewSet, MyInternalRoles, PersonViewSet
from django_users.views import login_redirect, signup_redirect, after_login_redirect, send_test_email,  \
     unsubscribe_only
from users.views import SubscribeView, ManageRoles

    # users apis


    path('ql/', login_with_token, name='qr-login'),   # login to same app, eg. on mobile
    path('lwt/', login_with_token,{'key': settings.REMOTE_LOGIN_SECRET}, name='login-with-token'),   # request to login from remote app with token
    path('login/', login_redirect, name='login'),
    path('logout', logout_user_from_keycloak_and_django, name="logout"),
    path('after_login_redirect/', after_login_redirect, name="after_login_redirect"),



You will need these in requirements (should not have all these dependancies!)

    git+https://github.com/phoebebright/django-users
    django_countries
    nanoid
    django-timezone-field
    # original library - not being updated
    git+https://github.com/phoebebright/django-yamlfield

Currently need roles and disciplines.  Create a file (see default_roles_and_disciplines.py) and add settings to point to it:

```python
MODEL_ROLES_PATH = 'config.roles_and_disciplines.ModelRoles'
DISCIPLINES_PATH = 'config.roles_and_disciplines.Disciplines'
```


## Migrating from keycloak to no keycloak

We need the password.  Best approach is to have a migration period to get most of the users across automatically, saving the password in django as we go.  

in settings: KEYCLOAK_MIGRATING = True
This will save the password in the django database (encrypted) on successful login

Benefits of keeping keycloak:
- MFA (not currently used)
- SSO (if multiple apps share same users)
- Social Signon - can also be implemented in django


## Status Updates

By default users are USER_STATUS_UNCONFIRMED (3) and then they become USER_STATUS_CONFIRMED (4) when they do something like fill in the profile.  By default this is done when update_subscribed is called but  decide how you want this to work and ensure it is in the save code of your user model.  You can call self.confirm()

```python
       # confirm once profile complete (ie. country is set)
        if self.country and self.status == self.USER_STATUS_UNCONFIRMED:
            self.confirm()



# Data Structures


## 1. Person – the real-world human

1. **Person represents a real person, not a login.**

   * A `Person` is the canonical identity object.

2. **A Person may exist with no User.**

   * e.g. historic competitors, riders imported from results.

3. **A Person may be linked to multiple Users.**

   * This covers “I want a separate admin login and competitor login”.

4. **Person has its own stable key and identifier.**

   * `ref` is a generated, stable ID (`Pxxxxx`).
   * `identifier_type` + `identifier` can be used (email/phone) when you want uniqueness at the identity level.

5. **Person’s name is the canonical name.**

   * `formal_name` is the primary name.
   * `sortable_name` and `friendly_name` are derived from it if missing.
   * `Person.save()` calls `change_name_globally()`, which pushes the name out to:

     * related `Role.name`
     * related `Competitor.name`
     * related `EventRole.name`

6. **Person↔Organisation membership is via PersonOrganisation.**

   * Many-to-many: `Person.organisation` through `PersonOrganisation`.
   * `PersonOrganisation` carries membership data: id, start/end, type, etc.

---

## 2. User (CustomUser) – the login account

1. **User is a login, not the identity.**

   * A `CustomUser` represents how someone signs in (email + password, etc.).

2. **Every User must be linked to a Person (canonical identity).**

   * Long-term invariant: `user.person` should always be set.
   * Current behaviour supports this:

     * In `CustomUserBaseBasic.save()`, if `person` is missing:

       * `self.person = Person.create_from_user(self)` is called.
   * Cleanup work is about enforcing this for legacy users.

3. **A Person can have multiple Users.**

   * Many Users may reference the same `Person` via `CustomUser.person`.
   * This is how you support “separate admin login vs competitor login”.

4. **User may have a default Organisation.**

   * `CustomUser.organisation` is a FK to a single `Organisation`.
   * This is the “default organisation context” for that login (e.g. the club they manage).
   * **the link to a person and organisation is via Role so consider removing Organisation from User?**

5. **User status models lifecycle of signup/subscription.**

   * Status values: TEMPORARY, UNCONFIRMED, CONFIRMED, TRIAL, SUBSCRIBED, etc.
   * `is_temporary`, `is_unconfirmed`, `is_confirmed`, `is_member` etc. wrap these.

6. **User uses Person for names.**

   * Properties like `name`, `friendly_name`, `formal_name`, `full_name` all fall back to the linked `Person` where possible.
   * When a User’s names/email change, `change_names_email()` pushes those updates to:

     * Person
     * Competitor
     * EventTeam
     * EventRole
     * Role

7. **User is the fast access point for runtime checks.**

   * Queries like “is this user a judge/manager/etc.?” are done via `Role` filtered by `user`.

---

## 3. Organisation

1. **Organisation represents an organising body / club / federation.**

   * `Organisation` holds name, scoring type, country, logos, etc.

2. **Organisation membership lives on Person and Role, not directly on User.**

   * Long-lived membership: `PersonOrganisation (Person ↔ Organisation)`.
   * Role-based capacity (judge, organiser, manager): `Role (Person ↔ Organisation ↔ User)`.

3. **User.organisation is a default/primary org for that login.**

   * Used as a convenient default when creating Roles, etc.

4. **Organisation may have settings / payment configuration.**

   * `Organisation.settings` (JSON) includes payment setups, Stripe account, etc.

---

## 4. Role – the glue between Person, User, Organisation

1. **Every Role belongs to a Person. (Required)**

   * `Role.person` is the canonical identity for the role.
   * This is the “who is this judge/organiser/manager really?”.

2. **Every Role also references a User.**

   * `Role.user` is which **login** they use for this role.
   * This is correct and desired because a Person may use different logins for different capacities.

3. **Consistency rule: Role.user must belong to Role.person.**

   * Invariants you want:

     * If both `role.person` and `role.user` are set, then:

       * `role.user.person == role.person`
   * That enforces: the login attached to this role is one of the person’s logins.

4. **Role should normally be linked to an Organisation.**

   * `Role.organisation` identifies for *which* organisation this role is exercised:

     * judge for Org A
     * organiser for Org B
   * If missing, it should be inferred where possible (from `user.organisation` or `PersonOrganisation`).

5. **Role reflects the capacity, not just membership.**

   * `role_type` expresses what they are: administrator, manager, judge, organiser, competitor, etc.
   * Each Person can have many Roles of different types and organisations.

6. **Role is the main source for permission checks.**

   * “Is this user an admin/manager/judge/competitor?” is determined via `Role` filtered by `user` and `role_type`.
   * Methods like `is_administrator`, `is_manager`, `is_judge`, `is_scorer`, etc. query `Role.objects.active().filter(user=self, ...)`.

7. **Role ties into organisation membership metadata via OrgMembershipMixin.**

   * A Role can also carry membership info (registration id, start/end, type), in addition to `PersonOrganisation`.

---

## 5. Relationship rules (summary)

Putting it all together:

1. **Person ↔ User**

   * One Person **can have many Users**.
   * One User **must have exactly one Person** (after cleanup).
   * `user.person` is the canonical identity link for that login.
   * `person.customuser_set.all()` gives all logins for that person.

2. **Person ↔ Organisation**

   * Connected via `PersonOrganisation` (many-to-many).
   * Stores membership details independent of how the person logs in.

3. **User ↔ Organisation**

   * `user.organisation` is a single “default” organisation, mainly for convenience and defaults.
   * It can be used to auto-fill `Role.organisation` where unambiguous.

4. **Person ↔ User ↔ Organisation via Role**

   * `Role.person` = real person.
   * `Role.user` = specific login used.
   * `Role.organisation` = organisation in which this role is held.
   * Invariant: if `Role.user` is set, that user must belong to `Role.person`.

---

If you’d like, next we can turn these rules into:

* a short **developer-facing docstring / README section** to live alongside the models, and/or
* **model-level assertions** (in `save()` or custom validators) that enforce the key invariants while still letting you clean legacy data.
