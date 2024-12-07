import base64
import json
import random

import string
import uuid

from datetime import date, datetime, time, timedelta
from string import digits

from OpenSSL.rand import status
from chunked_upload.models import AbstractChunkedUpload
from cryptography.fernet import Fernet

from django.apps import apps
from django.contrib.auth import authenticate, login
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.models import PermissionsMixin
from django.contrib.flatpages.models import FlatPage
from django.utils.module_loading import import_string
from django.core.mail import mail_admins

from django.conf import settings

import django
from django.core.validators import MinLengthValidator, MaxLengthValidator
from django.utils.dateparse import parse_time
from django.utils.functional import cached_property

from django.utils import timezone
from django_countries.fields import CountryField

from post_office import mail
from post_office.models import EmailTemplate

from timezone_field import TimeZoneField
from yamlfield.fields import YAMLField

from skorie.common.fields import EncryptedJSONField
from skorie.common.user_models import OrganisationBase, PersonOrganisationBase, PersonBase, RoleBase, CommsChannelBase, \
    VerificationCodeBase, UserContactBase, lazy_import
from skorie.common.models import DataQualityLogBase, ModelRoles
from testsheets.models import TestSheet
from tinycloud_storage.models import TinyCloudBaseVideoItem
from skorie.common.model_mixins import CreatedMixin,  EventMixin,  CreatedUpdatedMixin, \
     SponsorMixin, DataQualityMixin,  AliasForMixin, SellerMixin
from django.db import IntegrityError, models, transaction


from chunked_upload.models import AbstractChunkedUpload, ChunkedUpload


from django.utils.translation import gettext_lazy as _


import logging

from users.keycloak_tools import create_keycloak_user, verify_user_without_email
from users.notifications import on_new_user_unverified

ModelRoles = import_string(settings.MODEL_ROLES_PATH)
Disciplines = import_string(settings.DISCIPLINES_PATH)

logger = logging.getLogger('django')

class CommsChannel(CommsChannelBase):
    pass

class VerificationCode(VerificationCodeBase):
    pass

class CustomUserQuerySet(models.QuerySet):

    def old_anon(self, days=7):
        days_ago = timezone.now() - timedelta(days=days)
        return self.filter(status=self.model.USER_STATUS_ANON, date_joined__lt=days_ago)

    def active(self):

        return self.filter(active=True)

    def competitors(self):
        return self.filter(is_competitor=True)

    def riders(self):
        return self.filter(is_rider=True)

    def judges(self):
        return self.filter(is_judge=True)

    def icansee(self, user):
        '''used when organising an event and shows '''
        # needs to be built
        if user.is_superuser or user.is_administrator:
            return self.all()
        else:
            return self.none()


class CustomUserManager(BaseUserManager):
    _person_model = None

    @property
    def Person(self):
        if self._person_model is None:
            self._person_model = apps.get_model('users', 'Person')
        return self._person_model

    def _create_user(self, email, password,
                     is_staff, is_superuser, **extra_fields):
        """
        Creates and saves a User with the given username, email and password.
        """
        now = timezone.now()

        email = self.normalize_email(email)
        user = self.model(email=email,
                          is_staff=is_staff, is_active=True,
                          is_superuser=is_superuser, last_login=now,
                          date_joined=now, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)

        return user

    def create_user(self, email=None, password=None, **extra_fields):
        '''note that extra_fields only used in creating person not user'''
        is_active = True
        user_extras = {}
        if 'first_name' in extra_fields:
            user_extras['first_name'] = extra_fields['first_name']
            user_extras['last_name'] = extra_fields['last_name']
            extra_fields.pop('first_name')
            extra_fields.pop('last_name')

        # person needs a name
        if not 'formal_name' in extra_fields:
            if 'first_name' in extra_fields and 'last_name' in extra_fields:
                extra_fields['formal_name'] = f"{extra_fields['first_name']} {extra_fields['last_name']}"
            else:
                extra_fields['formal_name'] = email.split("@")[0]

        if 'username' in extra_fields:
            extra_fields.pop('username')
        if 'is_active' in extra_fields:
            is_active = extra_fields.pop('is_active')


        person = self.Person.objects.create(**extra_fields)

        user_extras['person'] = person
        user = self._create_user(email, password, False, False, **user_extras)

        if not is_active:
            user.is_active = False
            user.save()

        person.user = user
        person.save()

        return user

    def create_superuser(self, email, password, **extra_fields):

        person = self.Person.objects.create(**extra_fields)
        user = self._create_user(email, password, True, True,
                                 person=person, **extra_fields)
        person.user = user
        person.save()
        user.save()
        return user



class CustomUserBase(AbstractBaseUser, PermissionsMixin, DataQualityMixin):
    # options for additional roles within skorie

    # Private attributes for lazy-loaded models



    _system_user = None
    #I don't think this works as it needs to be a class property
    @property
    def system_user(self):
        if not self._system_user:

            # need a dummy person instance
            person, _ = self.Person.objects.get_or_create(formal_name="Skorie System")
            self._system_user, _ = CustomUserBase.objects.get_or_create(email="system@skor.ie",
                                                       defaults={'username': 'System',
                                                                 'person': person,
                                                                 'status': self.USER_STATUS_NA}
                                                   )
        return self._system_user


    _Role = None
    @property
    def Role(self):
        if not self._Role:
            self._Role = apps.get_model('users', 'Role')
        return self._Role

    _EventTeam = None
    @property
    def EventTeam(self):
        if not self._EventTeam:
            self._EventTeam = apps.get_model('web', 'EventTeam')
        return self._EventTeam

    _EventRole = None
    @property
    def EventRole(self):
        if not self._EventRole:
            self._EventRole = apps.get_model('web', 'EventRole')
        return self._EventRole

    _Competitor = None
    @property
    def Competitor(self):
        if not self._Competitor:
            self._Competitor = apps.get_model('web', 'Competitor')
        return self._Competitor

    _Organisation = None
    @property
    def Organisation(self):
        if not self._Organisation:
            self._Organisation = apps.get_model('users', 'Organisation')
        return self._Organisation

    _Person = None
    @property
    def Person(self):
        if not self._Person:
            self._Person = apps.get_model('users', 'Person')
        return self._Person

    _ModelRoles = None
    @property
    def ModelRoles(self):
        if not self._ModelRoles:
            self._ModelRoles = lazy_import('web.models.ModelRoles')
        return self._ModelRoles


    EXTRA_ROLES = {
        'testmanager': "Testsheet Manager",
        'testchecker': "Testsheet Checker",
        'devteam': "Skorie Development Team",
    }

    USER_STATUS_ANON = 0
    USER_STATUS_NA = 1  # used for system users
    USER_STATUS_UNCONFIRMED = 3
    USER_STATUS_CONFIRMED = 4
    USER_STATUS_TRIAL = 5
    USER_STATUS_SUBSCRIBED = 7
    USER_STATUS_TRIAL_LAPSED = 8
    USER_STATUS_SUBSCRIBED_LAPSED = 9

    USER_STATUS = (
        (USER_STATUS_ANON, "Unknown"),
        (USER_STATUS_NA, "Not Applicable"),
        (USER_STATUS_UNCONFIRMED, "Unconfirmed"),
        (USER_STATUS_CONFIRMED, "Confirmed"),
        (USER_STATUS_TRIAL, "Trial"),
        (USER_STATUS_SUBSCRIBED, "Subscribed"),
        (USER_STATUS_TRIAL_LAPSED, "Trial Lapsed"),
        (USER_STATUS_SUBSCRIBED_LAPSED, "Subscription Lapsed"),
    )

    # deprecated - names being pushed to Person entity.  Requires fix in keycloak authentication
    first_name = models.CharField(_('first name'), max_length=30, null=True, blank=True, db_index=True)
    last_name = models.CharField(_('last name'), max_length=30, null=True, blank=True, db_index=True)

    keycloak_id = models.UUIDField(editable=False, unique=True, null=True, blank=True)
    # email_verified = models.DateTimeField(blank=True, null=True)
    # mobile_verified = models.DateTimeField(blank=True, null=True)
    # verification_code = models.CharField(max_length=6, blank=True, null=True)

    # mobile = PhoneNumberField(null=True, blank=True)
    #
    # whatsapp = models.BooleanField(default=False, help_text=_("Do you use WhatsApp?"))

    country = CountryField(blank=True, null=True, help_text=_("Optional"))

    timezone = TimeZoneField(default='Europe/Dublin', help_text=_("Default timezone for this user"))
    #####

    user_source = models.CharField(max_length=20, default="Unknown",
                                   help_text=_("How or where did this user get created"))

    profile = models.JSONField(default=dict, blank=True, help_text=_("Free form info related to this users profile"))
    # ------------------

    # TODO: change organisation to M2M
    organisation = models.ForeignKey("users.Organisation", on_delete=models.CASCADE, blank=True, null=True)

    active = models.BooleanField(default=True,
                                 db_index=True)  # true when user accepts an invitation or confirms account - bad choice of name

    username = models.CharField(max_length=254, blank=True, null=True)  # required for keycloak interface only

    # if adding new roles, make sure they are included in the list of ModelRoles in EXTRA_ROLES
    extra_roles = models.CharField(max_length=100, blank=True, null=True,
                                   help_text=_("Additional roles for this user"))
    # ---------------------

    # current extra roles: testmanager, testchecker
    # TODO: add country, language, culture

    initial_ip = models.GenericIPAddressField(blank=True, null=True, editable=False,
                                              help_text="use to delete users that are bots")
    org_types = models.CharField(_("Organisation types involved with"), max_length=50, null=True, blank=True,
                                 help_text="eg. Pure Dressage, Eventing, Pony Club, Riding Club (Optional)")

    email = models.EmailField(_('email address'), unique=True)

    is_staff = models.BooleanField(_('staff status'), default=False,
                                   help_text=_('Designates whether the user can log into this admin '
                                               'site.'))
    is_active = models.BooleanField(_('active'), default=True,
                                    help_text=_('Designates whether this user should be treated as '
                                                'active. Unselect this instead of deleting accounts.'))
    date_joined = models.DateTimeField(_('date joined'), default=django.utils.timezone.now)   # has to point to django as timezone is used as a field

    removed_date = models.DateTimeField(blank=True, null=True)

    # notifications settings
    subscribe_news = models.DateTimeField(blank=True, null=True)
    unsubscribe_news = models.DateTimeField(blank=True, null=True)

    event_notifications_subscribed = models.DateTimeField(blank=True, null=True)
    event_notifications_unsubscribed = models.DateTimeField(blank=True, null=True)

    # competitor = models.ForeignKey("Competitor", on_delete=models.CASCADE,  blank=True, null=True, related_name="competitor_object",
    #                           help_text=_("Link to a competitor object if it applies"))

    # reg_iofh = models.CharField(_("ID on InternetOfPartners"), max_length=120, blank=True, null=True)

    status = models.PositiveSmallIntegerField(choices=USER_STATUS, default=USER_STATUS_UNCONFIRMED, db_index=True)

    trial_ends = models.DateTimeField(blank=True, null=True)
    subscription_ends = models.DateTimeField(blank=True, null=True)
    renew = models.BooleanField(default=False)

    activation_code = models.IntegerField(blank=True, null=True)

    free_account = models.BooleanField(_("Free Account"),
                                       help_text=_("No attempt to get subscription will be made on a free account"),
                                       default=False)  # used where users buy 3 for 2 deal, update by admin only

    # have to allow blank to prevent race condition on creating user
    person = models.ForeignKey("users.Person", on_delete=models.CASCADE, blank=True, null=True)

    usergroups = YAMLField(default=dict, help_text=_("Groups this user belongs to in Keycloak"))
    # profile_info = models.JSONField(blank=True, null=True, help_text=_("Free form info related to this users profile")) # see valid_profile_data for valid values

    preferred_channel = models.ForeignKey("users.CommsChannel", on_delete=models.CASCADE, blank=True, null=True)

    objects = CustomUserManager.from_queryset(CustomUserQuerySet)()

    USERNAME_FIELD = 'email'

    def __str__(self):
        if self.person and self.person.formal_name:
            return self.person.formal_name
        else:
            return self.email

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')
        abstract = True

    def save(self, *args, **kwargs):

        new = not self.id

        if not self.password:
            self.password = hash(str(uuid.uuid4()))

        super().save(*args, **kwargs)

        # need to link eventteam invites for new users to the invite when the user logs in for the first time
        # if new:
        #     for invite in CustomInvitations.objects.filter(email=self.email, accepted=False):
        #         try:
        #             eventteam = EventTeam.objects.get(invitation=invite)
        #         except EventTeam.DoesNotExist:
        #             logger.warning(f"Invitation {invite.pk} is not attached to event team object")
        #             pass
        #         else:
        #             eventteam.user = self
        #             eventteam.save()

        # Person has link to user, so can't create until user is saved
        if not self.person_id:
            self.person = self.Person.create_from_user(self)
            super().save(update_fields=['person', ])

        # get the keycloak_id as soon as we can - alternative is to change django_keycloak_admin
        try:
            if not self.keycloak_id and self.oidc_profile:
                self.keycloak_id = self.oidc_profile.sub
        except Exception as e:
            logger.warning(f"Error getting keycloak_id: {e}")
        # should not need to do this always...
        # self.match_user2competitor()

    def quick_save(self, *args, **kwargs):
        '''save without calling save on person'''
        super().save(*args, **kwargs)

    def delete(self, using=None, keep_parents=False):
        super().delete(using=None, keep_parents=True)

    def match_user2competitor(self):
        Rosette = apps.get_model('rosettes', 'rosette')

        linked = 0
        # if this email is linked to a rider in a recent event, then make them a rider and link them as a user to those riders
        for rider in self.Competitor.objects.filter(email=self.email, user__isnull=True,
                                               created__gte=timezone.now() - timedelta(days=31)):
            linked += 1
            rider.user = self
            rider.save()

            # # mark rosettes as collected
            # for rosette in Rosette.objects.filter(rider=rider):
            #     rosette.collected = timezone.now()
            #     rosette.collector = self
            #     rosette.save()

        if linked:
            self.upgrade_to_rider()
    @property
    def mobile(self):
        return None

    @property
    def has_mobile(self):
        return CommsChannel.objects.filter(user=self).exclude(channel_type="email", verified_at=None).exists()

    @property
    def has_email(self):
        return CommsChannel.objects.filter(user=self, channel_type="email").exclude(verified_at=None).exists()

    @property
    def get_preferred_channel(self):
        '''handle migration where there may be no email comms channel'''
        if not self.preferred_channel:
            self.preferred_channel.CommsChannel.objects.create(user=self, channel_type=CommsChannel.CHANNEL_EMAIL, value=self.email)
            self.quick_save(updated_fields=['preferred_channel'])

        return self.preferred_channel

    @property
    def is_member(self):
        '''user is paid up/approved'''
        return self.status == self.USER_STATUS_SUBSCRIBED

    @property
    def is_pro(self):
        '''in future this will be a paid level'''
        return self.is_superuser

    @property
    def name(self):
        '''do best to return a name - without accessing person'''

        if self.person and self.person.name:
            return self.person.name
        elif self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        elif self.first_name:
            return self.first_name
        elif self.last_name:
            return self.last_name
        else:
            return self.email

    @property
    def friendly_name(self):
        if self.person.friendly_name:
            return self.person.friendly_name
        elif self.person.formal_name:
            return self.person.formal_name
        else:
            return self.email

    @property
    def formal_name(self):

        if self.person.formal_name:
            return self.person.formal_name
        elif self.person.friendly_name:
            return self.person.friendly_name
        else:
            return self.email
        return self.person.formal_name

    @property
    def full_name(self):
        if self.person:
            return self.person.formal_name
        else:
            return "Unknown"

    # @classmethod
    # def valid_profile_fields(cls):
    #     '''used to remove any invalid profile_data - hacked together!'''
    #     valid = ['profile_info[interests][score]','profile_info[interests][score_mine]',
    #                   'profile_info[interests][store]', 'profile_info[interests][analyse]',
    #                   'profile_info[interests][analyse_students]',
    #                   'profile_info[interests][organise]', 'profile_info[interests][judge]',
    #                   'profile_info[interests][early_access]']
    #     return valid
    #

    @classmethod
    def system_user(cls):
        # need a dummy person instance
        person, _ = Person.objects.get_or_create(formal_name="Skorie System")
        system_user, _ = cls.objects.get_or_create(email="system@skor.ie",
                                                   defaults={'username': 'System',
                                                             'person': person,
                                                             'status': cls.USER_STATUS_NA}

                                                   )
        return system_user

    @classmethod
    def create_login_temporary_user(cls, request):

        pw = ''.join(random.choice('0123456789ABCDEF') for i in range(16))
        email = "%s@skor.ie" % pw

        cls.objects.create_user(email=email, password=pw, is_active=True)

        user = authenticate(username=email, password=pw)
        login(request, user)

        return user

    @classmethod
    def create_unconfirmed(cls, email, pw=None, add_device=False):
        '''create a new user where the email has not been confirmed and password may or may not be set
        if device is True, create a device for this user and pass back the key'''

        key = None
        if not pw:
            pw = cls.objects.make_random_password()

        user = cls.objects.create_user(email=email, password=pw, status=cls.USER_STATUS_UNCONFIRMED)

        device_key = None
        if add_device:
            device = user.add_device(name="mobile", activate=True)
            device_key = device.key

        user = authenticate(username=email, password=pw)

        return user, device_key


    def create_keycloak_user_from_user(self, password):

        user_data = {
            "firstName": self.first_name,
            "lastName": self.last_name,
            "email": self.email,
            "username": self.username,
            "enabled": True,
            "emailVerified": False,
            "credentials": [{"value": password, "type": "password"}],
        }
        try:
            keycloak_user_id, status_code = create_keycloak_user(user_data)

        except Exception as e:
            # Handle exceptions (e.g., user already exists)
            print(f"Error creating Keycloak user: {e}")
            return None
        else:

            self.keycloak_id = keycloak_user_id
            self.save()
            return status_code

    def update_keycloak_email_verified(self):
        verify_user_without_email(self.keycloak_id)

    #
    # def send_verification_code(self, method):
    #     self.verification_code = CustomUser.objects.make_random_password(length=6, allowed_chars='1234567890')
    #     self.save()
    #     if method == 'email':
    #         self.send_verification_email()
    #     else:
    #         self.send_verification_sms(self.mobile, self.verification_code)
    #
    # def send_verification_email(self):
    #
    #     msg = f"Please click on this link to activate your account and verify this email address: {settings.SITE_URL}/users/verify_account/{self.verification_code}/"
    #     subject = "Link to verify your email address and active your Skorie account"
    #     mail.send(
    #         recipients=self.email,
    #         subject=subject,
    #         message=msg,
    #         priority='now',
    #         language="EN",
    #     )
    #
    #
    #     # for some reason context is not being applied to template - give up wondering why
    #     # mail.send(
    #     #     recipients=self.email,
    #     #     template='verification_email',
    #     #     context={"verification_code":  self.verification_code},
    #     #     priority='now',
    #     #     language="EN",
    #     # )
    # def resend_verification_code(self, method):
    #     self.send_verification_code(method)
    #
    # def verify_code(self, code, method):
    #     if self.verification_code == code:
    #         if method == 'email':
    #             self.email_verified = timezone.now()
    #         else:
    #             self.mobile_verified = timezone.now()
    #         self.is_active = True
    #         self.verification_code = ''
    #         self.save()
    #         self.update_keycloak_email_verified()
    #         return True
    #     return False

    # note we want to have properties rather than a more generic has_role(role_required) so we can use them in templates
    # and because there is a lot of legacy code that uses these properties (that used to be part of the data model)
    @property
    def is_administrator(self):
        return self.Role.objects.active().filter(user=self, role_type=self.ModelRoles.ROLE_ADMINISTRATOR).exists() or self.is_superuser

    @cached_property
    def is_manager(self):
        return self.Role.objects.active().filter(user=self, role_type=self.ModelRoles.ROLE_MANAGER).exists()

    @cached_property
    def is_devteam(self):
        return self.is_superuser or (self.extra_roles and 'devteam' in self.extra_roles)

    @cached_property
    def is_issuer(self):
        return Role.objects.active().filter(user=self, role_type=self.ModelRoles.ROLE_ISSUER).exists()
    # @property
    # def is_bot(self):
    #     return self.Role.objects.filter(user=self, role_type=self.ModelRoles.ROLE_BOT).exists()
    @cached_property
    # def is_reader(self):
    #     #DEPRECATED
    #     return self.Role.objects.filter(user=self, role_type=self.ModelRoles.ROLE_AUXJUDGE).exists()

    @cached_property
    def is_auxjudge(self):
        return self.Role.objects.active().filter(user=self, role_type=self.ModelRoles.ROLE_AUXJUDGE).exists()

    @cached_property
    def is_judge(self):
        return self.Role.objects.active().filter(user=self, role_type=self.ModelRoles.ROLE_JUDGE).exists()

    @cached_property
    def is_organiser(self):
        return self.Role.objects.active().filter(user=self, role_type=self.ModelRoles.ROLE_ORGANISER).exists()

    @cached_property
    def is_scorer(self):
        # for now return either scorer pro or basic
        return self.Role.objects.active().filter(user=self, role_type__in=[self.ModelRoles.ROLE_SCORER, self.ModelRoles.ROLE_SCORER_BASIC]).exists()

    @cached_property
    def is_scorer_basic(self):
        return self.Role.objects.active().filter(user=self, role_type=self.ModelRoles.ROLE_SCORER_BASIC).exists()

    @cached_property
    def is_scorer_pro(self):
        return self.Role.objects.active().filter(user=self, role_type=self.ModelRoles.ROLE_SCORER).exists()

    @cached_property
    def is_competitor(self):
        '''Not adding everyone to role competitor anymore'''
        roles = self.Role.objects.active().filter(user=self)
        if roles.count() == 0:
            return True
        if roles.filter(role_type=self.ModelRoles.ROLE_COMPETITOR).exists():
            return True
        return False

    def has_role(self, role):
        '''check this user has the permission for this role'''

        if self.is_superuser:
            return True

        # check for cached value before accessing db
        if hasattr(self, 'roles'):
            return role in self.roles

        if self.Role.objects.active().filter(user=self, role_type=role).exists():
            return True
        elif self.extra_roles:
            return role in self.extra_roles
        return False

    def add_roles(self, roles):

        return self.person.add_roles(roles)

    def add_device(self, name=None, device_id=None, activate=False):
        return None
        # obj = Device.objects.create(user=self, name=name, device_id=device_id)
        # if activate:
        #     obj.activate()

        # return obj

    def get_full_name(self):
        if self.full_name:
            return self.full_name
        elif self.formal_name:
            return self.formal_name
        elif self.friendly_name:
            return self.friendly_name
        return str(self)


    @property
    def is_subscribe_news(self):
        return (self.subscribe_news and not self.unsubscribe_news)

    @property
    def has_email(self):
        '''see if user has added an email at some point, may do this when making contact before registering
        see new_user() for format of temporary email '''

        part1, part2 = self.email.split("@")
        return not (len(part1) == 30 and part2 == "skor.ie")

    @property
    def is_anon(self):
        '''not completed signup process'''
        logger.warning("CustomUser.is_anon is still being used but is deprecated")
        return len(self.email) == len("GTZXSWRUKCHKNQIUFAQLEEVWKTETMV@skor.ie") and 'skor.ie' in self.email
        # return self.status == self.USER_STATUS_ANON

    @property
    def is_unconfirmed(self):
        '''using keycloak so probably don't need this? '''
        return False
        return self.status == self.USER_STATUS_UNCONFIRMED

    @property
    def is_registered(self):
        '''email is confirmed and account activated'''

        return self.status >= self.USER_STATUS_TRIAL

    @property
    def can_save_scores(self):
        raise IntegrityError("Recode for event")
        # TODO: this will be mroe complex - what type of account, if competitor has used max free saves, organiser for event
        return (self.is_competitor or self.is_manager or self.is_scorer)

    @property
    def can_save_for_competitor_not_me(self):
        return False
        raise IntegrityError("Recode for event")
        return (self.is_manager or self.is_scorer)

    @property
    def is_default(self):
        # no other roles
        self.Role.objects.filter(user=self).exists()

    @property
    def is_system(self):

        return self.first_name == "System"

    @property
    def is_testchecker(self):
        return self.is_administrator or self.has_role("testchecker") or self.has_role("testmanager")

    @property
    def users_default_mode(self):
        '''if the user does not have a current mode, use this one.  Is the highest mode available'''
        # sure there is some clever way to do this

        roles = list(self.Role.objects.filter(user=self).values_list('role_type', flat=True))

        if self.ModelRoles.ROLE_ADMINISTRATOR in roles:
            return self.ModelRoles.ROLE_ADMINISTRATOR
        elif self.ModelRoles.ROLE_ORGANISER in roles:
            return self.ModelRoles.ROLE_ORGANISER
        elif self.ModelRoles.ROLE_AUXJUDGE in roles:
            return self.ModelRoles.ROLE_AUXJUDGE
        elif self.ModelRoles.ROLE_JUDGE in roles:
            return self.ModelRoles.ROLE_JUDGE
        elif self.ModelRoles.ROLE_COMPETITOR in roles:
            return self.ModelRoles.ROLE_COMPETITOR

        else:
            return self.ModelRoles.ROLE_DEFAULT

    def user_roles(self, event_ref: str = None, descriptions: bool = False):
        '''return list of roles available to this user.
        if event_ref is passed, include the roles for this event
        if description is true return list of lists, eg. [('M', 'Manager'),('R', 'Competitor')]
        if description is false, just return list of roles, eg. ['M','R']
        '''

        default_role = [self.ModelRoles.ROLE_DEFAULT, ]

        # get list of role types, eg. ['A','R'] and append default role
        non_event_roles = list(self.Role.objects.filter(user=self, active=True).values_list('role_type', flat=True))

        event_roles = []
        if event_ref:
            event_roles = list(
                self.EventRole.objects.filter(event_ref=event_ref, user=self).values_list('role_type',
                                                                                                    flat=True))
            # try:
            #     event_team = EventTeam.objects.values('roles',).get(event_ref=event_ref, user=self)
            #     #print("found roles %s" % event_team.roles)
            #     event_roles = event_team['roles']
            #
            #
            # except EventTeam.DoesNotExist:
            #     #print("No roles found")
            #     # self is god!
            #     event_roles = []

            # don't make admins automatically organisers any more
            # if self.is_superuser or self.is_administrator and not (self.ModelRoles.ROLE_ORGANISER, "Organiser") in event_roles:
            #     event_roles.append(self.ModelRoles.ROLE_ORGANISER,)

        extras = [] if not self.extra_roles else self.extra_roles.split(",")

        # deduplicate as we can have the same role in both event role and non-event role, eg. Judge
        roles = set(default_role + non_event_roles + event_roles + extras)

        if descriptions:
            roles_descriptions = self.ModelRoles.ROLE_DESCRIPTIONS
            roles_descriptions.update(self.EXTRA_ROLES)
            # these are roles added to the user model as a list
            #
            return [[code, roles_descriptions[code]] for code in list(roles)]
        else:
            return list(roles)

    # TODO: rename user_roles_list

    def user_modes_list(self, request=None, event_ref=None):
        # probably deprecated - use user_roles instead
        ''' a list of lists (Mode, Description) of the roles availble for this user
        if an event_ref is passed, include the roles for this event'''

        if request and not event_ref:
            request.session.get('event_ref', False)

        modes = []
        if self.is_administrator:
            modes.append((self.ModelRoles.ROLE_ADMINISTRATOR, self.ModelRoles.ROLES[self.ModelRoles.ROLE_ADMINISTRATOR]))
        if self.is_manager:
            modes.append((self.ModelRoles.ROLE_MANAGER, self.ModelRoles.ROLES[self.ModelRoles.ROLE_MANAGER]))
        if self.is_judge:
            modes.append((self.ModelRoles.ROLE_JUDGE, self.ModelRoles.ROLES[self.ModelRoles.ROLE_JUDGE]))
        if self.is_competitor:
            modes.append((self.ModelRoles.ROLE_COMPETITOR, self.ModelRoles.ROLES[self.ModelRoles.ROLE_COMPETITOR]))
        # if self.is_reader:
        #     modes.append((self.ModelRoles.ROLE_AUXJUDGE, self.ModelRoles.ROLES[self.ModelRoles.ROLE_AUXJUDGE]))

        if event_ref:
            try:
                event_team = self.EventTeam.objects.get(event_ref=event_ref, user=self)
                for role in event_team.roles:
                    if role:
                        modes.append((role, self.ModelRoles.ROLES[role]))

            except self.EventTeam.DoesNotExist:
                pass

        return modes

    def my_events(self):
        '''list of event refs that I am involved with.'''

        events = self.Event.objects.nowish().mine(self).distinct()
        # events = EventTeam.objects.filter(user=self).values_list('event_ref', flat=True).order_by('event_ref').distinct()

        return list(events)

    @cached_property
    def has_outstanding_event_invites(self):
        '''return a list of outstanding invitations to upcoming or current events'''
        return self.EventTeam.objects.outstanding().filter(user=self).count()

    @property
    def outstanding_event_invites(self):
        '''return a list of outstanding invitations to upcoming or current events'''
        return self.EventTeam.objects.outstanding().filter(user=self)

    # @property
    # def competitor(self):
    #     # depreacted - competitor should be specific to an event
    #     try:
    #         obj = Competitor.objects.get(user=self)
    #         return obj
    #     except Competitor.DoesNotExist:
    #         return None
    #     except Competitor.MultipleObjectsReturned:
    #         # return the first one
    #         # TODO: fix and notify admins
    #         logger.warning("Multiple Competitors found for user %s id %s" % (self, self.id))
    #         return Competitor.objects.filter(user=self).order_by('-created')[0]

    def make_order(self, event=None, items=None):
        """
        create order with all current outstanding items or specific item(s)
        or retrieve existing order
        """
        Order = apps.get_model('skorie_payments', 'order')  #
        Entry = apps.get_model('web', 'entry')  #
        try:
            order, created = Order.objects.get_or_create(user=self,
                                                         payid=None)
        except Order.MultipleObjectsReturned:
            # should not happen of course, but provide a way of recovering
            logger.warning(f"Duplicate unpaid orders found for user {self} - deleting extras")
            order = Order.objects.filter(user=self,
                                         payid=None).order_by('-created')[0]
            created = False
            Order.objects.filter(user=self,
                                 payid=None).exclude(ref=order.ref).delete()

        # add all entries excluded from previous order
        # TODO: should this sweep up any other entries or is it safe to assume that once the order is created they will all be added
        if created:

            entries = Entry.objects.mine(self).unpaid()

            if event:
                entries = entries.filter(event=event)
            # don't include entries on orders which are in the process of being paid
            # this is a bad way of doing this!
            for entry in entries:
                # add if not already existing
                order.add_item(entry=entry)

        return order

    @property
    def my_paid_orders(self):
        """
        NOTE: assumes all products are books!
        """
        Order = apps.get_model('skorie_payments', 'order')  #
        return Order.objects.filter(user=self, payid__isnull=False)

    def signup(self, save=True):
        # TODO: REMOVE or update - users for an event now go through event pipeline - there will be another type
        # of signup for users from the website.
        # user has signed up but email has not been confirmed
        self.status = self.USER_STATUS_UNCONFIRMED

        self.activation_code = "%s" % ''.join(random.choice(digits) for i in range(6))

        if save:
            self.save()

        return self

    def activate(self, save=True):

        self.status = self.USER_STATUS_TRIAL

        self.activation_code = None

        if save:
            self.save()

        return self

    def confirm(self, save=True):

        self.status = self.USER_STATUS_CONFIRMED

        if save:
            self.save()

        return self


    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return True

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    def attach_competitor(self, name, source=None):

        # for the moment add a new competitor - but should look for competitors that are not already attached to users

        return self.Competitor.new(name, user=self, source=source)

    @classmethod
    def add_or_update_user(cls, username, first_name, last_name, email ,passw=None,  phone=None, data=None):
        '''three aspects to creating a user:
        - django user
        - keycloak user
        - comms channels (contact methods)
        '''
        # channel_type = form.cleaned_data['channel_type']
        # email = form.cleaned_data['email']
        # mobile = form.cleaned_data['mobile']
        # password = form.cleaned_data['password']
        if not passw:
            random_number = random.randint(100000, 999999)
            random_letter = random.choice(string.ascii_uppercase)
            passw = f"{str(random_number)[:3]}{random_letter}{str(random_number)[3:]}"

        # currently username is email
        user, created = CustomUser.objects.get(username=username, defaults={'email': email,
                                                                            'first_name': first_name,
                                             'last_name': last_name,
                                                                            'is_active': False,
                                                                            **data})

        if created:
            status = "created"
        elif not user.keycloak_id and settings.USE_KEYCLOAK:
                # need to create a keycloak user
                keycloak_id = user.create_keycloak_user_from_user(passw)
                status = "keycloak created"

        elif not user.is_active:
            # user is not is_active (not same same active field, such a bad naming choice)
            # this happens if no comms channel has been verified
            # need to redirect to verify comms
            status="not active"

        return user, status

    # deprecated - use add_or_update_user instead
    #@classmethod
    # def new_user(cls, email, passw='valegro', request=None):
    #     ''' create a new user and all associated records - this way we only use edit forms never add forms
    #
    #     '''
    #
    #
    #     if email:
    #         user = cls.objects.create_user(email=email, password=passw)
    #     else:
    #         raise ValidationError("MIssing email on signup request")
    #
    #
    #     # look for additional fields in request
    #     if request:
    #
    #         # ip = request.META.get("HTTP_HOST", None)
    #         # if ip in settings.BOT_LIST:
    #         #     user.user_type = CustomUser.USER_TYPE_BOT
    #
    #         # get additional fields
    #         for f in cls._meta.get_fields():
    #             if f.name in request.POST and not f.name in ('email', 'username', 'password','csrfmiddlewaretoken'):
    #                 setattr(user, f.name, request.POST[f.name])
    #
    #
    #     user.save()
    #     return user

    def send_activation(self):

        # send email asking for confirmation
        mail.send(
            template="welcome_email",
            context={'user': self},
            recipients=[self.email, ],
            sender=settings.DEFAULT_FROM_EMAIL,
            priority='now',
        )

    def welcome_user(self):
        '''do whatever is required when a user completes signup'''

        logger.info(f"New User signed up {self.email}")

        # send welcome email

        mail.send(
            self.email,
            settings.DEFAULT_FROM_EMAIL,
            template='welcome_email',
            context={'user': self,
                     },
        )

        if settings.NOTIFY_NEW_USER_EMAILS:
            mail.send(
                settings.NOTIFY_NEW_USER_EMAILS,
                settings.DEFAULT_FROM_EMAIL,
                template='welcome_email',
                context={'user': self,
                         },
            )

    def upgrade_to_competitor(self, creator=None, source="system"):
        '''add role of competitor for this user'''

        roles = self.add_roles([self.ModelRoles.ROLE_COMPETITOR, ])

        return roles[0]

    def update_subscribed(self, subscribe):
        '''call with true or false to update'''
        if subscribe and not self.is_subscribe_news:
            self.subscribed = timezone.now()
        if not subscribe and self.is_subscribe_news:
            self.unsubscribed = timezone.now()

        # by subscribing (or not) status is at least confirmed
        if self.status < self.USER_STATUS_CONFIRMED:
            self.confirm(False)

        # status is now at least
        self.save()

    def change_names_email(self):
        '''change names for this user and email (as it appears in similar places)'''

        #currently we are going to use first and last name and derive formal and friendly
        # in future want to do away with first and last but django currently requires it (at least without further changes)

        # called from save so we assume the changes have already been saved in user model

        # name also appears in person
        if self.person:
            self.person.formal_name = self.formal_name
            self.person.friendly_name = self.friendly_name
            self.person.save()

        # and as competitor
        for competitor in self.Competitor.objects.filter(user=self):
            competitor.name = self.formal_name
            competitor.email = self.email
            competitor.save()

        # and as team member
        for team in self.EventTeam.objects.filter(user=self):
            team.name = self.formal_name
            team.email = self.email
            team.save()

        # and as event role
        for role in self.EventRole.objects.filter(user=self):
            role.name = self.formal_name
            role.email = self.email
            role.save()

        # and in Role
        for role in self.Role.objects.filter(user=self):
            role.name = self.formal_name
            role.email = self.email
            role.save()

    # deprecated - use is_subscribe_news instead
    def is_subscribed(self):
        '''
        is this user currently subscribed
        :return:
        '''
        return (self.subscribe_news and not self.unsubscribe_news)

    def update_event_subscribed(self, subscribe):
        '''call with true or false to update'''
        if subscribe and not self.event_notifications_subscribed:
            self.event_notifications_subscribed = timezone.now()
        if not subscribe and self.event_notifications_subscribed:
            self.subscribe_news = None
            self.event_notifications_unsubscribed = timezone.now()
        self.save()

    def get_username(self):
        return self.email

    # def get_full_name(self):
    #     """
    #     Returns the first_name plus the last_name, with a space in between.
    #     DEPRECATED - use property full_name instead
    #     """
    #     full_name = '%s %s' % (self.first_name, self.last_name)
    #     return full_name.strip()

    def get_short_name(self):
        "Returns the short name for the user."
        return self.email

    def email_user(self, subject, message, from_email=settings.DEFAULT_FROM_EMAIL, **kwargs):
        """
        Sends an email to this User.
        """

        mail.send(

            subject=subject,
            message=message,
            sender=from_email,
            recipients=[self.email],
        )

    @property
    def has_scores(self):
        '''
        :return:only true if is_competitor and has at least one scoresheet
        '''

        if self.is_competitor:
            return self.ScoreSheet.objects.mine(self).count() > 0

        return False

    def delete_one(self):
        '''delete causing stack overflow'''

        person = self.person
        if person:
            self.person = None
            self.save()
            person.delete()

        self.delete()

    def remove(self):
        '''remove all personal data and anonymising data added by the user'''

        # want to keep any scores for the moment as they indicate trials (maybe) keep if there
        # are scores attached (for now)
        scores = self.ScoreSheet.objects.filter(creator=self).count()

        if scores == 0:
            logger.info("Deleting user with no scores: %s " % self.email)
            self.delete()

        else:

            # replace with dummy email
            logger.info("Removing user %s..." % self)
            new_email = "%s@skor.ie" % ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(40))
            msg = "User %d with email %s has been removed and new email is %s - delete this email  " % (
                self.pk, self.email, new_email)

            if settings.DEBUG:
                print(msg)
            else:
                mail_admins("User %d has been removed" % self.pk, msg, fail_silently=False)

            self.username = new_email
            self.email = new_email
            self.first_name = ''
            self.last_name = ''
            self.password = 'none'
            self.is_active = False
            self.country = None
            self.org_types = None
            self.removed_date = timezone.now()

            self.save()
            logger.info("Finished removing user %s" % self)

        return True

    def can_notify(self, when=None):

        if not when:
            when = timezone.now()
        # notifications may only be valid at an event, at the time of the event
        # TODO: make sure at event
        return self.event_notifications_subscribed and \
            self.event_notifications_subscribed <= when and \
            (not self.event_notifications_unsubscribed or self.event_notifications_unsubscribed > when)


    def migrate_channels(self):
        # migrate email to comms channel and mobile if available in profile
        if not self.preferred_channel:
            self.preferred_channel, _ = CommsChannel.objects.get_or_create(user=self, channel_type=CommsChannel.CHANNEL_EMAIL, email=self.email)
            self.save()

            if 'mobile' in self.profile and self.profile['mobile']:
                CommsChannel.objects.get_or_create(user=self, channel_type=CommsChannel.CHANNEL_SMS, mobile=self.profile['mobile'])

#------------------  MODELS CUSTOMISED FOR THIS APPLICATION -----------------------

class DataQualityLog(DataQualityLogBase):
    pass
    # '''note that only models with a ref field can have an entry'''
    # ref = models.CharField(max_length=10, db_index=True)
    # reason_type = models.CharField(max_length=60, default="None", help_text=_("Reason for change in quality"))
    #
    # data_quality = models.SmallIntegerField(validators=[MinLengthValidator(0), MaxLengthValidator(100)])
    # data_comment = models.TextField(blank=True, null=True)
    # data_source = models.CharField(max_length=200, default="Data entry",
    #                                help_text=_("notes on source of data - may be url"))


class PersonOrganisation(PersonOrganisationBase):
    pass


class Person(PersonBase):
   pass

class Role(RoleBase):
    pass

class Organisation(OrganisationBase):
    code = models.CharField(max_length=8, help_text=_("Max 10 chars upper case.  Used to tag data as belonging to the organisation"))
    # need to think through how to handle key being wrong/changed so system does not crash
    # settings = EncryptedJSONField(default=dict, blank=True, help_text=_("Settings for this organisation"))
    settings = models.JSONField(default=dict, blank=True, help_text=_("Settings for this organisation"))
    '''
    {"STRIPE_API_KEY":"sk_test_51PH596KLzhkFeFrKYqw05ssNcnAvJRtTtx0vjRdP30R8oZW1kJX8Zz28EX7WCqp4Gl7oINEGks9158vd0H6xl6Rn0040SWxkF0","STRIPE_SECRET_KEY":"whsec_pHidHiMenLyJzp0bs8ziAd0ToWz6NWu7", "CURRENCY": "EUR"}
    '''
    # seller = models.ForeignKey("web.Seller", on_delete=models.CASCADE, blank=True, null=True)
    default_authority = models.ForeignKey("testsheets.Issuer", blank=True, null=True, on_delete=models.SET_NULL,
                                          related_name="default_issuer",)

    def decrypt_settings_data(self):
        cipher_suite = Fernet(settings.SETTINGS_KEY)
        decrypted_value = cipher_suite.decrypt(base64.b64decode(self.settings)).decode('utf-8')
        return json.loads(decrypted_value)

    @property
    def has_payment_gateway(self):
        '''this can get more sophisticated'''

        return 'STRIPE_API_KEY' in self.settings or hasattr(settings, 'STRIPE_API_KEY')



class CustomUser(CustomUserBase):
    EXTRA_ROLES = {
        'testmanager': "Testsheet Manager",
        'testchecker': "Testsheet Checker",
        'devteam': "Skorie Development Team",
    }

    USER_STATUS_ANON = 0
    USER_STATUS_NA = 1  # used for system users
    USER_STATUS_TEMPORARY = 2  # used where user has signed in with an acocunt like scorer1@skor.ie
    USER_STATUS_UNCONFIRMED = 3
    USER_STATUS_CONFIRMED = 4
    USER_STATUS_TRIAL = 5
    USER_STATUS_SUBSCRIBED = 7
    USER_STATUS_TRIAL_LAPSED = 8
    USER_STATUS_SUBSCRIBED_LAPSED = 9

    USER_STATUS = (
        (USER_STATUS_ANON, "Unknown"),
        (USER_STATUS_NA, "Not Applicable"),
        (USER_STATUS_TEMPORARY, "Temporary"),
        (USER_STATUS_UNCONFIRMED, "Unconfirmed"),
        (USER_STATUS_CONFIRMED, "Confirmed"),
        (USER_STATUS_TRIAL, "Trial"),
        (USER_STATUS_SUBSCRIBED, "Subscribed"),
        (USER_STATUS_TRIAL_LAPSED, "Trial Lapsed"),
        (USER_STATUS_SUBSCRIBED_LAPSED, "Subscription Lapsed"),
    )
    objects = CustomUserManager.from_queryset(CustomUserQuerySet)()

    def save(self, *args, **kwargs):

        new = not self.id

        # migrate email to comms channel
        if not self.preferred_channel and self.date_joined and self.date_joined < timezone.make_aware(datetime(*settings.USER_COMMS_MIGRATION_DATE)):

            email_channel, _ = CommsChannel.objects.get_or_create(user=self,
                                                                  channel_type=CommsChannel.CHANNEL_EMAIL,
                                                                  email=self.email,
                                                                  defaults={'verified_at': self.date_joined})

        super().save(*args, **kwargs)

        # setup email as preferred channel but not verified
        if not self.preferred_channel:
            email_channel, _ = CommsChannel.objects.get_or_create(user=self,
                                                                  channel_type=CommsChannel.CHANNEL_EMAIL,
                                                                 email=self.email)
            self.preferred_channel = email_channel
            self.quick_save(update_fields=['preferred_channel',])



    @property
    def is_rider(self):
        return self.is_competitor

    def upgrade_to_rider(self, creator=None, source="system"):
        '''add role of rider for this user'''
        Rider = apps.get_model('web', 'rider')
        roles = self.add_roles([ModelRoles.ROLE_COMPETITOR, ])

        for rider in Rider.objects.filter(email=self.email, user__isnull=True):
            rider.user = self
            rider.save()

        return roles[0]

class UserContact(UserContactBase):

    pass
