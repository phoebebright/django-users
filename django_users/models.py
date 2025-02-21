import base64
import hashlib
import json
import random

import string
import uuid

from datetime import date, datetime, time, timedelta
from string import digits

import nanoid
from django.apps import apps
from django.contrib.auth import authenticate, login
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.models import PermissionsMixin
from django.contrib.flatpages.models import FlatPage
from django.core.exceptions import ValidationError
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


from .tools.model_mixins import CreatedMixin,  CreatedUpdatedMixin, TrackChangesMixin, DataQualityMixin,  AliasForMixin
from django.db import IntegrityError, models, transaction


from django.utils.translation import gettext_lazy as _


import logging

if settings.USE_KEYCLOAK:
    from .keycloak import create_keycloak_user, verify_user_without_email, get_user_by_id, \
        search_user_by_email_in_keycloak

from .utils import send_email_verification_code, send_sms_verification_code, send_whatsapp_verification_code

ModelRoles = import_string(settings.MODEL_ROLES_PATH)
Disciplines = import_string(settings.DISCIPLINES_PATH)

CHANNEL_TYPES = getattr(settings, 'CHANNEL_TYPES', ['email', 'sms', 'whatsapp'])

def get_new_ref(model):
    '''
    S+6 = Scoresheet
    T+3 = Testsheet
    H+5 = Horse
    R+6 = Role
    P+5 = Person
    J+5 = Judge  # deprecated
    V+4 = Event
    C+5 = Competition
    E+8 = Entry = E + Event + sequence - handled in model
    W+5 = Order

    Rosettes
    Z+6 = Rosette

    2 = 900
    3 = 27,000
    4 = 810,000
    5 = 24,300,000
    6 = 729,000,000
    '''

    if type(model) == type("string"):
        model = model.lower()
    else:
        # assume model instance passed
        model = model._meta.model_name.lower()

    if model == "person":
        first = "P"
        size = 5
    elif model == "role":
        first = "R"
        size = 6

    else:
        raise IntegrityError("Unrecognised model %s" % model)

    return "%s%s" % (first, nanoid.generate(alphabet="23456789abcdefghjkmnpqrstvwxyz", size=size))


class DataQualityLogBase(CreatedMixin):
    '''note that only models with a ref field can have an entry'''
    ref = models.CharField(max_length=10, db_index=True)
    reason_type = models.CharField(max_length=60, default="None", help_text=_("Reason for change in quality"))

    data_quality = models.SmallIntegerField(validators=[MinLengthValidator(0), MaxLengthValidator(100)])
    data_comment = models.TextField(blank=True, null=True)
    data_source = models.CharField(max_length=200, default="Data entry",
                                   help_text=_("notes on source of data - may be url"))

    class Meta:
        abstract = True

logger = logging.getLogger('django')

def lazy_import(full_path):
    """Lazily import an object from a given path."""
    module_path, _, object_name = full_path.rpartition('.')
    imported_module = __import__(module_path, fromlist=[object_name])
    return getattr(imported_module, object_name)



class CommsChannelsQueryset(models.QuerySet):

    def verified(self):
        return self.filter(verified_at__isnull=False)

class CommsChannelBase(models.Model):

    CHANNEL_EMAIL = "email"
    CHANNEL_SMS = "sms"
    CHANNEL_WHATSAPP = "whatsapp"

    ALL_CHANNEL_CHOICES = [
        (CHANNEL_EMAIL, 'Email'),
        (CHANNEL_SMS, 'SMS'),
        (CHANNEL_WHATSAPP, 'WhatsApp'),
    ]

    CHANNEL_CHOICES = [(c[0], c[1]) for c in ALL_CHANNEL_CHOICES if c[0] in CHANNEL_TYPES]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='comms_channels')
    channel_type = models.CharField(max_length=10, choices=CHANNEL_CHOICES)
    value = models.CharField(max_length=255)
    verified_at = models.DateTimeField(null=True, blank=True)

    objects = CommsChannelsQueryset.as_manager()

    class Meta:
        unique_together = ('user', 'channel_type', 'value')
        abstract = True

    def __str__(self):
        return f"{self.get_channel_type_display()}: {self.value}"

    @property
    def is_verified(self):
        return self.verified_at is not None

    @property
    def obfuscated_value(self):
        if self.channel_type == self.CHANNEL_EMAIL:
            return self.obfuscated_email
        elif self.channel_type == self.CHANNEL_SMS:
            return self.obfuscated_mobile
        else:
            return ''
    @property
    def obfuscated_email(self):
        # Split the email into username and domain

        if not self.value:
            return ''

        try:
            username, domain = self.value.split('@')
        except:
            return ''
        else:
            # Keep the first character of the username and mask the rest
            obfuscated_username = username[0] + '*' * (len(username) - 1)
            return f"{obfuscated_username}@{domain}"

    @property
    def obfuscated_mobile(self):
        # Only show the last four digits, mask the rest
        if self.value:
            mobile = str(self.value)
            return  '*' * (len(mobile) - 4) + mobile[-4:]
        else:
            return ''


    @property
    def hash_username(self):
        '''create a hash of the username to pass into a form so as to avoid exposing the email address'''
        # Convert the username (email) to lowercase to ensure consistent hashing
        normal = self.username.strip().lower()
        return hashlib.sha256(normal.encode()).hexdigest()

    def verify(self):
        self.verified_at = timezone.now()
        self.save()

        if settings.USE_KEYCLOAK:
            # at the moment we can't trust that is_active in django will match active in keycloak, so lets check
            keycloak_verified = False

            # do we have keycloak user setup yet?
            keycloak_user = None
            if self.user.keycloak_id:
                keycloak_user = get_user_by_id(self.user.keycloak_id)
            if keycloak_user:
                keycloak_verified =  keycloak_user['emailVerified']
            else:
                # let's create keycloak user and mark as verified
                payload = {
                    "email": self.user.username,
                    "username": self.user.username,
                    "firstName": self.user.first_name,
                    "lastName": self.user.last_name,
                    "enabled": True,
                    'emailVerified': True,
                    "requiredActions": [],
                }
                keycloak_id, status_code = create_keycloak_user(payload)

            self.user.is_active = True
            self.user.save()

        # TODO: move this somewhere better
        if not self.user.is_active or not keycloak_verified:
            self.user.is_active = True
            self.user.save()
            verify_user_without_email(self.user.keycloak_id)


    def send_msg(self, msg, subject=None):
        if self.channel_type == self.CHANNEL_EMAIL:
            mail.send(
                recipients=self.value,
                subject=subject,
                message=msg,
                priority='now',
                language="EN",
            )
        elif self.channel_type == self.CHANNEL_SMS:
            send_sms_verification_code(self.value, msg)
        elif self.channel_type == self.CHANNEL_WHATSAPP:
            send_whatsapp_verification_code(self.value, msg)

class VerificationCodeBase(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='verification_codes')
    channel = models.ForeignKey('CommsChannel', on_delete=models.CASCADE)
    code = models.CharField(max_length=6)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    attempts = models.PositiveIntegerField(default=0)



    def __str__(self):
        return f"Code for {self.user} via {self.channel}"

    class Meta:
        abstract = True

    @classmethod
    def create_verification_code(cls, user, channel):
        code = ''.join(random.choices(string.digits, k=6))
        expires_at = timezone.now() + timedelta(minutes=settings.VERIFICATION_CODE_EXPIRY_MINUTES)
        obj = cls.objects.create(
            user=user,
            channel=channel,
            code=code,
            expires_at=expires_at
        )
        return obj

    @property
    def is_expired(self):
        return timezone.now() > self.expires_at

    @classmethod
    def verify_code(cls, code, channel):

            match = cls.objects.filter(
                channel=channel,
                code=code,
                expires_at__gt=timezone.now()
            )
            if match.exists():
                channel.verify()



                # Delete all verification codes for this channel
                cls.objects.filter(channel=channel).delete()

                return True
            return False

    def send_verification_code(self)->bool:

        if self.channel.channel_type == 'email':
            return send_email_verification_code(self)
        elif self.channel.channel_type == 'sms':
            return send_sms_verification_code(self.channel.value, self.code)
        elif self.channel.channel_type == 'whatsapp':
            return send_whatsapp_verification_code(self.channel.value, self.code)



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

        # this should be limited to if the user was only just created and somehow ending up with a duplicte rather than overwriting an existing user...
        user, created = self.model.objects.get_or_create(email=email, username=email, defaults={'is_staff': is_staff, 'is_active': True, 'is_superuser': is_superuser, 'last_login': now, 'date_joined': now, **extra_fields})
        # user = self.model(email=email,
        #                   is_staff=is_staff, is_active=True,
        #                   is_superuser=is_superuser, last_login=now,
        #                   date_joined=now, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)

        return user

    @transaction.atomic
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
        if 'keycloak_id' in extra_fields:
            user_extras['keycloak_id'] = extra_fields.pop('keycloak_id')
        if 'activation_code' in extra_fields:
            user_extras['activation_code'] = extra_fields.pop('activation_code')


        person = self.Person.objects.create(**extra_fields)

        user_extras['person'] = person
        user = self._create_user(email, password, False, False, **user_extras)

        if not is_active:
            user.is_active = False
            user.quick_save(update_fields=['is_active', ])

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


class CustomUserBaseBasic(AbstractBaseUser, PermissionsMixin):
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

    _CommsChannel = None
    @property
    def CommsChannel(self):
        if not self._CommsChannel:
            self._CommsChannel = apps.get_model('users', 'CommsChannel')
        return self._CommsChannel

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
            self._ModelRoles = ModelRoles
        return self._ModelRoles



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


    country = CountryField(blank=True, null=True, help_text=_("Optional"))

    timezone = TimeZoneField(default='Europe/Dublin', help_text=_("Default timezone for this user"))


    profile = models.JSONField(default=dict, blank=True, help_text=_("Free form info related to this users profile"))


    # TODO: change organisation to M2M
    organisation = models.ForeignKey("users.Organisation", on_delete=models.CASCADE, blank=True, null=True)

    #TODO: can we remove this - very confusing as we have django is_active field as well
    #active = models.BooleanField(default=True,
                                 #db_index=True)  # true when user accepts an invitation or confirms account

    username = models.CharField(max_length=254, blank=True, null=True)  # required for keycloak interface only

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


    status = models.PositiveSmallIntegerField(choices=USER_STATUS, default=USER_STATUS_UNCONFIRMED, db_index=True)



    activation_code = models.CharField(max_length=10, blank=True, null=True)


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
        app_label = 'django_users'

    def save(self, *args, **kwargs):

        new = not self.id

        if not self.password:
            self.password = hash(str(uuid.uuid4()))

            # migrate email to comms channel
        if not self.preferred_channel and self.date_joined and self.date_joined < timezone.make_aware(
                datetime(*settings.USER_COMMS_MIGRATION_DATE)):
            email_channel, _ = self.CommsChannel.objects.get_or_create(user=self,
                                                                  channel_type=self.CommsChannel.CHANNEL_EMAIL,
                                                                  value=self.email,
                                                                  defaults={'verified_at': self.date_joined})

        super().save(*args, **kwargs)

        # setup email as preferred channel but not verified
        if not self.preferred_channel:
            email_channel, _ = self.CommsChannel.objects.get_or_create(user=self,
                                                                  channel_type=self.CommsChannel.CHANNEL_EMAIL,
                                                                  value=self.email)
            self.preferred_channel = email_channel
            self.quick_save(update_fields=['preferred_channel', ])





        # Person has link to user, so can't create until user is saved
        if not self.person_id:
            self.person = self.Person.create_from_user(self)
            self.quick_save(update_fields=['person', ])

        # get the keycloak_id as soon as we can - alternative is to change django_keycloak_admin



    def quick_save(self, *args, **kwargs):
        '''save without calling save on person'''
        super().save(*args, **kwargs)

    def delete(self, using=None, keep_parents=False):
        super().delete(using=None, keep_parents=True)

    def match_user2competitor(self):
        Rosette = apps.get_model('rosettes', 'rosette')

        linked = 0
        # if this email is linked to a rider in a recent event, then make them a rider and link them as a user to those riders
        for competitor in self.Competitor.objects.filter(email=self.email, user__isnull=True,
                                               created__gte=timezone.now() - timedelta(days=31)):
            linked += 1
            competitor.user = self
            competitor.save()

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
        return self.CommsChannel.objects.filter(user=self, channel_type=self.CHANNEL_SMS).exclude(verified_at=None).exists()

    @property
    def has_email(self):
        return self.CommsChannel.objects.filter(user=self, channel_type=self.CHANNEL_EMAIL).exclude(verified_at=None).exists()

    @property
    def get_preferred_channel(self):
        '''handle migration where there may be no email comms channel'''
        if not self.preferred_channel:
            self.preferred_channel.CommsChannel.objects.create(user=self, channel_type=self.CommsChannel.CHANNEL_EMAIL, value=self.email)
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

    @property
    def is_subscribe_news(self):
        return (self.subscribe_news and not self.unsubscribe_news)


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
        #person, _ = cls.Person.objects.get_or_create(formal_name="Skorie System") - doesn't work
        Person = apps.get_model('users', 'Person')
        person, _ = Person.objects.get_or_create(formal_name=settings.SITE_NAME)
        system_user, _ = cls.objects.get_or_create(email="system@test.com",
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

    @classmethod
    def check_register_status(cls, email, requester):
        '''check if user is registered and activated/verified'''

        # get user in django
        try:
            # username will be set by keycloak so use email as key
            django_user = cls.objects.get(email=email)
        except cls.DoesNotExist:
            django_user = None

            return {
                "keycloak_user_id": '',
                "django_user_keycloak_id": django_user.keycloak_id if django_user else 0,
                "django_user_id": django_user.pk if django_user else 0,

            }



    # note we want to have properties rather than a more generic has_role(role_required) so we can use them in templates
    # and because there is a lot of legacy code that uses these properties (that used to be part of the data model)
    @property
    def is_administrator(self):
        return self.Role.objects.active().filter(user=self, role_type=self.ModelRoles.ROLE_ADMINISTRATOR).exists() or self.is_superuser

    @cached_property
    def is_manager(self):
        return self.Role.objects.active().filter(user=self, role_type=self.ModelRoles.ROLE_MANAGER).exists()or self.is_superuser


    # move to app code
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
    def is_default(self):
        # no other roles
        self.Role.objects.filter(user=self).exists()

    @property
    def is_system(self):

        return self.first_name == "System"


    @property
    def users_default_mode(self):
        '''if the user does not have a current mode, use this one.  Is the highest mode available'''
        # sure there is some clever way to do this

        roles = list(self.Role.objects.filter(user=self).values_list('role_type', flat=True))

        if self.ModelRoles.ROLE_ADMINISTRATOR in roles:
            return self.ModelRoles.ROLE_ADMINISTRATOR
        elif self.ModelRoles.ROLE_MANAGER in roles:
            return self.ModelRoles.ROLE_MANAGER

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
        roles = list(self.Role.objects.filter(user=self, active=True).values_list('role_type', flat=True))


        if descriptions:
            roles_descriptions = self.ModelRoles.ROLE_DESCRIPTIONS
            roles_descriptions.update(self.EXTRA_ROLES)
            # these are roles added to the user model as a list
            #
            return [[code, roles_descriptions[code]] for code in list(roles)]
        else:
            return list(roles)

    # TODO: rename user_roles_list

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
        user, created = cls.objects.get(username=username, defaults={'email': email,
                                                                            'first_name': first_name,
                                             'last_name': last_name,
                                                                            'is_active': False,
                                                                            **data})

        if created:
            status = "created"
        elif settings.USE_KEYCLOAK and not user.keycloak_id:
                # need to create a keycloak user
                keycloak_id = user.create_keycloak_user_from_user(passw)
                status = "keycloak created"

        elif not user.is_active:
            # user is not is_active (not same same active field, such a bad naming choice)
            # this happens if no comms channel has been verified
            # need to redirect to verify comms
            status="not active"

        return user, status


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

    def migrate_channels(self):
        # migrate email to comms channel and mobile if available in profile
        if not self.preferred_channel:
            self.preferred_channel, _ = self.CommsChannel.objects.get_or_create(user=self,
                                                                                channel_type=self.CommsChannel.CHANNEL_EMAIL,
                                                                                email=self.email)
            self.save()

            if 'mobile' in self.profile and self.profile['mobile']:
                self.CommsChannel.objects.get_or_create(user=self, channel_type=self.CommsChannel.CHANNEL_SMS,
                                                        mobile=self.profile['mobile'])


class CustomUserBase(CustomUserBaseBasic):

    EXTRA_ROLES = {
        'testmanager': "Testsheet Manager",
        'testchecker': "Testsheet Checker",
        'devteam': "Skorie Development Team",
    }

    keycloak_id = models.UUIDField(editable=False, unique=True, null=True, blank=True)

    user_source = models.CharField(max_length=20, default="Unknown",
                                   help_text=_("How or where did this user get created"))

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

    event_notifications_subscribed = models.DateTimeField(blank=True, null=True)
    event_notifications_unsubscribed = models.DateTimeField(blank=True, null=True)

    trial_ends = models.DateTimeField(blank=True, null=True)
    subscription_ends = models.DateTimeField(blank=True, null=True)
    renew = models.BooleanField(default=False)

    free_account = models.BooleanField(_("Free Account"),
                                       help_text=_("No attempt to get subscription will be made on a free account"),
                                       default=False)  # used where users buy 3 for 2 deal, update by admin only

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')
        abstract = True


    def save(self, *args, **kwargs):

        super().save(*args, **kwargs)

        if not self.keycloak_id:
            self.keycloak_id = None

        if not self.ref:
            self.ref = get_new_ref("user")

    @classmethod
    def check_register_status(cls, email, requester):
        '''check if user is registered and activated/verified'''

        # get user in django
        try:
            # username will be set by keycloak so use email as key
            django_user = cls.objects.get(email=email)
        except cls.DoesNotExist:
            django_user = None

        keycloak_user = search_user_by_email_in_keycloak(email, requester)

        if keycloak_user:

            return {
                "keycloak_user_id": keycloak_user['id'],
                "keycloak_created": keycloak_user['createdTimestamp'],
                "keycloak_enabled": keycloak_user['enabled'],
                "keycloak_actions": keycloak_user['requiredActions'],
                "keycloak_verified": keycloak_user['emailVerified'],
                "django_user_keycloak_id": django_user.keycloak_id if django_user else 0,
                "django_user_id": django_user.pk if django_user else 0,
                "django_is_active": django_user.is_active,

            }

        else:
            return {
                "keycloak_user_id": '',
                "django_user_keycloak_id": django_user.keycloak_id if django_user else 0,
                "django_user_id": django_user.pk if django_user else 0,

            }

    def create_keycloak_user_from_user(self, password, requester):

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
            keycloak_user_id, status_code = create_keycloak_user(user_data, requester)

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

    @cached_property
    def is_devteam(self):
        return self.is_superuser or (self.extra_roles and 'devteam' in self.extra_roles)

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

    @property
    def users_default_mode(self):
        '''if the user does not have a current mode, use this one.  Is the highest mode available'''
        # sure there is some clever way to do this

        roles = list(self.Role.objects.filter(user=self).values_list('role_type', flat=True))

        if self.ModelRoles.ROLE_ADMINISTRATOR in roles:
            return self.ModelRoles.ROLE_ADMINISTRATOR
        elif self.ModelRoles.ROLE_MANAGER in roles:
            return self.ModelRoles.ROLE_MANAGER
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


    def user_modes_list(self, request=None, event_ref=None):
        # probably deprecated - use user_roles instead
        ''' a list of lists (Mode, Description) of the roles availble for this user
        if an event_ref is passed, include the roles for this event'''

        if request and not event_ref:
            request.session.get('event_ref', False)

        modes = []
        if self.is_administrator:
            modes.append(
                (self.ModelRoles.ROLE_ADMINISTRATOR, self.ModelRoles.ROLES[self.ModelRoles.ROLE_ADMINISTRATOR]))
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


    def attach_competitor(self, name, source=None):

        # for the moment add a new competitor - but should look for competitors that are not already attached to users

        return self.Competitor.new(name, user=self, source=source)

    def upgrade_to_competitor(self, creator=None, source="system"):
        '''add role of competitor for this user'''

        roles = self.add_roles([self.ModelRoles.ROLE_COMPETITOR, ])

        return roles[0]



    def update_event_subscribed(self, subscribe):
        '''call with true or false to update'''
        if subscribe and not self.event_notifications_subscribed:
            self.event_notifications_subscribed = timezone.now()
        if not subscribe and self.event_notifications_subscribed:
            self.subscribe_news = None
            self.event_notifications_unsubscribed = timezone.now()
        self.save()


    @property
    def has_scores(self):
        '''
        :return:only true if is_competitor and has at least one scoresheet
        '''

        if self.is_competitor:
            return self.ScoreSheet.objects.mine(self).count() > 0

        return False


    def can_notify(self, when=None):

        if not when:
            when = timezone.now()
        # notifications may only be valid at an event, at the time of the event
        # TODO: make sure at event
        return self.event_notifications_subscribed and \
            self.event_notifications_subscribed <= when and \
            (not self.event_notifications_unsubscribed or self.event_notifications_unsubscribed > when)


class UserContactBase(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    contact_date = models.DateTimeField(auto_now_add=True, db_index=True)
    method = models.CharField(max_length=40)
    notes = models.TextField(blank=True, null=True)
    data = models.TextField(blank=True, null=True)  # use for json data, convert to field when avaialble

    def __str__(self):
        return "%s" % self.user

    class Meta:
        abstract = True

    @classmethod
    def add(cls, user, method, notes=None, data=None, send_mail=True):

        if type(data) == str:
            try:
                data = json.loads(data)
            except json.JSONDecodeError:
                logger.warning(f"Data is not valid json: {data}")
                mail.send(
                    subject=f"Contact from {settings.SITE_NAME} unable to decode ",
                    message=data,
                    recipients=[settings.SUPPORT_EMAIL, ]
                )
                return

        obj = cls.objects.create(user=user, method=method, notes=notes, data=data)
        if data and 'message' in data:
            msg = f"{user} contacted us via {data['message']}"
        else:
            msg = f"{user} contacted us via {method}"

        if send_mail:
            mail.send(
                subject=f"Contact from {settings.SITE_NAME} user {obj.user} ",
                message=msg,
                recipients=[settings.SUPPORT_EMAIL, ],
                sender=settings.DEFAULT_FROM_EMAIL,
                priority='now',
                language='EN',
            )


#------------------  MODELS CUSTOMISED FOR THIS APPLICATION -----------------------


class PersonBase(CreatedUpdatedMixin, AliasForMixin, TrackChangesMixin):


    _Role = None
    @property
    def Role(self):
        if not self._Role:
            self._Role = apps.get_model('users', 'Role')
        return self._Role

    _CustomUser = None
    @property
    def CustomUser(self):
        if not self._CustomUser:
            self._CustomUser = apps.get_model('users', settings.AUTH_USER_MODEL)
        return self._CustomUser

    IDENTIFIER_TYPE_EMAIL = "E"
    IDENTIFIER_TYPE_PHONE = "P"
    IDENTIFIER_TYPE_CHOICES = (
        (IDENTIFIER_TYPE_EMAIL, "Email"),
        (IDENTIFIER_TYPE_PHONE, "Phone"),
    )
    DEFAULT_IDENTIFIER_TYPE = "E"

    # ? should there be an email or mobile in here as a key to identifying a unique Person?
    ref = models.CharField(max_length=6, primary_key=True)

    formal_name = models.CharField(_('formal name'), max_length=50,
                                   help_text=_("Full name including salution"))

    sortable_name = models.CharField(_('sortable, eg. last name then first name'), max_length=130, blank=True)
    friendly_name = models.CharField(_('friendly name'), max_length=30, blank=True, null=True,
                                     help_text=_("Short name used in groups"))

    dob = models.DateField(blank=True, null=True)  # n/a once an adult?
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="person_user")



    # consider only adding a person if you have some way of making them unique, eg. email or phone
    identifier_type = models.CharField(max_length=1, choices=IDENTIFIER_TYPE_CHOICES, default=DEFAULT_IDENTIFIER_TYPE)
    identifier = models.CharField(max_length=50, unique=True, blank=True, null=True)

    country = CountryField(blank=True, null=True, help_text=_("Optional"))

    timezone = TimeZoneField(default='UTC', help_text=_("Default timezone for this user"))

    organisation = models.ManyToManyField("users.Organisation", through="users.PersonOrganisation")


    def __str__(self):
        return self.formal_name

    class Meta:
        verbose_name = _('person')
        verbose_name_plural = _('people')
        ordering = ['sortable_name', ]
        abstract = True


    def save(self, *args, **kwargs):

        if not self.ref:
            self.ref = get_new_ref("person")

        if not self.identifier:
            self.identifier = None

        # try to split name assuming it is a western name
        if not self.sortable_name:
            parts = self.formal_name.split(" ")
            if len(parts) > 1:
                self.sortable_name = f"{parts[-1]} {parts[-2]}"
            else:
                self.sortable_name = self.formal_name

        super().save(*args, **kwargs)

        # causes recursion
        # if 'user' in self.changed_fields and self.user != None:
        #     self.bump(10, "linking user to person")

    @classmethod
    def id_or_name(cls, id, name, data, creator=None):
        raise ValidationError("Deprecated method id_or_name")

    @property
    def name(self):
        '''if available return formal_name (friendly_name), if not do your best!'''

        if self.formal_name:
            return self.formal_name
        elif self.friendly_name:
            return self.friendly_name
        else:
            return self.ref

    @classmethod
    def new(cls, name, roles=None, user=None, source="Unknown", ref=None, creator=None, **data):
        '''create a new person and all associated links - name at least is required and this becomes formal_name if that is not supplied
        returns person object and first role object as often want to just add a judge for example and not then have to go and look for it'''

        obj = None

        # FOR NOW ONLY ONE PERSON PER USER
        if user:
            try:
                obj = cls.objects.get(user=user)
            except:
                pass
            else:
                # person may already have been created with user so just update the name
                obj.formal_name = name
                for k, v in data.items():
                    setattr(obj, k, v)

                if creator:
                    obj.updator = creator

                obj.save()

        # create Person object
        if not obj:

            if user:
                data['identifier_type'] = cls.IDENTIFIER_TYPE_EMAIL
                data['identifier'] = user.email

            obj = cls.objects.create(formal_name=name, user=user, creator=creator, data_source=source, **data)

        # else:
        #
        #     # update name if Person already exists
        #     if obj.formal_name != name:
        #         obj.formal_name = name
        #         obj.save()

        # if we have a user, this improves the quality of the data
        if user:
            quality = obj.DEFAULT_QUALITY + 10
        else:
            quality = obj.DEFAULT_QUALITY

        obj.update_quality(quality=quality, comment='', source=source, creator=creator)

        # create role links
        if roles:
            role_objs = obj.add_roles(roles)
            role_obj = role_objs[0]
        else:
            role_obj = None

        return obj, role_obj

    @classmethod
    def create_from_user(cls, user):

        person = cls(
            user=user,
            data_source="User"
        )

        if user.first_name:
            person.friendly_name = user.first_name

        if user.last_name:
            person.formal_name = f"{user.first_name} {user.last_name}"

        # have to have a formal name, so build from email
        if not person.formal_name:
            parts = user.email.split("@")
            person.formal_name = parts[0]

        person.save()

        return person

    @classmethod
    def create_person_and_user(cls, username, email, friendly_name, formal_name, **kwargs):

        person = cls(
            friendly_name=friendly_name,
            formal_name=formal_name,
            **kwargs,
        )
        person.save()

        user = cls.CustomUser.objects.create_user(username=username, email=email, person=person)

    @property
    def roles(self):
        return self.Role.objects.active().filter(person=self)

    def add_roles(self, roles):
        '''add roles to PersonRoles where roles is a list of role ids'''

        objs = []
        for role in roles:
            try:
                obj, _ = self.Role.objects.get_or_create(name=self.formal_name, person=self, role_type=role, user=self.user)
            except self.Role.MultipleObjectsReturned:
                logger.warning(f"Multiple roles returned for {self.formal_name} {role}")
                obj = self.Role.objects.filter(name=self.formal_name, person=self, role_type=role, user=self.user).last()
            objs.append(obj)

        return objs

    def remove_roles(self, roles):

        for role in roles:
            try:
                self.Role.objects.get(person=self, role_type=role).delete()
            except Exception as e:
                logger.warning(f"exception {e} on removing role {role}")



class RoleQuerySet(models.QuerySet):

    def judges(self):
        return self.filter(role_type=ModelRoles.ROLE_JUDGE)

    def active(self):
        return self.filter(active=True)

    def event_roles(self):
        '''excluding judges'''
        return self.filter(role_type__in=ModelRoles.EVENT_ROLES_LIST_NO_JUDGES)

class RoleBase(CreatedUpdatedMixin):
    '''a person may have many roles and many have different versions of the same role, for example,
    be a judge at a different level in different disciplines or different countries.  If this person
    is also a user of the system then the user will be linked in
    May also be used for memberships in future so I have a role as an AIRC Member
    This is the role outside of the event - EventRole is used to say what roles they have at ane event'''

    ref = models.CharField(max_length=7, unique=True, null=True, blank=True)

    role_type = models.CharField(max_length=1, choices=ModelRoles.ROLE_CHOICES)

    # making person not required so that where you have a person with little info other than a name , eg. a competitor at a historical event
    # you do not necessarily need to create a person, and very likely end up with many duplicate Person records.

    person = models.ForeignKey("Person", on_delete=models.CASCADE, blank=True, null=True, related_name="role_person")

    # Role will belong to whinnie in future and should not be used by other systems
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True,
                             related_name="role_user")

    name = models.CharField(_("Name"), max_length=60, db_index=True)

    # # we may not want level and credentials - only really useful for competitor and judge and these have their own model (?)
    # level = models.CharField(_("List"), max_length=20, blank=True, null=True)
    # credentials = models.CharField(_("List of credentials"), max_length=254, blank=True, null=True)

    country = CountryField(blank=True, null=True,
                           help_text=_("Optional"))

    discipline = models.CharField(choices=Disciplines.DISCIPLINE_CHOICES, max_length=2,
                                  default=Disciplines.DEFAULT_DISCIPLINE)

    organisation = models.ForeignKey("users.Organisation", blank=True, null=True, on_delete=models.CASCADE)
    active = models.BooleanField(default=True, db_index=True)
    comments = models.TextField(blank=True, null=True)

    objects = RoleQuerySet().as_manager()

    def __str__(self):
        return self.name

    class Meta:
        abstract = True
        indexes = [
            models.Index(fields=['user', 'active','role_type']),
        ]

    def save(self, *args, **kwargs):

        if not self.ref:
            self.ref = get_new_ref("role")

        # Ensure consistency between user and person
        if self.person and self.person.user and self.person.user != self.user:
            self.user = self.person.user
        elif self.user and self.user.person and self.user.person != self.person:
            self.person = self.user.person

        if self.user and self.user.person and self.person != self.user.person:
            raise ValidationError(
                f"User and Person have a one to one link - user is linked to {self.user.person} and trying to save with link to person {self.person}")

        if self.organisation != self.user.organisation:
            self.organisation = self.user.organisation

        if not self.name and self.person:
            self.name = self.person.formal_name

        super().save(*args, **kwargs)

    @classmethod
    def get_or_create(cls, role_type, user=None, person=None, **extra_fields):
        # Role is not currently to be trusted - it is creating multiple roles for the same person/competitor
        if user or person:
            roles = cls.objects.filter(role_type=role_type)

            if user:
                roles = roles.filter(user=user)
            elif person:
                roles = roles.filter(person=person)

            if roles.exists():
                return roles[0], False

        # create

        return cls.objects.create(role_type=role_type, user=user, person=person, **extra_fields), True


class PersonOrganisationBase(CreatedUpdatedMixin):
    person = models.ForeignKey("users.Person", on_delete=models.CASCADE)
    organisation = models.ForeignKey("users.Organisation", on_delete=models.CASCADE)

    membership_id = models.CharField(max_length=30, blank=True, null=True)
    membership_starts = models.DateTimeField(blank=True, null=True)
    membership_ends = models.DateTimeField(blank=True, null=True)
    membership_type = models.CharField(max_length=40, blank=True, null=True)

    class Meta:
        abstract = True




class OrganisationBase(CreatedUpdatedMixin):
    ''' the organising group for an event.  This could be a club, eg South Munster Dressage or a national body, eg. Dressage Ireland
    Note that some bodies will be listed under both Organisation and Issuer.
    It is expected that an Organisation will always run using the rule book of a single authority but this may not be the case so
    both Organisation (organising body) and Issuer (authority) are listed in the event.
    '''
    # scoring_type determines how final score is calculated. eg. dressage is totals marks as %,
    # eventing  100 - (total marks as %)
    SCORING_TYPES = (
        ("D", "Dressage"),
        ("E", "Eventing"),
        ("C", "Combined Training"),
    )
    code = models.CharField(max_length=8, primary_key=True, help_text=_("Max 10 chars upper case.  Used to tag data as belonging to the organisation"))
    name = models.CharField(_('Organisation Name'), max_length=50, db_index=True)

    test = models.BooleanField(default=False, db_index=True)
    active = models.BooleanField(default=True, db_index=True)
    scoring_type = models.CharField(max_length=1, choices=SCORING_TYPES, default='D')  # default for this organisation
    country = CountryField(blank=True, null=True)
    home_page = models.URLField(blank=True, null=True)
    logo_link_large = models.ImageField(upload_to="logo/organisation/", blank=True, null=True)
    logo_link_small = models.ImageField(upload_to="logo/organisation/", blank=True, null=True)

    def __str__(self):
        return self.name

    class Meta:
        ordering = ['name', ]
        abstract = True

    @property
    def is_test(self):
        return self.test
