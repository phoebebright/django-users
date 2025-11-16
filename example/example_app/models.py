# we create models here that we can use for testing
# imported from skorie1
import base64
import json

from cryptography.fernet import Fernet
from django.apps import apps
from django.conf import settings
from django.utils import timezone

from django_users.models import OrganisationBase, PersonOrganisationBase, PersonBase, RoleBase, ModelRoles, \
    DataQualityLogBase, CommsChannelBase, VerificationCodeBase, UserContactBase, CustomUserBase, CustomUserManager, \
    CustomUserQuerySet

from django.db import models



from django.utils.translation import gettext_lazy as _


import logging

from django_users.tools.model_mixins import DataQualityMixin

logger = logging.getLogger('django')

def lazy_import(full_path):
    """Lazily import an object from a given path."""
    module_path, _, object_name = full_path.rpartition('.')
    imported_module = __import__(module_path, fromlist=[object_name])
    return getattr(imported_module, object_name)




class CommsChannel(CommsChannelBase):

   pass

class VerificationCode(VerificationCodeBase):
    pass





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


class Person(DataQualityMixin, PersonBase):

    def save(self, *args, **kwargs):

        super().save(*args, **kwargs)
        self.change_name_globally()

    def change_name_globally(self):
        '''name is added to various models - replace them all'''
        users = self.customuser_set.all()


        # # note that person is not getting set in competitor and should be
        # Competitor = apps.get_model('web', 'Competitor')
        # for item in Competitor.objects.filter(user__in=users):
        #     item.name = self.formal_name
        #
        #     if not item.person:
        #         item.person = self
        #
        #     item.save()

        Role = apps.get_model('users', 'Role')
        for item in Role.objects.filter(person=self):
            item.name = self.formal_name
            item.save()


        # EventRole = apps.get_model('web', 'EventRole')
        # # this should probably inherit from the user object as it is not related to person
        # for item in EventRole.objects.filter(user__in=users):
        #     item.name = self.formal_name
        #     item.save()


class OrgMembershipMixin(models.Model):
    registration_id = models.CharField(max_length=20, blank=True, null=True)
    registered_start = models.DateTimeField(blank=True, null=True)
    registered_end = models.DateTimeField(blank=True, null=True)
    registration_type = models.CharField(max_length=20, blank=True, null=True)
    registration_code = models.CharField(max_length=20, blank=True, null=True)

    class Meta:
        abstract = True

    @property
    def registration_current(self, when=timezone.now()):
        '''can have a start date and no end date so this means they never expire
        must have a start if have an end'''
        if self.registered_start and self.registered_end and self.registered_start <= when <= self.registered_end:
            return True
        elif self.registered_start and not self.registered_end:
            return self.registered_start <= when
        return False

class Role(RoleBase, OrgMembershipMixin):
    pass

class Organisation(OrganisationBase):
    code = models.CharField(max_length=8, help_text=_("Max 10 chars upper case.  Used to tag data as belonging to the organisation"))
    # need to think through how to handle key being wrong/changed so system does not crash
    # settings = EncryptedJSONField(default=dict, blank=True, help_text=_("Settings for this organisation"))
    settings = models.JSONField(default=dict, blank=True, help_text=_("Settings for this organisation"))


    def decrypt_settings_data(self):
        cipher_suite = Fernet(settings.SETTINGS_KEY)
        decrypted_value = cipher_suite.decrypt(base64.b64decode(self.settings)).decode('utf-8')
        return json.loads(decrypted_value)


class CustomUser(DataQualityMixin, CustomUserBase):
    '''a user should be able to have just one login to the system and be able to switch between their role as rider, judge,
    organiser (for one organisation) and manager for two more organisations. etc.  However the mode switching is not always
    perfect.
    If you want to know what members an organisation has and what roles, look in the Role model.'''
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
    DEFAULT_USER_STATUS = USER_STATUS_TEMPORARY

    USER_STATUS = (
        (USER_STATUS_ANON, "Unknown"),
        (USER_STATUS_NA, "Not Applicable"),
        (USER_STATUS_TEMPORARY, "Temporary"),
        (USER_STATUS_UNCONFIRMED, "Unconfirmed"),
        (USER_STATUS_CONFIRMED, "Confirmed"),
        (USER_STATUS_TRIAL, "Trial"),
        (USER_STATUS_SUBSCRIBED, "Subscribed"),  #TODO: rename to avoid confusion with subscribed to newsletter
        (USER_STATUS_TRIAL_LAPSED, "Trial Lapsed"),
        (USER_STATUS_SUBSCRIBED_LAPSED, "Subscription Lapsed"),
    )
    ALLOWED_PROFILE_FIELDS = [
        "city", "where_did_you_hear","early_access","interests"
    ]
    objects = CustomUserManager.from_queryset(CustomUserQuerySet)()

    # subscribed = models.DateTimeField(blank=True, null=True)
    # unsubscribed = models.DateTimeField(blank=True, null=True)
    # # event_notifications_subscribed = models.DateTimeField(blank=True, null=True)
    # event_notifications_unsubscribed = models.DateTimeField(blank=True, null=True)


    def save(self, *args, **kwargs):

        # confirm once profile complete (ie. country is set)
        if self.country and self.status == self.USER_STATUS_UNCONFIRMED:
            self.confirm()

        super().save(*args, **kwargs)

        # during migration - copy across missing comms channel
        if self.comms_channels.all().count() == 0:
            CommsChannel.objects.create(user=self, channel_type='email', value=self.email)
            if self.mobile:
                CommsChannel.objects.create(user=self, channel_type='sms', value=self.mobile)


class UserContact(UserContactBase):

    attributes = models.JSONField(default=dict, blank=True, help_text=_("Data for this contact"))

    def save(self, *args, **kwargs):


        if self.data and not self.attributes:
            self.attributes = self.data

        super().save(*args, **kwargs)

    def positive_attributes(self):
        """Return a list of attributes and their values that were not False."""
        if self.attributes:
            try:
                return {k: v for k, v in self.attributes.items() if v not in (False, None, '')}
            except Exception as e:
                logger.error(f"Error processing attributes for {self}: {e}")
                return {}
