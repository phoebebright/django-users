import base64
import json
import random

import string
import uuid

from datetime import date, datetime, time, timedelta
from string import digits


from cryptography.fernet import Fernet

from django.apps import apps
from django.contrib.auth import authenticate, login
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.models import PermissionsMixin

from django.utils.module_loading import import_string
from django.core.mail import mail_admins

from django.conf import settings

import django

from django.utils.functional import cached_property

from django.utils import timezone

from tb_tools.storage_backends import connect_sftp
from .models_common import OrganisationBase, PersonOrganisationBase, PersonBase, RoleBase, CommsChannelBase, \
    VerificationCodeBase, UserContactBase, lazy_import, DataQualityLogBase, CustomUserBase, CustomUserManager, \
    CustomUserQuerySet

from django.db import IntegrityError, models, transaction


from django.utils.translation import gettext_lazy as _


import logging

ModelRoles = import_string(settings.MODEL_ROLES_PATH)
Disciplines = import_string(settings.DISCIPLINES_PATH)

logger = logging.getLogger('django')

class CommsChannel(CommsChannelBase):
    pass

class VerificationCode(VerificationCodeBase):
    pass


#------------------  MODELS CUSTOMISED FOR THIS APPLICATION -----------------------

class DataQualityLog(DataQualityLogBase):
    pass



class PersonOrganisation(PersonOrganisationBase):
    pass


class Person(PersonBase):
   pass

class Role(RoleBase):
    pass

class Organisation(OrganisationBase):
    code = models.CharField(max_length=8, help_text=_("Max 10 chars upper case.  Used to tag data as belonging to the organisation"))
    description = models.TextField(blank=True, null=True)
    settings = models.JSONField(default=dict, blank=True, help_text=_("Settings for this organisation"))


    @property
    def has_payment_gateway(self):
        '''this can get more sophisticated'''

        return False



class CustomUser(CustomUserBase):
    EXTRA_ROLES = {}

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

    DEFAULT_USERTYPE = "User"
    USERTYPE_ADMIN = "Admin"  # puritie only
    USERTYPE_CADMIN = "CAdmin"  # customer only
    USERTYPE_DATA = "Data"
    USERTYPE_GADGET = "Gadget"
    USERTYPE_SYSTEM = "System"
    USERTYPE_FACTORY = "Factory"
    USERTYPES = (
        (DEFAULT_USERTYPE, "User"),
        (USERTYPE_ADMIN, "Admin"),
        (USERTYPE_CADMIN, "Customer Administrator"),
        (USERTYPE_SYSTEM, "System/API"),
        (USERTYPE_FACTORY, "Factory"),
    )
    VALID_USERTYPES = [code for code, label in USERTYPES]

    usertype = models.CharField(
        _("Primary User Type"),
        db_index=True,
        max_length=8,
        choices=USERTYPES,
        default=DEFAULT_USERTYPE,
    )
    usertypes = models.CharField(
        _("All User Types"),
        max_length=100,
        blank=True,
        null=True,
        help_text=_("All permissions granted to user"),
    )
    default_key = models.CharField(
        max_length=20,
        blank=True,
        null=True,
        editable=False,
        help_text=_("browser key used for uploads"),
    )
    renew_permissions = models.DateTimeField(
        blank=True,
        null=True,
        help_text=_("Check with users ok to use cookies when date expires"),
    )

    objects = CustomUserManager.from_queryset(CustomUserQuerySet)()

    def save(self, *args, **kwargs):

        new = not self.id


        if not self.usertype in self.VALID_USERTYPES:
            raise ValidationError(f"Invalid usertype {self.usertype} for {self}")
        else:
            pass

        if "organisation" in self.changed_fields:
            logger.info(f"Organisation changed to {self.organisation} for {self} ")

            # commented out 6Dec22 trying to get it to not fail because it can't find settings.OWNER_ORG_CODE
            # prevent usertype/org mismatch - this should not have got this far
            # if self.organisation and self.organisation.code == settings.OWNER_ORG_CODE:
            #     if self.usertype in [self.USERTYPE_CADMIN,]:
            #         raise ValidationError("CADMIN is invalid user type for this user %s" % self)
            # elif self.organisation and self.usertype in [self.USERTYPE_ADMIN,]:
            #     raise ValidationError("Admin can only be granted to user %s who are part of supporting organisation" % self)

        # if usertype is pending, prevent the is_active flag being set
        if self.is_active and self.usertype == "Pending":
            self.is_active = False

        # when usertype is set to User or Admin then set is_active to True
        if not self.is_active and self.usertype in ("User", "Admin"):
            self.is_active = True

        # toggle is_staff flag if usertype is admin
        if not self.is_staff and self.usertype == "Admin":
            self.is_staff = True


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
    def is_user(self):
        """is basic user - default customer user"""
        return self.usertype in (self.DEFAULT_USERTYPE, self.USERTYPE_CADMIN)

    @property
    def is_admin(self):
        return self.usertype == self.USERTYPE_ADMIN or self.is_superuser or self.is_staff

    @property
    def is_researcher(self):
        return self.usertype in (self.USERTYPE_CADMIN, self.DEFAULT_USERTYPE)

    @property
    def is_factory(self):
        return self.usertype == self.USERTYPE_FACTORY



    @property
    def permission_expired(self):

        return not self.renew_permissions or timezone.now() > self.renew_permissions

    @property
    def can_debug(self):
        """can use debug batch_mode"""
        return (
            self.organisation.code == settings.OWNER_ORG_CODE
            and self.usertype == self.USERTYPE_ADMIN
        )

    @cached_property
    def my_loggers(self):
        from gadgetdb.models import Gadget

        return (
            Gadget.objects.mine(self)
            .active()
            .prefetch_related("gadget_model")
            .order_by("factory_id")
        )

    @cached_property
    def my_recent_loggers(self):
        all = self.my_loggers
        seven_days_ago = timezone.now() - timezone.timedelta(days=7)
        return all.filter(last_seen_timestamp__gte=seven_days_ago)

    @property
    def my_sessions(self):
        from web.models import Session

        return Session.objects.mine(self).order_by("-starts")

    @property
    def my_recent_sessions(self):
        all = self.my_sessions
        return all[:10]

    def renew_permission(self):

        now = timezone.now()
        try:
            self.renew_permissions = now.replace(year=now.year + 1)
        except ValueError:
            # leap year
            self.renew_permissions = now.replace(year=now.year + 1, day=now.day - 1)

        self.save(
            update_fields=[
                "renew_permissions",
            ]
        )

    def add_device(self, name=None, device_id=None):

        obj = Device.objects.create(user=self, name=name, device_id=device_id)
        return obj

    @property
    def has_factory_access(self):
        return self.usertypes and "/Factory" in self.usertypes

    @classmethod
    def update_or_create_from_token(cls, token):

        logger.info("Calling update or create from token")
        # get or create user
        username = token["sub"]
        try:
            user = cls.objects.get(username=username)
        except cls.DoesNotExist:
            user = cls.objects.create_user(username=username, email=token["email"])

        # see if we need to update

        # if we have org groups, assume they are organisations this user belongs to.
        # for now we are only handling one organisation per user

        # this shouldn't happen
        # if not 'groups' in token and settings.DEBUG:
        #         logger.warning(f"No groups in token for user {user}")
        # else:
        if "groups" in token:
            org_groups = [item for item in token["groups"] if item[:4] == "/org"]
            org_codes = [code.split("/")[2] for code in org_groups]
            org_code = org_codes[0] if org_codes else None
        else:
            # REMOVE - ALL USERS SHOULD HAVE ORGS
            logger.error(
                f"No groups in token for user {user} - may need to add builtin groups to mappers in client in keycloak"
            )
            org_groups = ["/org/DEF"]
            org_codes = [
                "DEF",
            ]
            org_code = "DEF"
        # make sure we have an organisation setup
        if org_code:
            org, created = Organisation.objects.get_or_create(code=org_code)
            if created:
                logger.warning(f"Created new organisation {org_code} for user {user}")

        # extract user type from groups - if more than one, take highest level
        usertype = "User"
        usertypes = "User"
        if "groups" in token:
            if "/Puritie Admins" in token["groups"]:
                usertype = "Admin"
            elif "/Customer Admin" in token["groups"]:
                usertype = "CAdmin"
            elif "/Factory" in token["groups"]:
                usertype = "Factory"
            else:
                usertype = "User"
            usertypes = token["groups"]

        # by default users have access to AQGateway only, unless they are have organisation alphasense
        # if they have the group GasCloudOnly then they only have access to TheGasCloud
        # this is controlled within django

        if (
            user.first_name != token.get("given_name", "")
            or user.last_name != token.get("family_name", "")
            or user.organisation_id != org_code
            or user.usertype != usertype
            or user.usertypes != usertypes
        ):

            user.first_name = token.get("given_name", "")
            user.last_name = token.get("family_name", "")
            user.organisation_id = org_code
            user.usertype = usertype
            user.usertypes = usertypes
            # user.is_staff = usertype == "Admin"

            user.save(
                update_fields=[
                    "first_name",
                    "last_name",
                    "organisation_id",
                    "usertype",
                    "usertypes",
                ]
            )

        return user

    @classmethod
    def uploaders(cls):

        return cls.objects.filter(
            organisation__isnull=False,
            is_active=True,
            usertype__in=("Admin", "CAdmin", "Data"),
        )

    def can_upload(self):

        return (
            self.organisation is not None
            and self.is_active
            and self.usertype in ("Admin", "CAdmin", "Data")
        )

    @classmethod
    def workflow_user(cls):

        try:
            return cls.objects.get(username=settings.WORKFLOW_USER)
        except:
            return None

    def is_workflow_user(self):
        if hasattr(settings, "WORKFLOW_USER"):
            return self.username == settings.WORKFLOW_USER
        else:
            return False

    def is_gadget_admin(self):
        """is from alphasesense and is usertype gadget or admin or superuser"""

        if self.is_superuser:
            return True

        # if alphasense - can change any gadget otherwise only those of same organisation
        return (
            self.organisation_id
            and self.organisation_id == settings.OWNER_ORG_CODE
            and self.usertype in (self.USERTYPE_GADGET, self.USERTYPE_ADMIN)
        )

    def can_view_gadget(self, gadget):

        # if alphasense - can view any gadget otherwise only those of same organisation
        if self.organisation.code == settings.OWNER_ORG_CODE:
            return True
        else:
            return self.organisation == gadget.owner

    @classmethod
    def make_dirs_for_users(cls, setting):

        sftp = connect_sftp(setting)

        for user in User.uploaders():
            mkdir_p(sftp, fullpath(setting["SFTP_STORAGE_ROOT"], user))

        sftp.close()

    @property
    def roles(self):
        """return a list of permissions this user has"""
        roles = set([])

        if self.is_superuser:
            roles.update(["ADMIN", "INVITE", "GADGETS", "DATA_UPLOAD"])
        if self.is_staff and self.usertype == self.USERTYPE_ADMIN:
            roles.update(
                [
                    "USER_ADMIN",
                    "DATA",
                    "DATA_UPLOAD",
                    "GADGETS",
                ]
            )

        if self.usertype == self.USERTYPE_ADMIN:
            roles.update(
                [
                    "INVITE",
                    "ADMIN",
                ]
            )
        elif self.usertype == self.USERTYPE_CADMIN:
            roles.update(["INVITE", "USER_ADMIN", "DATA_UPLOAD"])
        elif self.usertype == self.USERTYPE_DATA:
            roles.update(["DATA_UPLOAD", "DATA"])

        return roles



class UserContact(UserContactBase):

    pass
