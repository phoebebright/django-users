import logging
import ast
from datetime import datetime
from itertools import chain
import pandas as pd
from django.apps import apps
from django.conf import settings
from copy import deepcopy

from django.contrib.auth import get_user_model
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models, transaction
from django.core.mail import mail_admins
from django.db.models import Q
from django.forms import model_to_dict
from django.utils import timezone
from django.utils.dateparse import parse_time
from django.utils.functional import cached_property
from django.utils.module_loading import import_string




from django.utils.translation import gettext_lazy as _

from django.core import checks, exceptions, validators
from django.core.exceptions import ValidationError
from django.core.files import File
from django.db.models.expressions import BaseExpression
from django.db.models.expressions import Combinable
from post_office import mail

from typing import Optional, Dict, Any, Set
from django_users.models import  get_new_ref


logger = logging.getLogger('django')

ModelRoles = import_string(settings.MODEL_ROLES_PATH)
Disciplines = import_string(settings.DISCIPLINES_PATH)


class UnsignedAutoField(models.AutoField):
    def db_type(self, connection):
        return 'integer UNSIGNED AUTO_INCREMENT'

    def rel_db_type(self, connection):
        return 'integer UNSIGNED'


class RefAutoField(models.AutoField):
    description = _("Alphanumeric identifier")

    empty_strings_allowed = False
    default_error_messages = {
        'invalid': _("'%(value)s' value must be an alphanumeric."),
    }

    def __init__(self, *args, **kwargs):
        kwargs['blank'] = True
        super().__init__(*args, **kwargs)
        self.validators.append(validators.MaxLengthValidator(self.max_length))


    def get_internal_type(self):
        return "RefAutoField"

    def pre_save(self, model_instance, add):

       return get_new_ref(self.name)

    def to_python(self, value):
        if value is None:
            return value
        try:
            return str(value)
        except (TypeError, ValueError):
            raise exceptions.ValidationError(
                self.error_messages['invalid'],
                code='invalid',
                params={'value': value},
            )

    def rel_db_type(self, connection):
        return self.db_type(connection)



    def validate(self, value, model_instance):
        pass

    def get_db_prep_value(self, value, connection, prepared=False):
        if not prepared:
            value = self.get_prep_value(value)
            value = connection.ops.validate_autopk_value(value)
        return value

    def get_prep_value(self, value):
        from django.db.models.expressions import OuterRef
        value = super().get_prep_value(value)
        if value is None or isinstance(value, OuterRef):
            return value
        return int(value)


    def formfield(self, **kwargs):
        return None


class TrackChangesMixin:
    _snapshot: Optional[Dict[str, Any]] = None
    _track_fields: Optional[Set[str]] = None
    FIELDS_TO_CHECK = None

    def __init__(self, *args, track_fields: Optional[Set[str]] = None, **kwargs):

        super().__init__(*args, **kwargs)
        self._track_fields = track_fields
        self.take_snapshot()

    def take_snapshot(self):
        self._snapshot = self.as_dict

    @property
    def diff(self) -> Dict[str, Any]:
        if self._snapshot is None:
            raise ValueError("Snapshot wasn't taken; can't determine diff.")
        current_state = self.as_dict
        diffs = {k: (v, current_state[k]) for k, v in self._snapshot.items() if v != current_state.get(k)}
        return diffs

    @property
    def has_changed(self) -> bool:
        return bool(self.diff)

    @property
    def changed_fields(self) -> Set[str]:
        return set(self.diff.keys())

    @property
    def as_dict(self, check_relationship=False, include_primary_key=True):


            """
            Capture the model fields' state as a dictionary.

            Only capture values we are confident are in the database, or would be
            saved to the database if self.save() is called.
            """
            #      return model_to_dict(self, fields=[field.name for field in self._meta.fields])

            all_field = {}


            deferred_fields = self.get_deferred_fields()

            for field in self._meta.concrete_fields:

                # For backward compatibility reasons, in particular for fkey fields, we check both
                # the real name and the wrapped name (it means that we can specify either the field
                # name with or without the "_id" suffix.
                field_names_to_check = [field.name, field.get_attname()]
                if self.FIELDS_TO_CHECK and (not any(name in self.FIELDS_TO_CHECK for name in field_names_to_check)):
                    continue

                if field.primary_key and not include_primary_key:
                    continue

                # leaving this will discard related fields - still suspect that changes are not being cleared when the object is saved.
                # if field.remote_field:
                #     if not check_relationship:
                #         continue

                if field.get_attname() in deferred_fields:
                    continue

                field_value = getattr(self, field.attname)

                if isinstance(field_value, File):
                    # Uses the name for files due to a perfomance regression caused by Django 3.1.
                    # For more info see: https://github.com/romgar/django-dirtyfields/issues/165
                    field_value = field_value.name

                # If current field value is an expression, we are not evaluating it
                if isinstance(field_value, (BaseExpression, Combinable)):
                    continue

                try:
                    # Store the converted value for fields with conversion
                    field_value = field.to_python(field_value)
                except ValidationError:
                    # The current value is not valid so we cannot convert it
                    pass

                if isinstance(field_value, memoryview):
                    # psycopg2 returns uncopyable type buffer for bytea
                    field_value = bytes(field_value)

                # Explanation of copy usage here :
                # https://github.com/romgar/django-dirtyfields/commit/efd0286db8b874b5d6bd06c9e903b1a0c9cc6b00
                all_field[field.name] = deepcopy(field_value)

            return all_field


class StatusMixin(object):

    def auto_update_status(self, before, save=False):
        raise NotImplementedError()

    def on_status_change(self, user=None):
        raise NotImplementedError()

    def manual_status_update(self, new_status, user=None, force=False):
        '''need to use this so we can trigger on_status_change
        force=True - does not run save method in model - only used in testing'''
        # TODO: what if new_status is less - eg. trying to move scoresheet from final to scoring - does this happen outside of tests?

        # print(f"Manual status update for {self} from {self.status} to {new_status}")
        before = self.status
        self.status = new_status

        # must save before calling on_status_change (?)
        if force:
            super().save(update_fields=['status',])
        else:
            self.save(user=user)

        self.on_status_change(before, user)


# can't put this in mixins as refers to customuser class
class IDorNameMixin(object):

    @classmethod
    def new(cls, name, source="Unknown", creator=None):

        obj = cls.objects.create(name=name, creator=creator)
        obj.update_quality(source=source)

        return obj

    @classmethod
    def get_or_create(cls, event_ref, name=None, pk=None, creator=None, bridle_no=None, source="System", **data):
        # TODO: provide ref that can be looked up in whinnie
        # TODO: check this event is editable

        assert name or pk or bridle_no, "ID or name or bridle_no required"

        obj = None
        Event = apps.get_model(app_label='web', model_name='Event')
        event = Event.objects.get(ref=event_ref)
        assert event.status > Event.EVENT_STATUS_PUBLISHED, "Event details cannot be changed once it is published"


        if id and int(id) > 0:
            obj = cls.objects.get(pk=int(id))
        if pk and int(pk) > 0:
            obj = cls.objects.get(pk=int(pk))

        if not obj and bridle_no:
            try:
                obj = cls.objects.get(event_ref=event_ref, bridle_no=bridle_no)
            except cls.DoesNotExist:
                pass
            except cls.MultipleObjectsReturned:
                logger.warning(f"Multiple objects with same bridle_no {bridle_no} in event {event_ref}")
                obj = cls.objects.filter(event_ref=event_ref, bridle_no=bridle_no).first()


        if not obj and name:

            try:
                obj = cls.objects.get(event_ref=event_ref, name__iexact=name.strip())
            except cls.DoesNotExist:
                pass


        # SO WILL NEED TO CREATE ONE

        if not obj:

            if not name:
                raise ValidationError(_("No name supplied"))

            # so create
            if bridle_no:
                data['bridle_no'] = bridle_no

            obj = cls.objects.create(event_ref=event_ref, name=name, creator=creator, **data)


        return obj


class CreatedUpdatedMixin(models.Model):

    creator = models.ForeignKey(settings.AUTH_USER_MODEL, related_name="%(app_label)s_%(class)s_creator", editable=False,blank=True, null=True, on_delete=models.PROTECT)
    created = models.DateTimeField(_('Created Date'), auto_now_add=True, editable=False, db_index=True)
    updator = models.ForeignKey(settings.AUTH_USER_MODEL, related_name="%(app_label)s_%(class)s_updator", editable=False,blank=True, null=True, on_delete=models.PROTECT,)
    updated = models.DateTimeField(_('Updated Date'), blank=True, null=True, editable=False, db_index=True)

    class Meta:
        abstract = True

    def save_model(self, request, obj, form, change):
        if obj.pk:
            # handle updator already been set
            if obj.updator != request.user:
                obj.updator = request.user
            obj.updated = timezone.now()

        else:
            # handle creator already been set
            if not obj.creator:
                obj.creator = request.user
            obj.created = timezone.now()

        super().save_model(request, obj, form, change)

    def save(self, *args, **kwargs):

        user = None
        if 'user' in kwargs:
            user = kwargs['user']
            kwargs.pop('user')


        if self.pk:
            self.updator = user
            self.updated = timezone.now()

        else:
            if not self.creator_id and user:
                self.creator = user
            self.created = timezone.now()

        super().save(*args, **kwargs)

    @property
    def touched(self):
        return self.updated if self.updated else self.created


class CreatedMixin(models.Model):

    creator = models.ForeignKey(settings.AUTH_USER_MODEL, related_name="%(app_label)s_%(class)s_creator", editable=False, blank=True, null=True, on_delete=models.DO_NOTHING,)
    created = models.DateTimeField(_('Created Date'), auto_now_add=True, editable=False, db_index=True)

    class Meta:
        abstract = True

    def save_model(self, request, obj, form, change):
        if not obj.pk:

            obj.creator = request.user
            obj.created = timezone.now()

        super().save_model(request, obj, form, change)




    @property
    def touched(self):
        return self.created

class TagForDeletionMixin(models.Model):

    for_deletion = models.BooleanField(default=False, help_text=_("Images to be deleted"))
    for_deletion_by = models.ForeignKey(settings.AUTH_USER_MODEL, related_name="%(app_label)s_%(class)s_for_deletion", blank=True, null=True, editable=False, on_delete=models.DO_NOTHING,)
    for_deletion_set = models.DateTimeField(_('When set for deletion'), editable=False, blank=True, null=True)


    class Meta:
        abstract = True

    def tag_for_deletion(self, user, save=True):
        self.for_deletion = True
        self.for_deletion_by = user
        self.for_deletion_set = timezone.now()

        if save:
            self.save()

    def untag_for_deletion(self, user, save=True):
        self.for_deletion = False
        self.for_deletion_by = user
        self.for_deletion_set = timezone.now()

        if save:
            self.save()



# class EventQueryManager(models.Manager):
#     def get_queryset(self):
#         return PersonQuerySet(self.model, using=self._db)
#
#     def authors(self):
#         return self.get_queryset().authors()


class EventMixin(models.Model):
    '''data is grouped by event and event is added as a denormalised fields to a number of models.  Both event_id that is
    used as a ForeignKey and event_ref which is retained even if the data is moved are included.  The key field for
    Event is not changed to the ref field because it causes a problem in various libraries that expect the key field
    to be a integer.'''


    # lazy loaded models
    _Event = None

    @property
    def Event(self):
        if not self._Event:
            self._Event = apps.get_model('web', 'Event')
        return self._Event

    # event fk used for internal queries for an event
    #TODO: try making event required
    event = models.ForeignKey('web.Event',  blank=True, null=True, on_delete=models.CASCADE)
    # event_ref is used for external queries for an event
    event_ref = models.CharField(max_length=5, db_index=True, blank=True, null=True)  # this should be a required field also



    class Meta:
        abstract = True

    def save(self, *args, **kwargs):


        # make sure event_ref is populated
        if not self.event_ref and self.event:
            self.event_ref = self.event.ref

        if self.event_ref and not self.event:
            cls = apps.get_model(app_label='web', model_name='Event')

            self.event = cls.objects.get(ref=self.event_ref)

        if self.event and  self.event_ref != self.event.ref:

                logger.error(f"Event ref and event do not match for {self} - {self.event_ref} - {self.event.ref}")
                raise ValidationError(f"Event ref and event do not match for {self} - {self.event}, event.ref={self.event.ref}, event_ref={self.event_ref}")


        # if not self.event_ref and not self.event :
        #     print("Warning no event - ok if this is in rider mode but how do we know?")
            #raise ValidationError("No event specified for %s" % self)

        super().save(*args, **kwargs)


    @classmethod
    def get_event(cls, key):

        try:
            return cls.objects.get(event_ref=key)
        except cls.DoesNotExist:
            return cls.objects.get(event_id=id)


    @classmethod
    def filter_event(cls, key):
        try:
            id = int(key)
            return cls.filter(event_id = id)
        except:
            return cls.filter(event_ref = key)


    @classmethod
    def event_qs(cls, event:object, group=True) -> object:
        '''return a queryset of all entries for this event
        if this event is part of a group, return all the objects for this group, unless group=False'''
        if len(event.event_group) > 1 and group:
            return cls.objects.filter(event_ref__in=event.event_group)
        else:
            return cls.objects.filter(event=event)


class SponsorMixin(models.Model):

    primary_sponsor = models.ForeignKey("Sponsor",
                                        related_name="%(app_label)s_%(class)s_sponsor",
                                        blank=True, null=True, on_delete=models.SET_NULL)
    sponsors = models.ManyToManyField("Sponsor", blank=True)

    class Meta:
        abstract = True

    def get_all_sponsors(self):
        Sponsor = apps.get_model(app_label='web', model_name='Sponsor')
        primary_sponsor_qs = Sponsor.objects.none()
        if self.primary_sponsor is not None:
            primary_sponsor_qs = Sponsor.objects.filter(id=self.primary_sponsor.id)
        return primary_sponsor_qs.union(self.sponsors.all())



class SellerMixin(models.Model):
    '''objects are being sold by this seller '''

    price = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    discount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    fee = models.PositiveIntegerField(default=0)
    seller = models.ForeignKey("Seller", blank=True, null=True, on_delete=models.CASCADE)


    class Meta:
        abstract = True


class AliasForMixin(models.Model):
    '''allow for more than one name to be used for a single entity - eg for testsheet, judge, rider or horse'''

    STATUS_PENDING = "P"
    STATUS_LIVE = "L"
    STATUS_ALIAS = "A"
    STATUS_ARCHIVED = "X"
    DEFAULT_STATUS = "L"

    STATUS_CHOICES = ((STATUS_PENDING, "Pending Approval"),
                      (STATUS_LIVE, "Live"),
                      (STATUS_ALIAS, "Archived"),
                      (STATUS_ARCHIVED, "Alias"))

    alias_for = models.ForeignKey("self", blank=True, null=True, on_delete=models.CASCADE,
                                  limit_choices_to={'status': 'L'}, help_text=_("This name is an alias for a live instance"))
    status = models.CharField(_("Status"), max_length=1, choices=STATUS_CHOICES, default=DEFAULT_STATUS, db_index=True)

    class Meta:
        abstract = True

    @property
    def master(self):
        '''usually self, but where this is an alias for another object, return that object'''
        return self if not self.alias_for else self.alias_for

class ProblemObjectMixin(object):
    '''give objects a problem status that can be brought to the attention of admins and organisers'''

    PROBLEM_STATUS = 9

    def mark_as_problem(self, message, user=None):
        self.status = self.PROBLEM_STATUS
        super().save(update_fields=['status',])

        mail_admins(
            subject=f'Problem identified with {self.ref} in event {self.event} for user {user}',
            message=message,
        )

class DataQualityMixin(models.Model):

    '''quality of data from low if a user added to high if verified by data owner and locked on blockchain.
    The quality of the data can impact what data can be added, for example if someone tries to add a test sheet to an event that has been verified or above they will not be allowed.  Data is collected but no additional functionality implemented.
    '''

    DEFAULT_QUALITY = 50
    DEFAULT_FORM_ENTRY = 60   # better quality if entered in a form in the system

    data_quality = models.SmallIntegerField(validators=[MinValueValidator(0), MaxValueValidator(100)], default=DEFAULT_QUALITY)
    current_quality = models.ForeignKey("DataQualityLog", blank=True, null=True, on_delete=models.DO_NOTHING)

    data_source = models.CharField(max_length=30, default="System")

    class Meta:
        abstract = True

    # def save(self, *args, **kwargs):
    #
    #     if 'data_source' in kwargs:
    #
    #         source = kwargs['data_source']
    #
    #
    #     super().save(*args, **kwargs)


    #TODO: turn into job
    def update_quality(self, quality=DEFAULT_QUALITY, reason=None, reason_type=None, comment=None, creator=None, source=None, save=True):
        '''and changes to data quality for items with a ref supplied - eg. Horse may not have a ref '''
        #TODO: decide how to handle quality for Horse, Rider, Judge and implement

        if hasattr(self, 'ref') and self.ref:
            # note that expecting a dataqualitylog model in each app that uses the mixin
            cls = apps.get_model(app_label=self._meta.app_label, model_name='DataQualityLog')

            self.data_quality = quality
            if not source:
                source = "DC Data Entry"


            if not reason_type:
                reason_type = reason
            if not reason_type:
                reason_type = "general"

            obj = cls.objects.create(ref=self.ref, data_quality=quality, reason_type=reason_type, data_comment=comment, data_source=source, creator=creator)
            self.current_quality = obj

            # will create loop if call normal model save, so by pass
            if save:
                super().save(update_fields=['data_quality'])

    def bump(self, by, reason, creator=None, source=None, comment=None, save=True):

        quality = self.data_quality
        if by > 0:
            quality = min(100, self.data_quality + by)
        elif by < 0:
            quality = max(0, self.data_quality + by)

        self.update_quality(quality, reason=reason, reason_type="Bump", comment=comment, creator=creator, source=source, save=save)



class ModelDiffMixin(object):
    """
    A model mixin that tracks model fields' values and provide some useful api
    to know what fields have been changed.
    from here: http://stackoverflow.com/questions/1355150/django-when-saving-how-can-you-check-if-a-field-has-changed
    """


    def __init__(self, *args, **kwargs):
        super(ModelDiffMixin, self).__init__(*args, **kwargs)
        self.__initial = self._dict

    @property
    def diff(self):
        d1 = self.__initial
        d2 = self._dict
        diffs = [(k, (v, d2[k])) for k, v in d1.items() if v != d2[k]]
        return dict(diffs)

    @property
    def has_changed(self):
        return bool(self.diff)

    @property
    def changed_fields(self):
        return self.diff.keys()

    def get_field_diff(self, field_name):
        """
        Returns a diff for field if it's changed and None otherwise.
        """
        return self.diff.get(field_name, None)

    def save(self, *args, **kwargs):
        """
        Saves model and set initial state.
        """



        super(ModelDiffMixin, self).save(*args, **kwargs)
        self.__initial = self._dict

    def refresh_initial(self):
        self.__initial = self._dict

    @property
    def _dict(self):

        opts = self._meta
        data = {}
        for f in chain(opts.concrete_fields):
                data[f.name] = f.value_from_object(self)
        return data

class SettingMixin(object):

    # assumes there is a settings field.  May have different defaults but assume that all are type dict
    #settings = models.JSONField(default={"compid_prefix": "Class "})

    setting_parent_fields = []

    # list of valid keys
    setting_valid_keys = []

    # dict of default values
    setting_defaults = {}

    def quick_save(self,  *args, **kwargs):
        super().save( *args, **kwargs)

    def on_setting_change(self, key: str, value):
        '''action on changing a setting - add to each model using settings'''
        pass

    def get_settings(self):
        '''get all settings as a dict'''
        #TODO: where is the definitive list!
        pass

    def get_setting(self, key:str, default=None):
        '''get setting - if setting is not there return default and adding this setting'''

        if key in self.settings:
            return self.settings[key]
        # this is last in skorie2 - which is correct - needs testing
        try:

            # look in the parents
            if self.setting_parent_fields:
                for parent_field in self.setting_parent_fields:
                    parent = getattr(self, parent_field)
                    if key in parent.setting_valid_keys:
                        return parent.get_setting(key)
                    elif key in parent.setting_defaults:
                        return parent.setting_defaults[key]
        except:
            pass

        # we don't already have this setting but we do have specified a default
        if default:
            self.set_setting(key, default)
            return self.settings[key]

        # use default specified in model if we have one
        if key in self.setting_defaults:
            self.set_setting(key, self.setting_defaults[key])
            return self.settings[key]

        # look for default in object - is this the right order?
        if hasattr(self, 'default_setting_'+key):
            self.set_setting(key, getattr(self, 'default_setting_'+key))
            return self.settings[key]

        # look in the parents
        # if self.setting_parent_fields:
        #     for parent_field in self.setting_parent_fields:
        #         parent = getattr(self, parent_field)
        #         if key in parent.setting_valid_keys:
        #             return parent.get_setting(key)
        #         elif key in parent.setting_defaults:
        #             return parent.setting_defaults[key]
        #

        logger.error(f"Unable to find setting value for key {key} in {self._meta.object_name}")
        return default




    def setting_default(self, key:str):
        '''allow it to fail if invalid key or missing default - assume this will be picked up by tests'''

        assert key in self.setting_defaults

        return self.setting_defaults[key]

    def set_setting(self, key:str, value, save=True):
        ''' set a setting with a value.
        return value used.
        Assume that changing setting will not have an impact on the rest of the object so just save the settings field by default
        otherwise use with Save=False and do a save() to trigger update of whole object.'''

        if (key in self.settings and self.settings[key] != value) or not key in self.settings:
            self.settings[key] = value

            if save:
                self.quick_save(update_fields=['settings',])

            self.on_setting_change(key, value)

    def string_to_type(self, value):
        '''used in api to convert the string passed to the correct type - or guess at type!'''

        # it's a boolean - should do further validation here
        if value in ['true', 'True', 'false', 'False']:
            return (value.lower() == 'true')
        else:


            # Try integer
            try:
                return int(value)
            except ValueError:
                pass

            # Try float
            try:
                return float(value)
            except ValueError:
                pass

            # Try to evaluate as list (or other literal structures like tuple, dictionary)
            try:
                potential_list = ast.literal_eval(value)
                if isinstance(potential_list, (list, tuple, dict)):
                    return potential_list
            except (ValueError, SyntaxError):
                pass

            # If all else fails, return as string
            return value


    def on_setting_change(self, key:str, value):
        '''action on changing a setting - add to each model using settings'''
        pass


class TermsMixin(models.Model):
    '''text and link to terms and conditions/rules - used for event and competitions
    expected to supply either text or a link but not both'''
    terms_text = models.TextField(blank=True, help_text=_("Terms for entry to event"))
    terms_link = models.URLField(blank=True, help_text=_("Link to Terms for entry to event (if not entering terms text)"))
    must_accept = models.BooleanField(default=False)

    class Meta:
        abstract = True

class CritiqueMixin(models.Model):
    '''adds the option to have a critique with a competition entry
    This is for competitions where a critique is an option'''
    has_critique = models.BooleanField(default=False)
    critique_price = models.DecimalField(max_digits=10, decimal_places=2, default=0)

    class Meta:
        abstract = True

    @property
    def show_critique_option(self):
        '''if competition allows for critiques but not if the competition is only critiques -
        use to display add critique checkbox'''
        if settings.ENABLE_CRITIQUES:
            return self.has_critique and not self.competition_type.settings.get('scoring_model','default') == 'Critique'
        return False

    @property
    def has_scores(self):
        '''if competitions has scores - usually true except if the competititon is just for Critiques
        Note that this is setup in the testsheet'''

        if self.testsheet.characteristics['has_scores'] and self.competition_type.settings.get('scoring_model','default') == 'Critique':
            logger.error(f"Competition {self} for critique only is setup incorrectly - testsheet characgeristic has_scores should be set to false")
        return not self.competition_type.settings.get('scoring_model','default') == 'Critique'

    @property
    def is_critique_only(self):
        return self.competition_type.settings.get('scoring_model','default') == 'Critique'


class CompetitionScheduledMixin(models.Model):

    SCHEDULING_OPTION_ENTER_FIRST = "E"
    SCHEDULING_OPTION_SCHEDULE_FIRST = "S"
    SCHEDULING_OPTION_NONE = "_"
    SCHEDULING_CHOICES = (
        (SCHEDULING_OPTION_ENTER_FIRST, 'Enter then schedule'),
        (SCHEDULING_OPTION_SCHEDULE_FIRST, 'Schedule then enter'),
    )
    DEFAULT_SCHEDULING = SCHEDULING_OPTION_NONE

    slot_name = models.CharField(max_length=15, default="Competition")
    slot_name_plural = models.CharField(max_length=15, default="Competitions")
    secs_per_entry = models.PositiveSmallIntegerField(default=0, help_text=_("Override running time on testsheet"))
    schedule_type = models.CharField(max_length=1, default=DEFAULT_SCHEDULING)

    class Meta:
        abstract = True


    def get_secs_per_entry(self):

        if not self.testsheet:
            return settings.DEFAULT_SLOT_DURATION
        else:

            # if testsheet can be ridden in more than one size
            if self.testsheet.arena_size == "46":
                if self.arena_size == "26":
                    return self.testsheet.running_time2

            return self.testsheet.running_time

class EventScheduledMixin(models.Model):

    _Schedule = None
    @property
    def Schedule(self):
        if not self._Schedule:
            self._Schedule = apps.get_model('web', 'Schedule')
        return self._Schedule

    _News = None
    @property
    def News(self):
        if not self._News:
            self._News = apps.get_model('web','News')
        return self._News

    _Slot = None
    @property
    def Slot(self):
        if not self._News:
            self._News = apps.get_model('web','News')
        return self._News

    _CustomUser = None
    @property
    def CustomUser(self):
        if not self._CustomUser:
            self._CustomUser = apps.get_model('users','CustomUser')
        return self._CustomUser

    _EventArena = None
    @property
    def EventArena(self):
        if not self._EventArena:
            self._EventArena = apps.get_model('web','EventArena')
        return self._EventArena

    _Event = None
    @property
    def Event(self):
        if not self._Event:
            self._Event = apps.get_model('web', 'Event')
        return self._Event

    class Meta:
        abstract = True

    @property
    def is_using_scheduling(self):
        return not self.is_virtual and self.setup_schedule != self.Event.EVENT_SCHEDULING_NONE

    @property
    def is_schedulable(self):
        '''check if event is in a state where it can be scheduled'''

        if not self.status < self.Event.EVENT_STATUS_CLOSED:
            return False

        # check all competitions are schedulable
        for item in self.competitions_qs_ex_supercomp:
            if not item.status >= item.COMPETITION_STATUS_COMPLETE:
                return False
        return self.status < self.Event.EVENT_STATUS_CLOSED

    @property
    def is_scheduling(self):
        '''check if event is in a state where it can be scheduled'''
        return self.status == self.Event.EVENT_STATUS_SCHEDULING

    def create_schedules(self, num_arenas=None, start_time="09:00", user=None, add_secs_between_entries=120,
                         add_break_between_comps=0):
        # NOTE: since writing this a decision was made that in terms of an Event object, it is only ever for one day
        # so there will only one schedule (unless people create multiple competiting schedules )
        '''create a new schedule for each day of this event - can have multiple schedules for an
        event before choosing the final one so this method always creates a new schedule.
        Once schedule is created for each day - only one arena is created (may change this
        in future), start time is set to 9:00 in schedule.new'''

        if not user:
            user = self.CustomUser.system_user()

        schedules = []

        # default arenas
        if not num_arenas:
            existing = self.EventArena.objects.filter(event=self).count()
            num_arenas = max(1, existing)

        if num_arenas > 30:
            raise ValidationError("Maximum of 30 arenas allowed")

        # cooerce to datetime
        try:
            event_date = self.start_date.date()
        except:
            pass

        start_datetime = datetime.combine(event_date, parse_time(start_time))

        settings = {
            'add_secs_between_entries': add_secs_between_entries,
            'add_break_between_comps': add_break_between_comps,
        }

        schedules.append(
            self.Schedule.new(event=self, num_arenas=num_arenas, start_time=start_datetime, creator=user, settings=settings))

        # trigger update in status for event.
        self.save()

        return schedules

    def publish_times(self, user=None):
        '''there are a number of scenarios to handle:
            - if event/schedule already published, do not raise error
            - event imported times and there is no schedule - just update status of event so people can see times
            - event has no schedule and no times - warn user and update status (?)
            - there is an unpublished schedule - go ahead an publish it
            - there is more than one unpublished schedule - fail and tell user to pick one - multiple schedules not currently (Sep19) implemented'''

        schedules = self.Schedule.objects.filter(event=self.event)

        # if no schedules, just make sure event has at least scheduled status
        # Is this valid?
        if schedules.count() == 0:
            if self.event.status < self.Event.EVENT_STATUS_SCHEDULING:
                self.event.manual_status_update(self.Event.EVENT_STATUS_SCHEDULING, user)



        elif schedules.count() > 1:
            raise ValidationError("Unable to publish times as more than one schedule for this event %s " % self)

        else:
            schedules[0].publish(user)

    def unpublish_times(self, user=None):
        '''reset status of event - usually because you have additional entries to schedule
        remove published times from entries and competitions'''

        schedule = self.Schedule.objects.filter(event=self).order_by('-id').last()
        schedule.unpublish(user)
        self.News.add(self, f"{user} unpublished times for event", for_organisers=True)

    def reschedule_times(self, user=None):
        '''reset scheduled status but leave existing times against entries - check that all entries are included'''

        schedule = self.Schedule.objects.filter(event=self).order_by('-id').last()
        schedule.reschedule(user)
        self.News.add(self, f"{user} adjusting schedule times for event", for_organisers=True)

class EntryScheduledMixin(models.Model):

    _Schedule = None
    @property
    def Schedule(self):
        if not self._Schedule:
            self._Schedule = apps.get_model('web','Schedule')
        return self._Schedule

    _Slot = None
    @property
    def Slot(self):
        if not self._Slot:
            self._Slot = apps.get_model('web','Slot')
        return self._Slot

    start_time = models.DateTimeField(_("Expected start time"), blank=True, null=True, db_index=True,
                                      help_text=_("The most up to date estimate of when this entry will start"))
    planned_start_time = models.DateTimeField(_("Planned start time"), blank=True, null=True, db_index=True,
                                              help_text=_(
                                                  "Where the entry has been scheduled in advance, this is the published start time"))
    actual_start_time = models.DateTimeField(_("Actual start time"), blank=True, null=True, db_index=True,
                                             help_text=_("Where recorded, this is the actual start time"))

    # planned fields - a denormalisation for schedule to be able to print out schedules from entry
    # duration = models.PositiveSmallIntegerField(default=0, help_text=_("Duration of test plus time between non_supercomp_entries"))
    # slot = models.ForeignKey(Slot, blank=True, null=True, on_delete=models.CASCADE)

    # out_of_sequence = models.BooleanField(_("Outside expect Times"), default=False, help_text=_("eg. to fit in 3 horses in a small class, one horse is ridden out of sequence in another competition"))

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):

        add2schedules = False
        if not self.pk and self.event.is_using_scheduling and self.event.status < self.event.EVENT_STATUS_PUBLISHED and not self.is_supercomp:
            # consider creating a new schedule if it is going to be updated, certainly if it is published
            # need to raise alarm that the schedule may need to be changed
            # TODO: write tests!
            add2schedules = True

        deletefromschedule = False
        if self.deleted:
            deletefromschedule = True

        super().save(*args, **kwargs)

        if add2schedules:
            # make sure all schedules have this entry
            for schedule in self.Schedule.objects.filter(event=self.event):
                compslot, _ = self.Slot.objects.get_or_create(schedule=schedule, slot_type="C",
                                                              competition=self.competition)
                # TODO: This needs to pick up default time as going in at 5 mins
                schedule.create_slot(
                    competition=self.competition,
                    competition_slot=compslot,
                    slot_type="E",
                entry=self)

        if deletefromschedule:
            slot = self.Slot.objects.filter(entry=self)
            if slot.count() != 1:
                logger.warning(f"Expecting 1 slot when deleting entry {self} but found {slot.count()}")
            slot.delete()


    @property
    def end_time(self):
        '''only have end_time is we have scheduled in Skorie and published the schedule'''
        if not self.start_time:
            return None
        if not self.event.published_schedule:
            return None

        try:
            slot = self.Slot.objects.get(event_ref=self.event_ref, entry_id=self.id)
        except self.Slot.DoesNotExist:
            return None
        except self.Slot.MultipleObjectsReturned:
            slot = self.Slot.objects.get(event_ref=self.event_ref, entry_id=self.id).first()

        if slot:
            return slot.end_time

    @property
    def duration(self):
        '''only have duration is we have scheduled in Skorie and published the schedule'''
        if not self.start_time:
            return None
        if not self.event.published_schedule:
            return None

        if settings.USE_SCHEDULE:
            try:
                slot = self.Slot.objects.get(event_ref=self.event_ref, entry_id=self.id)
            except self.Slot.DoesNotExist:
                return None
            except self.Slot.MultipleObjectsReturned:
                slot = self.Slot.objects.get(event_ref=self.event_ref, entry_id=self.id).first()

            if slot:
                return slot.duration

        else:
            if self.end_time:
                return self.end_time - self.start_time
            else:
                return None


class EntryCritiqueMixin(models.Model):
    '''this is not for competitions that are just for critiques.
    This is for competitions where a critique is an option'''
    has_critique = models.BooleanField(default=False)

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):

        if settings.ENABLE_CRITIQUES:

            if not self.pk or 'has_critique' in self.changed_fields:
                     # this was forcing it to be critique if competition was critique
                    # self.has_critique = self.has_critique or self.competition.has_critique

                    if self.pk:
                        try:
                            order = self.orderitem.order
                            order.rebuild_order()
                        except Exception as e:
                            logger.error(f"Unable to get order for {self} - {e}")
        else:
            self.has_critique = False

        super().save(*args, **kwargs)

    @property
    def base_price(self) -> float:
        '''return base price from competition and add critique if applicable'''

        if self.has_critique:
            return self.competition.base_price + self.competition.critique_price
        else:
            return self.competition.base_price



class EntrySuperCompMixin(models.Model):
    is_supercomp = models.BooleanField(default=False, editable=False,
                                       help_text=_("Denormalised field to enable faster queries"))

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):

        # ensure denormalised field is_supercomp is correct
        if settings.USE_SUPERCOMP and not self.pk or 'competition' in self.changed_fields:
            self.is_supercomp = bool(self.competition and self.competition.is_supercomp)


        super().save(*args, **kwargs)

    #deprecated - use is_deleteable
    @property
    def deleteable(self):
        return self.is_deleteable

    @property
    def is_deleteable(self):
        '''entry can be deleted until it is paid - after that it will have to be withdrawn
        or entries have closed'''
        # TODO: this is over simplified
        # and self.event.can_online_entry

        # handling bug where entries being created without competitions
        if not self.competition:
            logger.error(f"Deleting entry {self.ref} that does not have competition assigned - this should not happen!")
            return True

        return  self.super().is_deleteable and self.is_supercomp or (self.status < self.ENTRY_STATUS_SCORING and not self.paid_date)

    def add2supercomps(self, trigger, user=None):
        '''add to all supercompetitions and trigger recalculation for all entries in the supercomps.
        eg. this entry is part of the Prelim Championship and the Leading Prelim Rider '''

        if self.hc or self.withdrawn:
            return


        for item in self.SuperCompetitionLink.objects.filter(child_competition=self.competition):
            if item.recalc_on == trigger:
                with transaction.atomic():
                    # don't want to fail scoring because of an error in supercomps
                    try:
                        self.add2supercomp(item, user)
                    except Exception as e:
                        logger.error(f"Error adding entry {self.ref} to supercomp {item.parent_competition} - {e}")





    def add2supercomp(self, supercomplink, user=None):
        '''Create (or get) an entry in the supercompetition for this entry
        then add a SuperEntryLink between these two entries, linking in the SuperCompetionLink so that
          we have access to the settings for doing the recalculation'''

        #THIS CODE FOR WHERE YOU WANT TO ONLY ADD TO SUPERCOMP WHEN ALL ENTRIES ARE DONE - NOT USED FOR NOW
        # for the moment assume you must have scores for all competitions to be included
        # if supercomplink.super_type=="Sum":
        #     child_comps = SuperCompetitionLink.objects.filter(parent_competition=supercomplink.parent_competition).values_list('child_competition_id', flat=True)
        #     num_entries = Entry.objects.accepted().filter(horse=self.horse, rider=self.rider, competition_id__in=child_comps).count()
        #     if num_entries < len(child_comps):
        #         return

        supercomp_entry = self.get_or_create_supercomp_entry(supercomplink, user)
        superentry_link = supercomp_entry.add2superentry(self, supercomplink, user)
        superentry_link.recalculate(None, user)

        return superentry_link


    def remove_update_from_supercomp(self, user=None):
        '''if status goes down or entry removed, then need to remove from SuperEntryLink and the Entry from the supercomp,
        unless there are other entries pointing to this parent entry, in which case it needs to be recalculated

        Examples assuming they are all the same competitor/partner

        child                      link              parent
        Simple - delete link and parent
        Comp 1 - Entry 1           -              Champ 1 - Entry 1

        Mutiple entries 1 champ - delete link and updte parent
        Comp 1 - Entry 1           -              Champ 1 - Entry 1
        Comp 2 - Entry 2           -              Champ 1 - Entry 1


        1 entry multiple champs - delete both links and both parents
        Comp 1 - Entry 1           -              Champ 1 - Entry 1
                                   -              Champ 2 - Entry 1

        Multiple entries multiple champs - delete both links and both parents
        Comp 1 - Entry 1           -              Champ 1 - Entry 1
                                   -              Champ 2 - Entry 1
        Comp 2 - Entry 2           -              Champ 1 - Entry 1
        '''

        links = self.SuperEntryLink.objects.filter(child_entry=self)
        if links.count() == 0:
            return

        for item in links:

            # is there more than one link pointing to the parent of this link?  If so need to recalculate parent
            parents = self.SuperEntryLink.objects.filter(parent_entry=item.parent_entry).exclude(child_entry=self)
            if (parents.count() > 0):
                # need to update the total in the parent entry
                print(f"Deleting {item} and recalculate {parents}")
                item.delete()
                item.recalculate(parents)

            else:
                parent = item.parent_entry
                print(f"Delete {item} and parent {parent}")
                item.delete()
                # we can delete the single entry
                parent.delete()



    def get_or_create_supercomp_entry(self, supercomplink, user=None):
        '''return entry for this horse/rider/section in the supercompetition, create if necessary.
        grouping is a list with one or more of:
        ["RIDER", "HORSE", "SECTION"]
        TODO: Check if placing by sectino is used
        '''
        if not user:
            user = self.User.system_user()
        competition = supercomplink.parent_competition
        grouping = supercomplink.grouping


        # if set(grouping) == {"RIDER", "HORSE", "SECTION"}:
        #     obj, _ = Entry.objects.get_or_create(horse=self.horse,
        #                      rider=self.rider,
        #                      section=self.section,
        #                                 defaults={'creator': user})
        defaults = {'creator': user, 'section': self.section }

        if set(grouping) == {"RIDER", "HORSE"}:

            obj, c = self._meta.model.objects.get_or_create(competition=competition,
                                                 horse=self.horse,
                                                 rider=self.rider,
                                                 defaults=defaults)

        elif set(grouping) == {"HORSE"}:
            obj, c = self._meta.model.objects.get_or_create(competition=competition,
                                                 horse=self.horse,
                                                 defaults=defaults)
        elif set(grouping) == {"RIDER"}:
            obj, c = self._meta.model.objects.get_or_create(competition=competition,
                                                 rider=self.rider,
                                                 defaults=defaults)

        else:
            raise ValidationError(f"Invalid grouping {grouping}")


        # mode = "Adding" if c else "Updating"
        # print(f"{mode} {obj} to {competition} - grouping {grouping} horse: {self.horse} rider: {self.rider} defaults: {defaults} ")
        return obj

    def add2superentry(self, child_entry, supercomp, user=None):

        obj, c = self.SuperEntryLink.objects.get_or_create(parent_entry = self,
                                                      child_entry=child_entry,
                                                      supercomp = supercomp,
                                                      horse = self.horse,
                                                      rider = self.rider,
                                                      )

        #
        # mode = "Adding" if c else "Updating"
        # print(f"{mode} Link child {child_entry} to {self} in {supercomp} - horse: {self.horse} rider: {self.rider}")
        return obj



    # No longer used
    def update_supercomp_highscore(self, competition:object, who:str, user:object=None):
        '''get the highest scoring entry across all entries for this who ('horse' or 'rider')'''

        childcomps = list(competition.child_comps.all().values('ref'))
        if who == 'rider':
            entries = self._meta.model.objects.filter(competition__ref__in = childcomps, rider=self.rider)
            obj, created = self._meta.model.objects.get_or_create(competition=competition, rider=self.rider)
        elif who == 'horse':
            entries = self._meta.model.objects.filter(competition__ref__in = childcomps, horse=self.horse)
            obj, created = self._meta.model.objects.get_or_create(competition=competition, horse=self.horse)
        else:
            #horserider
            obj, created = self._meta.model.objects.get_or_create(competition=competition, horse=self.horse, rider=self.rider)

        # get the entry with the highest score - may want to calculate "score" for this entry and hold it
        final_score = 0
        use_entry = None
        for item in entries:

            # replace with function to get score, depending on super_type.  may be one or cumulative
            score = item.get_score()
            if score > final_score:
                final_score = score
            final_score = max(score, final_score)

            obj.extra = {'source': self.ref}
            obj.section = obj.testsheet
            obj.testsheet = self.testsheet

            # copy results
            obj.hc = self.hc
            obj.withdrawn_date = self.withdrawn_date
            obj.withdrawn_type = self.withdrawn_type


            obj.total = self.total
            obj.penalties = self.penalties
            obj.penalties_pct = self.penalties_pct
            obj.percentage = self.percentage
            obj.collectives_total = self.collectives_total

            obj.save()
            # only accept once all scored
            # if obj.percentage != None or obj.total != None:
            #     obj.accept()

    def related_entries(self, two_way=False):
        '''return queryset of entries in supercomps that relate to this entry'''
        # there is a better way!

        if two_way:
            matches = self.SuperEntryLink.objects.filter(
                Q(parent_entry=self) | Q(child_entry=self)
            )
            links = []
            for item in matches.all():
                if item.parent_entry == self:
                    links.append(item.child_entry.pk)
                elif item.child_entry == self:
                    links.append(item.parent_entry.pk)

        else:
            links = self.SuperEntryLink.objects.filter(parent_entry=self).values_list('child_entry', flat=True)

        return self._meta.model.objects.filter(pk__in=links).exclude(pk=self.pk).order_by('placing')


class EntryCheckOutInMixin(models.Model):
    '''functions to use in Entry where ScoreSheetCheckOutInMIxin is being used'''

    class Meta:
        abstract = True

    def checkout(self, judge_event_role):
        '''all related entries will be checked out together'''

        if not self.scoresheets.first().checkout(judge_event_role):
            raise ValidationError(f"Unable to checkout {self} to {judge_event_role}")

        return True

    @property
    def is_checkoutable(self):
        '''if any scoresheet is checkoutable then the entry is checkoutable'''
        for item in self.scoresheets:
            if item.is_checkoutable:
                return True
        else:
            return False

    def is_checkinable(self):
        return self.scoresheets.first().is_checkinable

    def is_releaseable(self):
        return self.scoresheets.first().is_releaseable

    def can_checkout(self, user):
        """must be organiser or judge to checkout an entry and must be checkoutable - note that there may be multiple scoresheets - try not to use this!"""

        # handle bug where multiple scoresheets are being created - one for each judge, and then being deleted
        # so many have many, many have one, may have none
        if self.status != self.ENTRY_STATUS_READY:
            return False

        n = self.scoresheets.all().count()
        if n != 0:  # expected if judging model is JUDGING_MODEL_1OFMANY
            self.refresh_scoresheets(user)
        else:
            self.add_missing_scoresheets(user)

        scoresheet = self.scoresheets.first()
        if scoresheet:
            return scoresheet.can_checkout(user)
        else:
            return False



    def is_checkedout_to(self, user):
        """must be organiser or judge that has currently checked out"""
        for scoresheet in self.scoresheets:
            if scoresheet.is_checkedout_to(user):
                return True

        return False



class ScoreSheetCheckOutInMixin(models.Model):
    '''instead of scoresheets automatically being assigned to a judge, let the judge check them out, judge them,
    then check them in again.

    '''

    checkout_date = models.DateTimeField(null=True, blank=True)
    checkin_date = models.DateTimeField(null=True, blank=True)


    class Meta:
        abstract = True



    @property
    def is_checkedout(self):

        return self.checkout_date != None and  self.checkin_date == None



    def is_checkedout_to(self, user):

        return self.is_checkedout and self.judge.user == user

    @property
    def is_checkedin(self):

        return self.checkin_date != None


    @property
    def is_checkoutable(self):
        #TODO: check that status is always 2 (self.SHEET_STATUS_COMPLETE)
        # if self.status < self.SHEET_STATUS_COMPLETE:
        #     logger.warning(f"Checking out scoresheet that is incomplete {self}")
        result = self.checkout_date == None and \
            self.status <= self.SHEET_STATUS_COMPLETE and \
            self.entry.status >= self.entry.ENTRY_STATUS_READY and \
            self.entry.status <= self.entry.ENTRY_STATUS_ACCEPTED and \
            not self.entry.withdrawn

        return result

    @property
    def is_checkinable(self):

        if self.is_checkedout:
            return self.status == self.SHEET_STATUS_SCORED or self.status == self.SHEET_STATUS_FINAL
        else:
            return False

    def is_releaseable(self):
        '''has been checked out and has not been marked
        this is checkin without marking'''

        return self.is_checkedout and not self.is_scored

    def can_checkout(self, user):
        """
        can checkout if paid and not already marked and user can mark
        """
        # change to is organiser of event or event role in list of competition judges
        return self.is_checkoutable and self.event.has_role4event(user, [ModelRoles.ROLE_JUDGE, ModelRoles.ROLE_AUXJUDGE, ModelRoles.ROLE_ORGANISER])


    def can_checkin(self, user):
        """
        can only checkin if marked and critiqued (as appropriate)
        if user passed, then must be the person who checked out or admin
        """
        return self.is_checkinable and self.event.has_role4event(user, [ModelRoles.ROLE_JUDGE, ModelRoles.ROLE_AUXJUDGE, ModelRoles.ROLE_ORGANISER])

    def can_release(self, user):
        """
        can only release if user is the person who checked out or
        they are admin
        """

        if user.is_administrator or user.is_superuser:
            return self.is_releaseable

        if self.judge and self.judge.user == user:
            return self.is_releaseable


        return False

    def can_uncheckin(self, user):
        """
        can return to checked out status if user is the person who checked in or admin
        """

        if user.is_administrator or user.is_superuser:
            return self.is_checkedin

        if self.judge and self.judge.user == user:
            return self.is_checkedin


        return False

    def checkout(self, judge_event_role=None, user=None):

        assert judge_event_role or user

        # must have judge_event_role or user
        if judge_event_role and not user:
            user = judge_event_role.user
        elif user and not judge_event_role:
            #TODO: don't seem to have this function and what about AUXJUDGE
            judge_event_role = self.event.get_role4user(user, ModelRoles.ROLE_JUDGE)

        if self.can_checkout(user):
            self.judge = judge_event_role
            self.checkout_date = timezone.now()
            self.save()

            send_notification("on_scoresheet_checkout", self, user=user)

            return True
        else:

            return False

    def checkin(self, judge_event_role=None, user=None):
        '''can only checkin once marked/critiqued.  Checkin moves status of scoresheet straight to published,
        and does the same for the entry '''

        assert judge_event_role or user

        # must have judge_event_role or user
        if judge_event_role and not user:
            #TODO: HACK LTE AT NIGHT!
            try:
                user = judge_event_role.user
            except:
                user=judge_event_role


        # if marked/critiqued
        if self.can_checkin(user):

            self.checkin_date = timezone.now()
            self.set_status_final(user)
            # the user needs to be able to see the critique now if there is one
            self.finalise(user)
            # but maybe we don't want to publish?
            # self.entry.publish(judge_event_role.user)


            self.event.add_news(f"{user} checked in  {self.entry} in {self.entry.competition} ")

            send_notification("on_scoresheet_checkin", self, user=user)



            return True
        else:
            return False

    def uncheckin(self, user):
        '''return to checked out status'''

        if self.can_uncheckin(user):
            self.checkin_date = None
            self.status = self.SHEET_STATUS_SCORING
            self.save()

            self.entry.save()  # trigger status update
            self.event.add_news(f"{user} un-checked in  {self.entry} in {self.entry.competition} ")
            return True

        return False

    def release(self, user):
        '''checked out scoresheet is checked in unjudged'''

        if self.can_release(user):
            self.checkout_date = None
            self.checkin_date = None
            self.judge = None
            self.status = self.SHEET_STATUS_INCOMPLETE
            self.save()

            #push status of entry back
            self.entry.status = self.entry.ENTRY_STATUS_READY
            self.entry.save()  # trigger status update
            self.event.add_news(f"{user} released  {self.entry} in {self.entry.competition} ")
            return True

        return False

class HelpdeskEntryMixin(models.Model):
    '''link a ticket to an entry
    requires the EntryHelpdeskLink to be created'''

    ticket = models.ForeignKey("EntryHelpdeskLink", blank=True, null=True, on_delete=models.CASCADE)

    class Meta:
        abstract = True


class ShortlistCompMixin(models.Model):
    '''Shortlist is a type of SuperComp so must also have SuperCompMixin to use this one'''
    # shortlist_comp = models.ForeignKey('self', blank=True, null=True, on_delete=models.SET_NULL,
    #                                    related_name="shortlist4comp")

    class Meta:
        abstract = True

    @property
    def is_shortlist(self):
        '''modify to check if parent is shortlist'''
        return self.competition_type and self.competition_type.is_supercomp

    @property
    def has_shortlist(self):
        return self.shortlist_comp is not None


class RosetteMixin(models.Model):
    '''mixin for Event to create specs for rosettes for each event'''
    class Meta:
        abstract = True


    def save(self, *args, **kwargs):
        # make rosette specs for all events for now, even if not used

        new = not self.pk

        super().save(*args, **kwargs)

        if new:
            # print(f"Creating default rosettes for {self.name}")
            RosetteSpec = apps.get_model('rosettes', 'rosettespec')
            RosetteSpec.make_defaults_for_event(self)


    def on_status_change(self, before, user=None):
        '''all changes to status that effect other objects should be triggered here - but there may still be rouges in the code that need moving here '''

        if self.status >= self.EVENT_STATUS_READY and before < self.EVENT_STATUS_READY:
            # make sure we have rosette specs
            if self.get_setting("rosette_on", True):
                RosetteSpec = apps.get_model('rosettes', 'rosettespec')
                RosetteSpec.make_defaults_for_event(self)
        return super().on_status_change(before, user)

    def on_setting_change(self, key: str, value):
        '''action on changing a setting - add to each model using settings'''

        # make sure RosetteSpec is set up
        if key == 'rosette_on' and value:
            RosetteSpec = apps.get_model('rosettes', 'rosettespec')
            RosetteSpec.make_defaults_for_event(self)

        return super().on_setting_change(key, value)

class EntryRosetteMixin(models.Model):
    '''for Entry model where RosetteMixin used in Event'''

    class Meta:
        abstract = True

    @property
    def rosette(self):
        '''in most (all?) cases there is only 1 rosette.  Rosette model allows for mutliple but going to return first one here'''
        if self.rosette_entry.all().exists():
            return self.rosette_entry.all().first()

        return None


class SuperEventMixin(models.Model):
    old_parent = None
    parent = models.ForeignKey('self', blank=True, null=True, related_name="parent_event", on_delete=models.CASCADE)
    is_parent = models.BooleanField(default=False, help_text=_("Can be selected as a parent event"))

    class Meta:
        abstract = True


    def save(self, *args, **kwargs):

        # copy partners/competitors etc. to parent event if one has been added
        # note that parent is not being saved in snapshot in TrackChanges - it is a remote field and check_relationship is false
        # so have to do our own manual workaround to check for changed value
        original_event_id = self._snapshot['parent']
        move_event = 'parent' in self.changed_fields

        super().save(*args, **kwargs)

        if move_event:
            if self.parent:
                # move to parent event
                self.move_event(to_event=self.get_parent())
            else:
                # moving out of parent back to child
                old = self._meta.model.objects.get(pk=original_event_id)
                old_parent = old.get_parent()
                try:
                    self.move_event(from_event=old_parent)
                except Exception as e:
                    logger.warning(f"Error moving {self} from {old_parent} to {self.get_parent()} - {e}")


    @property
    def competitions_qs_ex_supercomp(self):

        return self.competitions.filter(deleted__isnull=True, competition_type__is_supercomp=False).order_by('orderon', 'compid',
                                                                                                             'name').prefetch_related(
            'testsheet',
            'competition_type',
            'event')

    # def sync_with_parent(self):
    #     '''if an event is given a parent event, make sure all the partners for this event are also in the parent event
    #     and the same for competitor s- SHOULD THIS BE USED?  DO WE WANT TO COPY OR MOVE?'''
    #
    #     for item in self.Competitor.objects.filter(event=self):
    #         item.copy4event(self.parent)
    #
    #     if settings.USE_PARTNER:
    #         for item in self.Partner.objects.filter(event=self):
    #             item.copy4event(self.parent)

    def sync_with_parent(self):
        '''if an event is given a parent event, make sure all the partners for this event are also in the parent event
        and the same for competitor'''

        if not self.parent:
            # removing child from parent
            self.move_event(from_event=self.parent)
        else:
            self.move_event(to_event=self.parent)

    def move_event(self, to_event=None, from_event=None):
        '''switch event on competitors and parters if parent event changes
        if to_event then need to switch from the current event to another - eg. child is current event and has new parent (to_event)
        if from_event then switch from the event to this one - eg. child being removed from parent (from_event)
        '''

        assert to_event or from_event

        if to_event:
            # child is being attached to a parent - entries in child need to point to competitors/partners in parent
            print(f"Competitor count for {self} is {self.Competitor.objects.filter(event=self).count()}")
            print(f"Competitor count for {to_event} is {self.Competitor.objects.filter(event=to_event).count()}")
            print(f"Partner count for {self} is {self.Partner.objects.filter(event=self).count()}")
            print(f"Partner count for {to_event} is {self.Partner.objects.filter(event=to_event).count()}")


            for item in self.Competitor.objects.filter(event=self):
                # already in to_event?
                try:
                    competitor = self.Competitor.objects.get(event=to_event, name__iexact=item.name)
                except self.Competitor.DoesNotExist:
                    print(f"moving competitor to {to_event} from {item.event} for {item.name}")
                    item.event = to_event
                    item.event_ref = to_event.ref
                    item.save()
                except self.Competitor.MultipleObjectsReturned:
                    print(f"multiple competitors found for {item.name} in {to_event} - linking entries to first")
                    competitor = self.Competitor.objects.filter(event=to_event, name__iexact=item.name).first()
                    for entry in self.Entry.objects.filter(competitor=item):
                        entry.competitor = competitor
                        #entry.quick_save(update_fields=['competitor'])  # removed while have rider and competitor in model
                        entry.save()
                    for c in self.Competitor.objects.filter(event=to_event, name__iexact=item.name).exclude(pk=competitor.pk):
                        print(f"deleting duplicate competitor {c} {c.pk}")
                        c.delete()


                else:

                    for entry in self.Entry.objects.filter(competitor=item):
                        print(f"moving entry {entry.ref} to existing competitor to {to_event} from {item.event} for {item.name}")
                        entry.competitor = competitor
                        entry.quick_save(update_fields=['competitor'])
                        # can delete competitor for child event now
                        item.delete()

            if settings.USE_PARTNER:
                for item in self.Partner.objects.filter(event=self):
                    # already in to_event?
                    try:
                        partner = self.Partner.objects.get(event=to_event, name__iexact=item.name)
                    except self.Partner.DoesNotExist:
                        # move
                        item.event = to_event
                        item.event_ref = to_event.ref
                        item.save()
                    else:
                        # use existing in parent and delete child
                        for entry in self.Entry.objects.filter(partner=item):
                            print(
                                f"moving entry {entry.ref} to existing partner to {to_event} from {item.event} for {item.name}")

                            partner.attributes[f'bridle_no_{item.event_ref}'] = item.bridle_no or ''
                            partner.attributes[f'bridle_no_{partner.event_ref}'] = partner.bridle_no or ''
                            partner.bridle_no = item.bridle_no    # this is copying bridle no from child - may not want to do this!
                            partner.save()

                            entry.partner = partner
                            entry.save()
                            #entry.quick_save(update_fields=['partner'])
                            # deleting orphan partner in child
                            try:
                                item.delete()
                            except Exception as e:
                                logger.warning(f"Error deleting partner {item} - {e}")

            print('------ after move ------------')
            print(f"Competitor count for {self} is {self.Competitor.objects.filter(event=self).count()}")
            print(f"Competitor count for {to_event} is {self.Competitor.objects.filter(event=to_event).count()}")
            print(f"Partner count for {self} is {self.Partner.objects.filter(event=self).count()}")
            print(f"Partner count for {to_event} is {self.Partner.objects.filter(event=to_event).count()}")

        elif from_event:
            # child is being detached from parent - entries in child need to point to competitors/partners in child
            print(f"Competitor count for {self} is {self.Competitor.objects.filter(event=self).count()}")
            print(f"Competitor count for {from_event} is {self.Competitor.objects.filter(event=from_event).count()}")
            print(f"Partner count for {self} is {self.Partner.objects.filter(event=self).count()}")
            print(f"Partner count for {from_event} is {self.Partner.objects.filter(event=from_event).count()}")
            for entry in self.Entry.objects.filter(event=self):

                used_other_events = self.Entry.objects.filter(competitor=entry.competitor).exclude(event=self).exists()

                # move or copy
                if not used_other_events:
                    print(f"moving from {from_event} to {self} for {entry.competitor}")
                    entry.competitor.event = self
                    entry.competitor.event_ref = self.ref
                    entry.competitor.save()
                else:
                    print(f"copying from {from_event} to {self} for {entry.competitor}")
                    entry.competitor.pk = None
                    entry.competitor.event = self
                    entry.competitor.event_ref = self.ref
                    entry.competitor.save()

                if settings.USE_PARTNER:

                    used_other_events = self.Entry.objects.filter(partner=entry.partner).exclude(
                        event=self).exists()

                    # move or copy
                    if not used_other_events:
                        print(f"moving from {from_event} to {self} for {entry.partner}")
                        entry.partner.event = self
                        entry.partner.event_ref = self.ref
                        entry.partner.save()
                    else:
                        print(f"copying from {from_event} to {self} for {entry.partner}")
                        entry.partner.pk = None
                        entry.partner.event = self
                        entry.partner.event_ref = self.ref
                        entry.partner.save()

            print('------ after move ------------')
            print(f"Competitor count for {self} is {self.Competitor.objects.filter(event=self).count()}")
            print(f"Competitor count for {from_event} is {self.Competitor.objects.filter(event=from_event).count()}")
            print(f"Partner count for {self} is {self.Partner.objects.filter(event=self).count()}")
            print(f"Partner count for {from_event} is {self.Partner.objects.filter(event=from_event).count()}")


    def add_child_event(self, child):
        '''link parent and child events (can't link to self)'''
        if child != self:
            child.parent = self
            child.quick_save()
            child.sync_with_parent()

    def remove_child_event(self, child):
        child.parent = None
        child.quick_save()
        child.sync_with_parent()


    def get_parent(self):
        '''return parent or this event if this event is the parent or if there is not group'''
        if self.parent:
            return self.parent
        else:
            return self


    @cached_property
    def related_events(self):
        # get other events that have the same parent, or if this is a parent, get child events

        if self.parent:
            # return other children that share the same parent and the parent
            return self.__class__.objects.filter(Q(parent=self.parent) | Q(id=self.parent_id)).exclude(ref=self.ref).order_by('-start_date')
        else:
            # return  children that have this event as parent
            return self.__class__.objects.filter(parent=self).order_by('-start_date')

    @cached_property
    def event_group(self):
        '''list of event_refs for this and related events'''
        event_group = [event.ref for event in self.related_events]
        event_group.append(self.ref)
        return event_group

    @property
    def is_in_event_group(self):
        return self.parent or self.related_events.exists()


    @property
    # deprecated, use  self.parent or is_parent
    def is_master(self):
        '''is this the master event that holds to list of partners/competitors and has the accumulator competitions?'''
        return not self.parent

    @property
    def is_superevent(self):
        '''is this the master event that holds to list of partners/competitors and has the accumulator competitions?'''
        return self.setup_enter == self.SETUP_SUPEREVENT

    @property
    def is_child_event(self):
        '''is linked to a superevent '''
        return bool(self.parent)

class SuperCompMixin(models.Model):

    '''this mixin contains code used for supercomps and must have the settings.USE_SUPERCOMP set to True to be accessed.
    It is not a wholey self contained mixin - there is is_supercomp in the CompetitionBase model and code that behaves
    different if is_supercomp is True.  It has been done partially because this was separated out after it was written
    and trying to make it technically correct ended up with more confusion that leaving it like this.
    So this mixin is mainly to group the code together and make it easier to find and understand.'''

    _SuperEntryLink = None
    @property
    def SuperEntryLink(self):
        if not self._SuperEntryLink:
            self._SuperEntryLink = apps.get_model('web', 'SuperEntryLink')
        return self._SuperEntryLink

    child_comps = models.ManyToManyField('self', symmetrical=False, through="SuperCompetitionLink")

    class Meta:
        abstract = True


    def save(self, *args, **kwargs):

        #TODO: only if competition type has changed or new

        if hasattr(self, 'is_supercomp') and hasattr(self, 'competition_type'):
            self.is_supercomp = self.competition_type.is_supercomp

        super().save(*args, **kwargs)


    @classmethod
    def copy_entry_with_media(cls, entryref, compref, supercomplink, user):
        '''entryref - ref of entry to copy
        compref - ref of competition to copy to
        user - user doing the copying

        child is the original entry
        parent is the supercomp it is being moved to

        Copy all details of an entry, creating a new entry and submission object but
        point the submission at the same media as the original submission.
        Used for Critiques'''

        entry = cls.Entry.objects.get(ref=entryref)

        # don't copy more than once
        #TODO: might have case where points to a short_list entry that has been deleted
        if entry.shortlist_entry:
            return None

        # try:
        #     existing = Entry.objects.get(entryid=entry.entryid, competition__ref=compref)
        #
        # except Entry.DoesNotExist:
        #     pass
        # else:
        #     return None

        comp = cls.objects.get(ref=compref)

        # if entry.competition.event != comp.event:
        #     raise ValidationError(f"Can't copy entry {entry} to competition {comp} as they are not in the same event")

        if comp.is_published:
            raise ValidationError(f"Competition {comp} closed for entries")

        # do we have it already?
        new = True
        try:
            new_entry = cls.Entry.objects.get(shortlist_entry=entry, competition=comp)
            new = False
        except cls.Entry.MultipleObjectsReturned:
            new_entry = cls.Entry.objects.filter(shortlist_entry=entry, competition=comp).first()
            logger.error(f"Multiple entries for {entry} in {comp} - using {new_entry}")
            new = False
        except cls.Entry.DoesNotExist:
            new_entry = cls.Entry(event=comp.event,
                          competition=comp,
                          competitor=entry.competitor,
                          section=entry.section,
                              entryid=entry.entryid,
                              first_submission=entry.first_submission,
                              shortlisted=False,
                              paid_date=timezone.now(),   # shouldn't do this but in a hurry!
                          # extra=extra,
                          creator=user)

        # prevent it creating default submission then attach submissions for linked entry then call save with 'new' - this is all very nasty
        new_entry.quick_save()

        for submission in entry.submissions.all():
            cls.EntrySubmissionLink.objects.create(entry=new_entry, submission=submission)

        # need to save to get ref etc. now that we have submission attached
        if new:
            new_entry.save(new=True)

        obj, created = cls.SuperEntryLink.objects.get_or_create(parent_entry=entry,
                                                            child_entry=new_entry,
                                                            supercomp=supercomplink)

        # entry.extra['linked_entry'] = new_entry.ref
        # entry.quick_save(update_fields=['extra'])
        return new_entry

    @property
    def is_publishable(self):
        if self.is_supercomp:
            # see if all children are published
            all_published = True
            for child in self.child_comps.all():
                if not child.is_published:
                    all_published = False
                    break
            return all_published and self.status < self.COMPETITION_STATUS_PUBLISHED
        else:
            return self.status == self.COMPETITION_STATUS_SCORED

    @property
    def is_childcomp(self):
        '''does a supercomp link to this '''
        return self.SuperCompetitionLink.objects.filter(child_competition=self).exists()

    @property
    def is_supercomp_type(self):
        '''is this a supercomp according to competition type
        Note there is a denormalised field in Competition called is_supercomp that should always have the same value'''
        return self.competition_type and self.competition_type.is_supercomp

    @property
    def supercomp_links_as_parent(self):
        '''queryset of all SuperCompetitionLink instances where this competition is the parent'''
        return self.SuperCompetitionLink.objects.filter(parent_competition=self)

    @property
    def supercomp_links_as_child(self):
        '''queryset of all SuperCompetitionLink instances where this competition is the child'''
        return self.SuperCompetitionLink.objects.filter(child_competition=self)



    def remove_orphans_from_supercomp(self, user=None):
        '''hack because I havn't found the right place to remove an orphan - an entry is added to the supercomp
        but then something changes - maybe the section is changed and that child entry no longer qualifies, so there
        is never a check to remove the old entry in the supercomp'''

        for item in self.entries.all():

                # if we have no links TO this entry in superentrylink then delete
                # this happens if there was previously a link but that link not longer applies and was removed while
                # recalculating.  This is tidying up and remove those entries in the supercomp that no longer apply
                if item.parent_entry.all().count() == 0:
                    item.delete()

    def rebuild_supercomp(self, user=None):
        '''rebuild supercomp completely - not part of normal process!'''
        if self.is_published or not self.is_supercomp:
            return

        # delete entries and links
        # parent is the entry in the supercomp
        for item in self.Entry.objects.filter(competition=self):
            print(f"Removing {item} from {self}")
            self.SuperEntryLink.objects.filter(parent_entry=item).delete()
            item.delete()

        # get Competitor to link correctly
        for link in self.SuperCompetitionLink.objects.filter(parent_competition=self):
            for item in self.Entry.objects.accepted().filter(competition=link.child_competition):
                save = False
                if item.competitor.event != item.event.get_parent():
                    parent = item.event.get_parent()
                    print(f"Replace {item.competitor.event} with {parent}")
                    try:
                        item.competitor = item.competitor.copy4event(parent)
                    except Exception as e:
                        logger.error(f"Failed to merge competitor {item.competitor} with {e}")
                    else:
                        save = True



                if save:
                        item.quick_save()

        # assuming update on RECALC_ON_ENTRY_ACCEPT and RECALC_ON_ENTRY_PUBLISH for now
        for link in self.SuperCompetitionLink.objects.filter(parent_competition=self):

            if link.recalc_on == link.RECALC_ON_ENTRY_ACCEPT:
                qs = self.Entry.objects.accepted()
            elif link.recalc_on == link.RECALC_ON_ENTRY_PUBLISH:
                qs = self.Entry.objects.published()
            elif link.recalc_on == link.RECALC_ON_COMP_PUBLISH:
                qs = self.Entry.objects.filter(competition__status=self.COMPETITION_STATUS_PUBLISHED)
            else:
                raise ValueError(f"Unhandled recalc on {link.recalc_on} - rebuild_supercomp has stopped")

            for item in qs.filter(competition=link.child_competition).exclude(hc=True).exclude(withdrawn=True):
                item.add2supercomp(link, user)

        self.update_placings()

    def supercomp_sync(self):
        '''update entries for all child competitions - should not need to be used in production as updates
        happen from the child end - DONT USE - but we are  May23'''

        if not self.is_supercomp:
            return
        print(f"SYNCING {self}")
        # this sums all entries in child comps by horse + rider
        child_comp_pk = [item.pk for item in self.child_comps.all()]
        entries = self.Entry.objects.filter(competition_id__in=child_comp_pk).values('id', 'entryid','competition_id', 'horse_id',
                                                                                'rider_id', 'total', 'tiebreak',
                                                                                'penalties', 'penalties_pct', 'score',
                                                                                'placing', 'status', 'score',
                                                                                'tiebreak',
                                                                                'points')

        recalculate_on = self.get_setting('recalculate_on', None)
        if not recalculate_on:
            raise ValueError(f"Supercomp {self} has no recalculate_on setting")
        elif recalculate_on == "EntryAccept":
            entries = entries.filter(status=self.Entry.ENTRY_STATUS_ACCEPTED)
        elif recalculate_on == "EntryPublish":
            entries = entries.filter(status=self.Entry.ENTRY_STATUS_PUBLISHED)
        else:
            raise ValueError(f"Unhandled recalculate_on {recalculate_on} for {self}")


        # for e in entries:
        #     print(f"- entry {e['horse_id']}/{e['rider_id']} = {e['score']} - {e['id']}")
        if entries:
            self.supercomp_entries_sync(list(entries))


    def supercomp_entries_sync(self, entries: dict):
        '''given a queryset of entries, calculate supercomp entry for each group'''

        entries_df = pd.DataFrame.from_records(entries).fillna(0).set_index('id', append=True).reset_index()

        def summary(x):

            result = {
                'num_entries': x['id'].count(),
                'collectives_sum': x['tiebreak'].sum(),
                'tiebreak_sum': x['tiebreak'].sum(),
                'placing_sum': x['placing'].sum(),
                'penalties_sum': x['penalties'].sum(),
                'penalties_pct_sum': x['penalties_pct'].sum(),
                'total_sum': x['total'].sum(),
                'percent_sum': x['score'].sum(),
                'percent_mean': x['score'].mean(),
                'percent_range': x['score'].max() - x['score'].min(),
                'score_sum': x['score'].sum(),
                'score_mean': x['score'].mean(),
                'score_range': x['score'].max() - x['score'].min(),
                'entries': list(x['id']),
                'status': list(x['status']),
                'scores': list(x['score']),
            }

            return pd.Series(result).fillna(0)

        summed_df = entries_df.assign(count=1).groupby(['horse_id', 'rider_id'], dropna=False).apply(summary)
        for index, item in summed_df.iterrows():

            try:
                extras = item.to_dict()
            except:
                extras = {}

            # we want to trigger a status update on the first save, so if new add with a lower status and then update it
            initial_status = self.Entry.ENTRY_STATUS_SCORING
            # if using this, then need to remove entries that got unpublished
            num_dp = self.num_dp or 2
            obj, created = self.Entry.objects.update_or_create(horse_id=index[0], rider_id=index[1], competition=self, defaults={
                'percentage': round(item.percent_mean, num_dp),
                'total': round(item.total_sum, num_dp),
                                                              'penalties': round(item.penalties_sum),
                'penalties_pct': round(item.penalties_pct_sum,num_dp),
                'collectives_total': round(item.collectives_sum, num_dp),
                'score': round(item.score_sum, num_dp),
                'tiebreak': round(item.tiebreak_sum, num_dp),
                                                              'status': initial_status,
                                                              'extra': extras,
                'creator': self.CustomUser.system_user(),
                                                          })

            updated_status = min(item['status'])
            if obj.status < updated_status:
                obj.manual_status_update(updated_status)
        return

    def parent_comps(self):
        '''queryset of competitions for which this competition is a child'''
        links = list(self.SuperCompetitionLink.objects.filter(parent_competition=self).values_list('child_competition__id',
                                                                                              flat=True))
        return self.__class__.objects.filter(pk__in=links)

    def add_child_comp(self, competition, super_type=None, scoring_model=None, recalc_on=None, user=None) -> object:
        '''add a child competition to a supercompetition
        Note that the competition can be in any event (may want to restrict this at some point) but if you force the
        competition to link to only one parent, then can't run multiple types of leagues and leading horse/rider
        However, we will issue a warning as currently the form limits the choices to child events'''

        if not recalc_on:
            recalc_on = self.SuperCompetitionLink.RECALC_ON_DEFAULT
        if not scoring_model:
            scoring_model = self.SuperCompetitionLink.SCORING_MODEL_DEFAULT
        if not super_type:
            super_type = self.SuperCompetitionLink.SUPERTYPE_DEFAULT

        if competition.event != self.event:
            logger.warning(
                f"Adding child comp {competition.ref} to {self.ref} when {competition.event} is not a child event of {self.event}")

        obj, created = self.SuperCompetitionLink.objects.get_or_create(parent_competition=self,
                                                                  child_competition=competition, defaults={'recalc_on': recalc_on,
                                                                                                           'super_type': super_type,
                                                                                                           'scoring_model': scoring_model})


        # we want to trigger save method
        obj.save()
        return obj

    def remove_child_comp(self, competition):
        try:
            obj = self.SuperCompetitionLink.objects.get(parent_competition=self, child_competition=competition)
        except self.SuperCompetitionLink.DoesNotExist:
            logger.warning(f"Failed to find and remove child comp {competition.ref} from {self.ref}")
        else:
            obj.delete()

class SubmissionEntryMixin(models.Model):
    '''while much of the code would handle multiple submissions, there is currently no requirement to have
    more than one so there is some code that cheats and just looks at this field'''
    first_submission = models.ForeignKey('Submission', on_delete=models.SET_NULL, blank=True, null=True,
                                         related_name='first_submission')

    class Meta:
        abstract = True

    def add_pending_submission(self, user=None):
        '''create an empty submission record with pin for uploading'''

        if not user:
            user = self.creator

        links = self.EntrySubmissionLink.objects.filter(entry=self)
        if links.count() > 0:
            # we will use the first one - this may not be a good assumption...
            obj = links.first()
            sub = obj.submission
        else:
            sub = self.Submission.objects.create(event=self.event, creator=user,
                                            submission_type=self.competition.competition_type.settings[
                                                'submission_type'])
            self.EntrySubmissionLink.objects.create(entry=self, submission=sub)

        return sub

    # only used for testing
    def add_submission(self, user=None, **kwargs):
        '''currently only allow 1 submission per entry'''

        if not user:
            user = self.creator

        if self.first_submission:
            sub = self.first_submission
        else:
            # not expecting this to happen
            links = self.EntrySubmissionLink.objects.filter(entry=self)
            if links.count() > 0:
                # we will use the first one - this may not be a good assumption...
                obj = links.first()
                sub = obj.submission
            else:
                sub = self.Submission.objects.create(event=self.event, creator=user,
                                                submission_type=self.competition.competition_type.settings[
                                                    'submission_type'])
                self.submissions.add(sub)

        if kwargs:
            for k, v in kwargs.items():
                setattr(sub, k, v)
            sub.save()

        # resave entry to for update of entry status
        self.updated = timezone.now()
        self.updator = user
        self.save(resave=True)

        return sub

    def add_pending_submission(self, user=None):
        '''create an empty submission record with pin for uploading'''

        if not user:
            user = self.creator

        links = self.EntrySubmissionLink.objects.filter(entry=self)
        if links.count() > 0:
            # we will use the first one - this may not be a good assumption...
            obj = links.first()
            sub = obj.submission
        else:
            sub = self.Submission.objects.create(event=self.event, creator=user,
                                            submission_type=self.competition.competition_type.settings[
                                                'submission_type'])
            self.EntrySubmissionLink.objects.create(entry=self, submission=sub)

        return sub

class PaymentsEntryMixin(models.Model):
    paid_date = models.DateTimeField(null=True, blank=True)  # required where payments2 not made via skorie
    orderitem = models.ForeignKey("skorie_payments.OrderItem", null=True, blank=True, on_delete=models.SET_NULL,
                                   related_name="entry_order_item")

    class Meta:
        abstract = True


    def pay(self, order=None, item=None, user=None, paid_date=None):
        """
        pay is normally called from order.pay() but can be called
        directly, in which case an order is created just for this
        entry
        """

        payer = user or self.creator
        assert payer, "Need user to pay"

        if order and not paid_date:
            paid_date = order.payment_date

        if item:
            self.orderitem = item
            self.paid_date = paid_date
        else:
            self.paid_date = timezone.now()  # adding this to get tests to run - is this correct?

        self.save()

    def pay_manually(self, user=None):
        '''set paid_date on entry but no order '''
        if not self.paid_date:
            self.paid_date = timezone.now()
        self.extra['manual_payment'] = True
        if user:
            self.extra['manual_payment_user'] = user.full_name
        self.save()

    @property
    def paid_manually(self):
        return self.extra.get('manual_payment', False)
#
# class PaymentEventMixin(models.Model):
#     default_competition_seller = models.ForeignKey("Seller", blank=True, null=True, on_delete=models.SET_NULL,
#                                                    related_name="competition_seller")
#     default_product_seller = models.ForeignKey("Seller", blank=True, null=True, on_delete=models.SET_NULL,
#                                                related_name="product_seller")
#
#     class Meta:
#         abstract = True

class PaymentsCompetitionMixin(models.Model):

    # REMOVE - IN THE END USED LINKED COMPETITIONS INSTEAD
    PRICING_ONE_PRICE = "B"  # basic one price for all
    PRICING_CNC = "CNC"  # choice of competition, comp and critique or critique only - requires pricing_options in settings

    PRICING_MODEL_CHOICES = (
        (PRICING_ONE_PRICE, "One price"),
        (PRICING_CNC, "Choice of competition and/or critique"),
    )
    PRICING_MODEL_DEFAULT = PRICING_ONE_PRICE

    # note that if the base_price is 0 then the competition is assumed to be free regardless of the pay_type of the Event.
    base_price = models.DecimalField(_("Price"), default=0, decimal_places=2, max_digits=10)
    pricing_model = models.CharField(max_length=3, choices=PRICING_MODEL_CHOICES, default=PRICING_MODEL_DEFAULT)

    class Meta:
        abstract = True
