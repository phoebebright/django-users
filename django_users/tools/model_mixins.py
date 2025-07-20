import ast
import logging
from copy import deepcopy
from itertools import chain
from typing import Optional, Dict, Any, Set

import nanoid
from django.apps import apps
from django.conf import settings
from django.core import exceptions, validators
from django.core.exceptions import ValidationError
from django.core.files import File
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models, IntegrityError
from django.db.models.expressions import BaseExpression
from django.db.models.expressions import Combinable
from django.utils import timezone
from django.utils.module_loading import import_string
from django.utils.translation import gettext_lazy as _

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

    # note this is customised for django-users and put here to avoid circular dependancy
    def get_new_ref(self, model):
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

    def pre_save(self, model_instance, add):

       return self.get_new_ref(self.name)

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



class HelpdeskEntryMixin(models.Model):
    '''link a ticket to an entry
    requires the EntryHelpdeskLink to be created'''

    ticket = models.ForeignKey("EntryHelpdeskLink", blank=True, null=True, on_delete=models.CASCADE)

    class Meta:
        abstract = True
#
# class UserSubscribeMixin(models.Model):
#     '''use where want different levels of subscribe and are using events'''
#     # Subscription tracking with audit trail
#     subscribe_news = models.DateTimeField(blank=True, null=True, help_text="When user subscribed to general news")
#     unsubscribe_news = models.DateTimeField(blank=True, null=True, help_text="When user unsubscribed from general news")
#     subscribe_events = models.DateTimeField(blank=True, null=True, help_text="When user subscribed to event updates")
#     unsubscribe_events = models.DateTimeField(blank=True, null=True,
#                                               help_text="When user unsubscribed from event updates")
#     subscribe_myevents = models.DateTimeField(blank=True, null=True,
#                                               help_text="When user subscribed to events they are entered in")
#     unsubscribe_myevents = models.DateTimeField(blank=True, null=True,
#                                                 help_text="When user unsubscribed from evenets they have entered in")
#
#     @property
#     def is_subscribed_news(self):
#         """Check if user is currently subscribed to news"""
#         return (self.subscribe_news and
#                 (not self.unsubscribe_news or self.subscribe_news > self.unsubscribe_news))
#
#     @property
#     def is_subscribed_events(self):
#         """Check if user is currently subscribed to events"""
#         return (self.subscribe_events and
#                 (not self.unsubscribe_events or self.subscribe_events > self.unsubscribe_events))
#
#     @property
#     def is_subscribed_myevents(self):
#         """Check if user is currently subscribed to their events only"""
#         return (self.subscribe_myevents and
#                 (not self.unsubscribe_myevents or self.subscribe_myevents > self.unsubscribe_myevents))
#
#     @property
#     def communication_preference_level(self):
#         """Determine user's communication preference level"""
#         if self.is_subscribed_news:
#             return 'all'
#         elif self.is_subscribed_events:
#             return 'events_only'
#         elif self.is_subscribed_myevents:
#             return 'my_events_only'
#         else:
#             return 'none'
#
#     def subscribe_to(self, subscription_type):
#         """Subscribe user to a communication type"""
#         now = timezone.now()
#         if subscription_type == 'news':
#             self.subscribe_news = now
#             self.unsubscribe_news = None
#         elif subscription_type == 'events':
#             self.subscribe_events = now
#             self.unsubscribe_events = None
#         elif subscription_type == 'myevents':
#             self.subscribe_myevents = now
#             self.unsubscribe_myevents = None
#         self.save()
#
#     def unsubscribe_from(self, subscription_type):
#         """Unsubscribe user from a communication type"""
#         now = timezone.now()
#         if subscription_type == 'news':
#             self.unsubscribe_news = now
#         elif subscription_type == 'events':
#             self.unsubscribe_events = now
#         elif subscription_type == 'myevents':
#             self.unsubscribe_myevents = now
#         self.save()
#
#     def get_subscription_history(self):
#         """Get complete subscription history for analytics"""
#         history = []
#
#         subscriptions = [
#             ('news', self.subscribe_news, self.unsubscribe_news),
#             ('events', self.subscribe_events, self.unsubscribe_events),
#             ('myevents', self.subscribe_myevents, self.unsubscribe_myevents),
#         ]
#
#         for sub_type, sub_date, unsub_date in subscriptions:
#             if sub_date:
#                 history.append({
#                     'type': sub_type,
#                     'action': 'subscribe',
#                     'datetime': sub_date,
#                     'is_active': not unsub_date or sub_date > unsub_date
#                 })
#             if unsub_date:
#                 history.append({
#                     'type': sub_type,
#                     'action': 'unsubscribe',
#                     'datetime': unsub_date,
#                     'is_active': False
#                 })
#
#         return sorted(history, key=lambda x: x['datetime'], reverse=True)
