import copy

from django.apps import apps
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.utils.translation import gettext_lazy as _
from django.http import QueryDict
from django_countries.serializer_fields import CountryField
from django_countries.serializers import CountryFieldMixin
from rest_framework import serializers

# assume that all user models have been subclass in users app in target system to allow for customisation
from users.models import Person, Role, Organisation
from web.models import EventRole

User = get_user_model()


def deep_merge_override(dst, src):
    """
    Recursively merge `src` into `dst`.
    - dict vs dict: recurse per key
    - otherwise (scalars/lists/type mismatch): src overwrites dst
    Returns a NEW dict; does not mutate inputs.
    """
    if not isinstance(dst, dict) or not isinstance(src, dict):
        # Any non-dict replaces the old value entirely
        return src

    out = {**dst}
    for k, v in src.items():
        if k in out:
            out[k] = deep_merge_override(out[k], v)
        else:
            out[k] = v
    return out


class DynamicModelSerializer(serializers.ModelSerializer):
    """
    A base serializer that dynamically resolves models for Meta class.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Dynamically set the model if it hasn't been set yet
        if not self.Meta.model:
            raise ValueError("Meta.model must be defined or dynamically resolved in the derived serializer.")


class EmailExistsSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ('is_active',  'date_joined',)

    def to_representation(self, instance):

        if not instance:
            return None

        ret = super().to_representation(instance)
        ret['competitor_name'] = None
        ret['is_active'] = instance.is_active
        ret['verified'] = instance.is_active    # for backward compatibility
        #ret['user_type'] = instance.user_type
        ret['date_joined'] = instance.date_joined
        ret['not_registered'] = False

        # if instance.competitor:
        #     ret['competitor_name'] = instance.competitor.name

        return ret


class UserShortSerializer(CountryFieldMixin, DynamicModelSerializer):

    class Meta:
        model = User
        fields = ('id','username','email','first_name', 'last_name',  'country','date_joined','last_login','is_active','profile')

    def to_representation(self, instance):

        ret = super().to_representation(instance)
        #TODO: prevent null in db so we don't have to do this
        ret['country'] = instance.country.name if instance.country else ''
        if instance.person:
            ret['friendly_name'] = instance.person.friendly_name
            ret['formal_name'] = instance.person.formal_name
            ret['sortable_name'] = instance.person.sortable_name
        else:
            ret['friendly_name'] = instance.name
            ret['formal_name'] = instance.name
            ret['sortable_name'] = instance.last_name + instance.first_name

        ret['user_pk'] = str(instance.keycloak_id) if instance.keycloak_id else instance.pk
        return ret

class UserSerializer(UserShortSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'first_name', 'last_name', 'country', 'date_joined', 'last_login', 'is_active',
        'profile','person')


    def validate_profile(self, value):
        # Optional: enforce an allowlist to avoid junk keys
        allowed = getattr(self.Meta.model, 'ALLOWED_PROFILE_FIELDS', None)
        if allowed:
            invalid = set(value.keys()) - set(allowed)
            if invalid:
                raise serializers.ValidationError(
                    f"Invalid profile fields: {', '.join(sorted(invalid))}"
                )
        return value

    def update(self, instance, validated_data):
        incoming_profile = validated_data.pop('profile', None)

        if incoming_profile is not None:
            current = instance.profile or {}
            # Deep merge with overwrite-on-conflict (but not replacing whole blob)
            instance.profile = deep_merge_override(current, incoming_profile)

        # Update non-profile fields normally
        return super().update(instance, validated_data)

    def to_representation(self, instance):

        if not instance:
            return None

        ret = super().to_representation(instance)
        if instance.person:
            ret['name'] = instance.person.name
        else:
            ret['name'] = instance.name
        ret['roles'] = instance.user_roles()


        ret['preferred_channel'] = instance.preferred_channel.channel_type if instance.preferred_channel and instance.preferred_channel.channel_type else 'email'

        return ret


class UserProfileSerializer(UserSerializer):
    class Meta:
        model = User
        fields = ('id',  'country', 'profile')

class UserSerializerBase(UserSerializer):
    pass

class UserContactSerializer(DynamicModelSerializer):
    user = None
    class Meta:
        model = User
        fields = ['user','contact_date']

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        ret = ret + instance.data
        return ret

class UserContactSerializerBase(UserContactSerializer):
    pass

class UserEmailSerializer(DynamicModelSerializer):

    class Meta:
        model = User
        fields = ('email',)


class UserSyncSerializer(DynamicModelSerializer):

    class Meta:
        model = User
        fields = ('email','username',)


    def is_valid(self, raise_exception=False):
        '''may already have all the entities setup if scoring at an event with entries
        or may be entering a old scoresheet and need to create the scoresheet, entry, competitor, partner, judge, event ....'''
        if super().is_valid(raise_exception):

            data = copy.deepcopy(self.initial_data)

            self.message = None
            self.obj = None
            user = None

            if 'email' in data:
                # do we know about this email
                try:
                    self.obj = User.objects.get(email=data['email'])
                    if self.obj.username != data['username']:
                        self.message = _("This user already exists with a different username")
                    else:
                        self.message = _("User already exists")

                except User.DoesNotExist:
                    pass
            else:
                self.message = _(
                    "Missing email field. This is the key field for users.")

            # do we know about this username
            if not self.obj:
                if 'username' in data and len(data['username']) == 36:
                    try:
                        self.obj = User.objects.get(username=data['username'])
                        self.message = _("This user already exists with a different email")
                    except User.DoesNotExist:
                        pass
                else:
                    self.message = _("Missing username field.  This is the GUID returned from keycloak in the username field.")



            return (self.message == None)

        else:
            return False

class OrganisationSerializer(CountryFieldMixin, DynamicModelSerializer):

    class Meta:
        model = Organisation
        fields = '__all__'

class OrganisationSerializerBase(OrganisationSerializer):
    pass


class CommsChannelSerializerBase(DynamicModelSerializer):
    # mobile = PhoneNumberField()
    class Meta:
        model = None
        fields = '__all__'
        extra_kwargs = {'user': {'read_only': True}}  # Prevent user field from being directly editable

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user  # Use user from context if needed
        return super().create(validated_data)

class RoleShortSerializer(serializers.ModelSerializer):

    class Meta:
        model = Role
        fields = ['id','name','ref']


class RoleSerializer(serializers.ModelSerializer):

    class Meta:
        model = Role
        fields = ['id','name','ref','person','user','organisation']

    def to_representation(self, instance):
        data = super().to_representation(instance)
        if instance.user:
            data['email'] = instance.user.email
        else:
            data['email'] = ''
        return data


class PersonSerializer(serializers.ModelSerializer):
    class Meta:
        model = Person
        fields = ['formal_name', 'friendly_name', 'sortable_name']


class SubscriptionStatusSerializer(serializers.ModelSerializer):
    """Serializer for current subscription status"""
    is_subscribed_news = serializers.ReadOnlyField()
    is_subscribed_events = serializers.ReadOnlyField()
    is_subscribed_myevents = serializers.ReadOnlyField()
    communication_preference_level = serializers.ReadOnlyField()

    class Meta:
        model = User
        fields = [
            'is_subscribed_news',
            'is_subscribed_events',
            'is_subscribed_myevents',
            'communication_preference_level'
        ]


class SubscriptionUpdateSerializer(serializers.Serializer):
    """Serializer for updating subscription preferences"""
    subscription_type = serializers.ChoiceField(
        choices=['news', 'events', 'myevents'],
        required=True
    )
    action = serializers.ChoiceField(
        choices=['subscribe', 'unsubscribe'],
        required=True
    )


class SubscriptionPreferencesSerializer(serializers.ModelSerializer):
    """Serializer for managing all subscription preferences at once"""
    subscribe_to_news = serializers.BooleanField(source='is_subscribed_news', read_only=True)
    subscribe_to_events = serializers.BooleanField(source='is_subscribed_events', read_only=True)
    subscribe_to_myevents = serializers.BooleanField(source='is_subscribed_myevents', read_only=True)

    # Write fields
    news = serializers.BooleanField(write_only=True, required=False)
    events = serializers.BooleanField(write_only=True, required=False)
    myevents = serializers.BooleanField(write_only=True, required=False)

    class Meta:
        model = User
        fields = [
            'subscribe_to_news',
            'subscribe_to_events',
            'subscribe_to_myevents',
            'news',
            'events',
            'myevents'
        ]

    def update(self, instance, validated_data):
        # Handle subscription changes
        if 'news' in validated_data:
            if validated_data['news'] != instance.is_subscribed_news:
                if validated_data['news']:
                    instance.subscribe_to('news')
                else:
                    instance.unsubscribe_from('news')

        if 'events' in validated_data:
            if validated_data['events'] != instance.is_subscribed_events:
                if validated_data['events']:
                    instance.subscribe_to('events')
                else:
                    instance.unsubscribe_from('events')

        if 'myevents' in validated_data:
            if validated_data['myevents'] != instance.is_subscribed_myevents:
                if validated_data['myevents']:
                    instance.subscribe_to('myevents')
                else:
                    instance.unsubscribe_from('myevents')

        return instance


class SubscriptionHistorySerializer(serializers.Serializer):
    """Serializer for subscription history"""
    type = serializers.CharField()
    action = serializers.CharField()
    datetime = serializers.DateTimeField()
    is_active = serializers.BooleanField()
