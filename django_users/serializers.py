import copy
from django.utils.translation import gettext_lazy as _
from django.http import QueryDict
from django_countries.serializers import CountryFieldMixin
from phonenumber_field.serializerfields import PhoneNumberField
from rest_framework import serializers

class DynamicModelSerializer(serializers.ModelSerializer):
    """
    A base serializer that dynamically resolves models for Meta class.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Dynamically set the model if it hasn't been set yet
        if not self.Meta.model:
            raise ValueError("Meta.model must be defined or dynamically resolved in the derived serializer.")


class EmailExistsSerializerBase(DynamicModelSerializer):

    class Meta:
        model = None
        fields = ('active',  'date_joined',)

    def to_representation(self, instance):

        if not instance:
            return None

        ret = super().to_representation(instance)
        ret['competitor_name'] = None
        ret['active'] = instance.active
        #ret['user_type'] = instance.user_type
        ret['date_joined'] = instance.date_joined

        # if instance.competitor:
        #     ret['competitor_name'] = instance.competitor.name

        return ret


class UserShortSerializerBase(CountryFieldMixin, DynamicModelSerializer):

    class Meta:
        model = None
        fields = ('id','username','first_name', 'last_name',  'active', 'country','date_joined','last_login','is_active','profile')


class UserShortSerializerBase(CountryFieldMixin, DynamicModelSerializer):

    class Meta:
        model = None
        fields = ('id','username','email','first_name', 'last_name',  'active', 'country','date_joined','last_login','is_active','profile')

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
        return ret

class UserSerializerBase(CountryFieldMixin, DynamicModelSerializer):
    where_did_you_hear = serializers.CharField(max_length=255, required=False)
    city = serializers.CharField(max_length=255, required=False)
    class Meta:
        model = None
        fields = ('id','username','first_name', 'last_name',  'full_name', 'active', 'friendly_name','formal_name', 'person','country','date_joined','last_login','is_active')

    def to_representation(self, instance):

        if not instance:
            return None

        ret = super().to_representation(instance)
        if instance.person:
            ret['name'] = instance.person.name
        else:
            ret['name'] = instance.name
        ret['roles'] = instance.user_roles()

        profile = instance.profile if instance.profile else {}
        ret['county'] = profile.get('county', '')
        ret['current_level'] = profile.get('current_level', '')

        ret['preferred_channel'] = instance.preferred_channel.channel_type if instance.preferred_channel and instance.preferred_channel.channel_type else 'email'

        return ret

    def to_internal_value(self, data):
        '''merge attributes in profile with those in the user object'''
        if isinstance(data, QueryDict):
            data = data.copy()

            # Extract profile fields from data
        profile_data = {
            'where_did_you_hear': data.pop('where_did_you_hear', None),
            'city': data.pop('city', None)
        }

        internal_value = super().to_internal_value(data)

        # Merge profile data
        profile = internal_value.get('profile', {})
        profile.update({k: v for k, v in profile_data.items() if v is not None})
        internal_value['profile'] = profile

        return internal_value


    def create(self, validated_data):
        profile_data = validated_data.pop('profile', {})
        user = super().create(validated_data)
        user.profile = profile_data
        user.save()
        return user


    def update(self, instance, validated_data):
        profile_data = validated_data.pop('profile', {})
        instance = super().update(instance, validated_data)

        # Update profile fields
        profile = instance.profile if instance.profile else {}
        profile.update(profile_data)
        instance.profile = profile
        instance.save()

        return instance

class UserContactSerializerBase(DynamicModelSerializer):
    user = None
    class Meta:
        model = None
        fields = ['user','contact_date']

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        ret = ret + instance.data
        return ret

class UserEmailSerializerBase(DynamicModelSerializer):

    class Meta:
        model = None
        fields = ('email',)


class UserSyncSerializerBase(DynamicModelSerializer):

    class Meta:
        model = None
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
                    self.obj = CustomUser.objects.get(email=data['email'])
                    if self.obj.username != data['username']:
                        self.message = _("This user already exists with a different username")
                    else:
                        self.message = _("User already exists")

                except CustomUser.DoesNotExist:
                    pass
            else:
                self.message = _(
                    "Missing email field. This is the key field for users.")

            # do we know about this username
            if not self.obj:
                if 'username' in data and len(data['username']) == 36:
                    try:
                        self.obj = CustomUser.objects.get(username=data['username'])
                        self.message = _("This user already exists with a different email")
                    except CustomUser.DoesNotExist:
                        pass
                else:
                    self.message = _("Missing username field.  This is the GUID returned from keycloak in the username field.")



            return (self.message == None)

        else:
            return False

class OrganisationSerializerBase(DynamicModelSerializer):
    class Meta:
        model = None
        fields = '__all__'


class CommsChannelSerializerBase(DynamicModelSerializer):
    # mobile = PhoneNumberField()
    class Meta:
        model = None
        fields = '__all__'
        extra_kwargs = {'user': {'read_only': True}}  # Prevent user field from being directly editable

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user  # Use user from context if needed
        return super().create(validated_data)

    def validate(self, attrs):
        '''validate the phone number'''
        if attrs['channel_type'] == 'email':
            if not attrs['email']:
                raise serializers.ValidationError(_("Missing email"))
        else:
            if not attrs['mobile']:
                raise serializers.ValidationError(_("Missing mobile number"))
        return attrs
