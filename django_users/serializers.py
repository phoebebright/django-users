import copy

from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from django.http import QueryDict
from django_countries.serializers import CountryFieldMixin
from rest_framework import serializers

User = get_user_model()

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
        fields = ('is_active',  'date_joined',)

    def to_representation(self, instance):

        if not instance:
            return None

        ret = super().to_representation(instance)
        ret['competitor_name'] = None
        ret['is_active'] = instance.is_active
        #ret['user_type'] = instance.user_type
        ret['date_joined'] = instance.date_joined

        # if instance.competitor:
        #     ret['competitor_name'] = instance.competitor.name

        return ret


class UserShortSerializerBase(CountryFieldMixin, DynamicModelSerializer):

    class Meta:
        model = None
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
        return ret

class UserSerializerBase(UserShortSerializerBase):
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'first_name', 'last_name', 'country', 'date_joined', 'last_login', 'is_active',
        'profile','person')


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
