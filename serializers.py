import copy

from django.http import QueryDict
from django_countries.serializers import CountryFieldMixin
from rest_framework import serializers

from .models import CustomUser, UserContact
from django.utils.translation import gettext_lazy as _

class EmailExistsSerializer(serializers.Serializer):

    class Meta:
        model = CustomUser
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


class UserSyncSerializer(serializers.ModelSerializer):

    class Meta:
        model = CustomUser
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


class UserShortSerializer(CountryFieldMixin, serializers.ModelSerializer):

    class Meta:
        model = CustomUser
        fields = ('id','username','email','first_name', 'last_name',  'active', 'country','date_joined','last_login','is_active','profile')

    def to_representation(self, instance):

        ret = super().to_representation(instance)
        #TODO: prevent null in db so we don't have to do this
        ret['country'] = instance.country.name if instance.country else ''
        return ret

class UserSerializer(CountryFieldMixin, serializers.ModelSerializer):

    # field that we want to collect and put in profile field but can't include in here without error
    # where_did_you_hear = serializers.CharField(max_length=255, required=False)
    # city = serializers.CharField(max_length=255, required=False)

    class Meta:
        model = CustomUser
        fields = ('id','username','first_name', 'last_name',  'full_name','email', 'active', 'friendly_name','formal_name', 'person','mobile','whatsapp','country','date_joined','last_login','is_active')



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
        ret['where_did_you_hear'] = profile.get('where_did_you_hear', '')
        ret['city'] = profile.get('city', '')

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

class UserContactSerializer(serializers.Serializer):
    user = UserSerializer
    class Meta:
        model = UserContact
        fields = ['user','contact_date']

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        ret = ret + instance.data
        return ret

class UserEmailSerializer(serializers.ModelSerializer):

    class Meta:
        model = CustomUser
        fields = ('email',)
