import base64
import json

from cryptography.fernet import Fernet
from django import forms
from django.contrib import admin
from django.conf import settings
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from django.db import transaction
from django.shortcuts import render
from django.utils import timezone

from django.contrib.auth.admin import UserAdmin
from django.utils.translation import gettext_lazy as _
from users.models import ModelRoles
from .models import Organisation, UserContact, CustomUser as User, Role, Person, PersonOrganisation, CustomUser, \
    CommsChannel, VerificationCode


# Register your models here.


class  UserContactAdmin(admin.ModelAdmin):

    class Meta:
        model = UserContact

    list_display = ('user', 'contact_date', 'method', )
    list_filter = ('contact_date', 'method' )

class UserContactInline(admin.TabularInline):
    model = UserContact

def email_list(self, request, queryset):
    return render('admin/email_list.html', {
        'items': queryset.values('email').distinct().order_by(),
    })


email_list.short_description = "Generate email list"

def remove(self, request, queryset):
    for item in queryset:
        item.remove()

remove.short_description = "Remove/Anonymise user data - FOREVER!"

@transaction.non_atomic_requests
def delete_one(self, request, queryset):
    Person = User.person.field.related_model
    people_to_delete = []
    for item in queryset:
        if item.person:
            people_to_delete.append(item.person)
            item.person = None
            item.save()

        # remove user links in Person
        for p in Person.objects.filter(user=item):
            if p not in people_to_delete:
                people_to_delete.append(p)
            p.user = None
            p.save()

    for p in people_to_delete:
        p.delete()

    for item in queryset:
        item.delete()



delete_one.short_description = "If Delete fails try this"

def subscribe(self, request, queryset):
    for item in queryset:
        item.subscribe_news = timezone.now()
        item.save()

subscribe.short_description = "Subscribe"

def unsubscribe(self, request, queryset):
    for item in queryset:
        item.subscribe_news = None
        item.save()

unsubscribe.short_description = "Unsubscribe"



def credential_representation_from_hash(hash_, temporary=False):
    algorithm, hashIterations, salt, hashedSaltedValue = hash_.split('$')

    return {
        'type': 'password',
        'hashedSaltedValue': hashedSaltedValue,
        'algorithm': algorithm.replace('_', '-'),
        'hashIterations': int(hashIterations),
        'salt': base64.b64encode(salt.encode()).decode('ascii').strip(),
        'temporary': temporary
    }


def add_user(client, user):
    """
    Create user in Keycloak based on a local user including password.

    :param django_keycloak.models.Client client:
    :param django.contrib.auth.models.User user:
    """
    credentials = credential_representation_from_hash(hash_=user.password)

    client.admin_api_client.realms.by_name(client.realm.name).users.create(
        username=user.email,
        credentials=credentials,
        first_name=user.first_name,
        last_name=user.last_name,
        email=user.email,
        enabled=user.is_active
    )

def make_event_manager(self, request, queryset):

    for user in queryset:
        user.add_roles([ModelRoles.ROLE_MANAGER, ModelRoles.ROLE_ORGANISER])

make_event_manager.short_description = "Add Role Event Manager"

def add_to_keycloak(self, request, queryset):

    realm = settings.KEYCLOAK_CLIENTS['DEFAULT']['REALM']

    for user in queryset:
        add_user(client=realm.client, user=user)

add_to_keycloak.short_description = "Add to Keycloak"

class UserCreationForm(forms.ModelForm):
    """A form for creating new users. Includes all the required
    fields, plus a repeated password."""
    password1 = forms.CharField(label='Password', widget=forms.PasswordInput)
    password2 = forms.CharField(label='Password confirmation', widget=forms.PasswordInput)

    class Meta:
        model = User

        fields = ('email', )

    def clean_password2(self):
        # Check that the two password entries match
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Passwords don't match")
        return password2

    def save(self, commit=True):
        # Save the provided password in hashed format

        user = super(UserCreationForm, self).save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user

class UserChangeForm(forms.ModelForm):
    """A form for updating users. Includes all the fields on
    the user, but replaces the password field with admin's
    password hash display field.
    """
    password = ReadOnlyPasswordHashField(label= ("Password"),
        help_text= ('<a href="../password/">Change Password</a>.'))

    class Meta:
        model = User
        fields = ('email', 'password', 'extra_roles','is_active','person')

    def clean_password(self):
        # Regardless of what the user provides, return the initial value.
        # This is done here, rather than on the field, because the
        # field does not have access to the initial value
        return self.initial["password"]

# admin.site.unregister(User)
@admin.register(CustomUser)
class CustomAdmin(UserAdmin):

    list_display = ('email', 'person','username','is_active','last_login','date_joined', 'subscribe_news', 'unsubscribe_news')
    list_filter = ('is_staff', 'is_active', 'status','subscribe_news', 'unsubscribe_news')
    search_fields = (  'email','username')
    ordering = ( 'email',)
    inlines = [UserContactInline,]


    actions = [email_list, subscribe, unsubscribe, remove, add_to_keycloak, make_event_manager, delete_one]


    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (_('Personal info'), {'fields': ('username', 'person')}),
        (_('Subscribed to News'), {'fields': ('subscribe_news', 'unsubscribed_news','status','free_account')}),
        (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser','extra_roles',
                                       'groups', 'user_permissions')}),
        (_('Important dates'), {'fields': ('last_login', 'date_joined', 'removed_date')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2'),
        }),
            (_('Personal info'), {'fields': ('status',)}),
    )

    # The forms to add and change user instances
    form = UserChangeForm
    add_form = UserCreationForm

    def delete_model(self, request, obj):
        '''prevent recusion error when deleting'''

        # disconnect from person
        #TODO: for GDPR type delete, need to anonymise
        if self.person:
            self.person.user = None
            self.person.bump(-20, "deleting_user", request.user)
            self.person.save()



        obj.delete()






class OrganisationAdminForm(forms.ModelForm):
    class Meta:
        model = Organisation
        exclude = ('country',) #AttributeError: 'BlankChoiceIterator' object has no attribute '__len__'

    # def __init__(self, *args, **kwargs):
    #     super().__init__(*args, **kwargs)
    #     if self.instance and self.instance.pk:
    #         self.fields['secret_data'].initial = self.decrypt_value(self.instance.secret_data)
    #
    # def decrypt_value(self, value):
    #     cipher_suite = Fernet(settings.SECRET_KEY.encode())
    #     decrypted_value = cipher_suite.decrypt(base64.b64decode(value)).decode('utf-8')
    #     return json.loads(decrypted_value)
    #
    # def encrypt_value(self, value):
    #     cipher_suite = Fernet(settings.SECRET_KEY.encode())
    #     json_str = json.dumps(value)
    #     encrypted_value = base64.b64encode(cipher_suite.encrypt(json_str.encode('utf-8')))
    #     return encrypted_value.decode('utf-8')
    #
    # def clean_secret_data(self):
    #     data = self.cleaned_data['secret_data']
    #     return self.encrypt_value(data)



    # def decrypt_secret_data(self, obj):
    #     return json.dumps(obj.decrypt_secret_data(), indent=2)
    #
    # decrypt_secret_data.short_description = 'Decrypted Secret Data'
    # decrypt_secret_data.allow_tags = True




class PersonRoleInline(admin.TabularInline):
    model = Role
    extra = 0

    def encrypt_value(self, value):
        cipher_suite = Fernet(settings.SECRET_KEY.encode())
        json_str = json.dumps(value)
        encrypted_value = base64.b64encode(cipher_suite.encrypt(json_str.encode('utf-8')))
        return encrypted_value.decode('utf-8')

class PersonOrgInline(admin.TabularInline):
    model = PersonOrganisation
    extra = 0

@admin.register(Person)
class PersonAdmin(admin.ModelAdmin):

    class Meta:
        model = Person
    list_display = ('ref','formal_name','friendly_name','user',)
    search_fields = ('formal_name','friendly_name','user__email','ref')
    ordering = ('sortable_name', 'formal_name')
    inlines = [PersonRoleInline,PersonOrgInline]

@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):

    class Meta:
        model = Role
    list_display = ('ref','name','role_type','user','organisation',)
    list_filter = ('role_type',)
    search_fields = ('name','ref')
    ordering = ('name', 'role_type')


@admin.register(CommsChannel)
class CommsChannelAdmin(admin.ModelAdmin):
    list_display = ('user', 'channel_type', 'email', 'mobile', 'verified_at')
    list_filter = ('channel_type',)
    search_fields = ('phone', 'email')

@admin.register(VerificationCode)
class VerificationCodeAdmin(admin.ModelAdmin):
    list_display = ('user', 'channel', 'code', 'expires_at', 'created_at')
    list_filter = ('channel__channel_type',)
    search_fields = ('user__email', 'channel__email', 'channel__mobile', 'code')
