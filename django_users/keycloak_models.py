from django.db import models

# Create your models here.
class RealmEntity(models.Model):
    id = models.CharField(max_length=36, primary_key=True)
    name = models.CharField(max_length=255, unique=True)
    display_name = models.CharField(max_length=255, blank=True, null=True)
    display_name_html = models.TextField(blank=True, null=True)
    enabled = models.BooleanField(default=True)
    ssl_required = models.CharField(max_length=255)
    registration_allowed = models.BooleanField(default=False)
    registration_email_as_username = models.BooleanField(default=False)
    remember_me = models.BooleanField(default=False)
    verify_email = models.BooleanField(default=False)
    reset_password_allowed = models.BooleanField(default=False)
    edit_username_allowed = models.BooleanField(default=False)
    revoke_refresh_token = models.BooleanField(default=False)
    access_token_lifespan = models.IntegerField(default=300)
    sso_session_idle_timeout = models.IntegerField(default=1800)
    sso_session_max_lifespan = models.IntegerField(default=36000)
    access_token_lifespan_for_implicit_flow = models.IntegerField(default=900)
    not_before = models.IntegerField(default=0)
    default_signature_algorithm = models.CharField(max_length=255, default='RS256')


    def __str__(self):
        return self.name

    class Meta:
        app_label = 'keycloak'
        db_table = 'realm'

class ClientEntity(models.Model):
    id = models.CharField(max_length=36, primary_key=True)
    client_id = models.CharField(max_length=255, unique=True)
    name = models.CharField(max_length=255, blank=True, null=True)
    enabled = models.BooleanField(default=True)
    description = models.TextField(blank=True, null=True)
    realm = models.ForeignKey(RealmEntity, on_delete=models.CASCADE)
    secret = models.CharField(max_length=255, blank=True, null=True)
    base_url = models.URLField(blank=True, null=True)
    bearer_only = models.BooleanField(default=False)
    consent_required = models.BooleanField(default=False)
    standard_flow_enabled = models.BooleanField(default=True)
    implicit_flow_enabled = models.BooleanField(default=False)
    direct_access_grants_enabled = models.BooleanField(default=True)
    service_accounts_enabled = models.BooleanField(default=False)
    public_client = models.BooleanField(default=False)
    frontchannel_logout = models.BooleanField(default=False)
    protocol = models.CharField(max_length=255, default='openid-connect')
    full_scope_allowed = models.BooleanField(default=True)
    node_re_registration_timeout = models.IntegerField(default=-1)
    not_before = models.IntegerField(default=0)


    def __str__(self):
        return self.client_id

    class Meta:
        app_label = 'keycloak'
        db_table = 'client'

class RoleEntity(models.Model):
    id = models.CharField(max_length=36, primary_key=True)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    realm = models.ForeignKey(RealmEntity, on_delete=models.CASCADE, blank=True, null=True)
    client = models.ForeignKey(ClientEntity, on_delete=models.CASCADE, blank=True, null=True)
    client_role = models.BooleanField(default=False)
    composite = models.BooleanField(default=False)


    def __str__(self):
        return self.name

    class Meta:
        app_label = 'keycloak'
        db_table = 'role'

class GroupEntity(models.Model):
    id = models.CharField(max_length=36, primary_key=True)
    name = models.CharField(max_length=255)
    realm = models.ForeignKey(RealmEntity, on_delete=models.CASCADE)
    parent = models.ForeignKey('self', on_delete=models.CASCADE, blank=True, null=True)

    def __str__(self):
        return self.name

    class Meta:
        app_label = 'keycloak'
        db_table = 'group'


class UserEntity(models.Model):
    id = models.CharField(max_length=36, primary_key=True)
    email = models.CharField(max_length=255, blank=True, null=True)
    email_constraint = models.CharField(max_length=255, blank=True, null=True)
    email_verified = models.BooleanField(default=False)
    enabled = models.BooleanField(default=False)
    federation_link = models.CharField(max_length=255, blank=True, null=True)
    first_name = models.CharField(max_length=255, blank=True, null=True)
    last_name = models.CharField(max_length=255, blank=True, null=True)
    realm_id = models.CharField(max_length=255, blank=True, null=True)
    username = models.CharField(max_length=255, blank=True, null=True)
    created_timestamp = models.BigIntegerField(blank=True, null=True)
    service_account_client_link = models.CharField(max_length=255, blank=True, null=True)
    not_before = models.IntegerField(default=0)

    def __str__(self):
        return self.username

    class Meta:
        app_label = 'keycloak'

class UserRoleMapping(models.Model):
    user = models.ForeignKey(UserEntity, on_delete=models.CASCADE)
    role = models.ForeignKey(RoleEntity, on_delete=models.CASCADE)


    def __str__(self):
        return f"{self.user} -> {self.role}"

    class Meta:
        app_label = 'keycloak'

class UserGroupMembership(models.Model):
    group = models.ForeignKey(GroupEntity, on_delete=models.CASCADE, db_column='group_id', primary_key=True)
    user = models.ForeignKey(UserEntity, on_delete=models.CASCADE, db_column='user_id', primary_key=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['group', 'user'], name='constraint_user_group')
        ]
        app_label = 'keycloak'
        # Ensure that Django doesn't automatically add an id field
        auto_created = True
        managed = True


    def __str__(self):
        return f'{self.user_id} is in group {self.group_id}'
