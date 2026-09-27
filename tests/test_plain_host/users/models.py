"""A plain-Django host's concrete users app, shaped like BuiltAir's.

- Built on CustomUserBaseBasic (not CustomUserBase): no keycloak_id/authentik_id.
- The user model tracks field changes the way BuiltAir's ModelDiffMixin does:
  it reads every field when an instance is built. A deferred-field instance
  (.only()/.defer()) then reloads each missing field, which builds another
  instance, and so on - so any .only() on the user model recurses.
"""
from django.db import models
from django.forms.models import model_to_dict

from django_users.models import (
    CommsChannelBase, CustomUserBaseBasic, CustomUserManager, OrganisationBase,
    PersonBase, PersonOrganisationBase, RoleBase, VerificationCodeBase,
)


class FieldTrackingMixin(models.Model):
    class Meta:
        abstract = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._initial = model_to_dict(self, fields=[f.name for f in self._meta.fields])


class Organisation(OrganisationBase):
    pass


class Person(PersonBase):
    pass


class PersonOrganisation(PersonOrganisationBase):
    pass


class Role(RoleBase):
    pass


class CommsChannel(CommsChannelBase):
    pass


class VerificationCode(VerificationCodeBase):
    pass


class CustomUser(FieldTrackingMixin, CustomUserBaseBasic):
    objects = CustomUserManager()
