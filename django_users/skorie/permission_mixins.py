"""Role mixins for skorie hosts only.

Moved from `django_users.tools.permission_mixins` in 3.1.1. They read skorie
roles (issuer, organiser, judge, competitor) from the host's `ModelRoles` when
the class is defined, so in generic code they broke the import for any host
without those roles. Skorie hosts import them from here.
"""
from django.conf import settings
from django.utils.module_loading import import_string

from django_users.tools.permission_mixins import HasRoleMixin

ModelRoles = import_string(settings.MODEL_ROLES_PATH)


class UserCanAdministerOrIssuerMixin(HasRoleMixin):

    role_required = [ModelRoles.ROLE_ADMINISTRATOR, ModelRoles.ROLE_ISSUER]

class UserCanAdministerOrganise(HasRoleMixin):

    role_required = [ModelRoles.ROLE_ADMINISTRATOR, ModelRoles.ROLE_ORGANISER]
    mode_role = ModelRoles.ROLE_ORGANISER

class UserCanJudgeMixin(HasRoleMixin):

    role_required = ModelRoles.JUDGE_ROLES
    also_allow = [ModelRoles.ROLE_MANAGER, ModelRoles.ROLE_ADMINISTRATOR]
    mode_role = ModelRoles.ROLE_JUDGE

class UserCanCompeteMixin(HasRoleMixin):

    role_required = ModelRoles.ROLE_COMPETITOR
    mode_role = ModelRoles.ROLE_COMPETITOR

    def get_permission_denied_message(self):
        return f"Rider access is currently in Beta.  If you would like to try the new pages for Riders, please email phoebe@skor.ie to request access to this page - {self.request.path}."


class UserCanOrganiserMixin(HasRoleMixin):

    role_required = ModelRoles.ROLE_ORGANISER
