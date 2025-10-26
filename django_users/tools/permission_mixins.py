import logging

from django.apps import apps
from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.contrib.auth.mixins import (AccessMixin, LoginRequiredMixin,
                                        UserPassesTestMixin)
from django.shortcuts import redirect
from django.utils.module_loading import import_string
from django.utils.translation import gettext_lazy as _

from django.contrib import auth

from rest_framework import permissions
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated, BasePermission



ModelRoles = import_string(settings.MODEL_ROLES_PATH)
Disciplines = import_string(settings.DISCIPLINES_PATH)

logger = logging.getLogger('django')

# for APIView and APIModelViews



# for django views
class HasRoleMixin(UserPassesTestMixin):
    '''user must be logged in and have role
    '''

    me = None
    my_roles = []
    current_mode = None

    role_required = "__any__"

    def test_func(self):


        if not self.request.user.is_authenticated:
            logger.info("Non-autheticated user requested access ")
            return False

        self.me = self.request.user


        # special case for superuser
        if self.me.is_superuser:
            return True


        # what roles does the user have
        if not self.my_roles and hasattr(self.me, 'roles'):
            # set in middleware
            self.my_roles_list = self.me.roles
        else:
            self.my_roles_list = [item.role_type for item in self.my_roles]
        # if role is in the also list then allow but do not change user_mode
        ordered_result = [role for role in self.my_roles_list if role in self.role_required]

        first_match = ordered_result[0] if ordered_result else None


        if first_match:
                self.request.session['user_mode'] = first_match
                return True

        # check roles that don't change mode
        if self.also_allow:
            for role in self.also_allow:
                if role in self.my_roles_list:
                    return True

        return False

    def get_permission_denied_message(self):
        return f"You do not have the role required ({self.role_required}) to access this page - {self.request.path}."


    def handle_no_permission(self):
        if self.raise_exception or self.request.user.is_authenticated:
            msg = self.get_permission_denied_message()
            self.request.permission_message = msg

            raise PermissionDenied()
        else:
            # I don't think this gets displayed
            msg = _("You do not have access. You may have been logged out.  Try logging in again. ")
            self.request.permission_message = msg
            raise PermissionDenied();

# for django views
class UserCanManageMixin(HasRoleMixin):

    role_required = ModelRoles.ROLE_MANAGER

class UserCanAdministerMixin(HasRoleMixin):

    role_required = ModelRoles.ROLE_ADMINISTRATOR

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

# for django views
class CanUpdateHelpdeskMixin(AccessMixin):

    def dispatch(self, request, *args, **kwargs):

        if not request.user.is_authenticated:
            user = auth.get_user(request)
            raise PermissionDenied("Logged in user required")

        if not request.user.has_role('devteam'):
            raise PermissionDenied("Requires extra_role devteam")

        return super().dispatch(request, *args, **kwargs)

class IsAdministrator(BasePermission):
    def has_permission(self, request, view):
        return getattr(request.user, 'is_administrator', False)
