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
            self.my_roles = self.me.roles


        if not type(self.role_required) == type([]):
            self.role_required = [self.role_required,]

        # check if user has ANY of the roles required
        for role in self.role_required:
            if role in self.my_roles:
                return True


        return False

    def handle_no_permission(self):
        if self.raise_exception or self.request.user.is_authenticated:
            raise PermissionDenied(self.get_permission_denied_message())
        else:
            raise PermissionDenied(_("You do not have access. You may have been logged out.  Try logging in again. "));

# for django views
class UserCanManageMixin(HasRoleMixin):

    role_required = ModelRoles.ROLE_MANAGER

class UserCanAdministerMixin(HasRoleMixin):

    role_required = ModelRoles.ROLE_ADMINISTRATOR


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
