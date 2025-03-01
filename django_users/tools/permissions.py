from django.utils.module_loading import import_string
from rest_framework import permissions

from django.conf import settings
from django.utils import timezone

import logging
logger = logging.getLogger('django')

ModelRoles = import_string(settings.MODEL_ROLES_PATH)


def user_role_check(request, event, role_required):

    if not request.user.is_authenticated:
        logger.info("Non-autheticated user requested access ")
        return False


    me = request.user

    # # special case if creating an event - can be done by organisers or competitors
    # if not event and request.method == "POST" and (me.is_manager or me.is_competitor):
    #     return True

    # special case for superuser
    # if me.is_superuser:
    #     return True

    if event:
        # logger.info(f"Checking user {me} has role {role_required} for event {event}")
        result = event.has_role4event(me, role_required)
    else:
        logger.error(f"user_role_check called without event paramter for user {me}")
        result = False



    return result



# add to api permission classes
class CheckRolePermissions(permissions.BasePermission):

    def has_permission(self, request, view):
        view.me = request.user
        return view.me.has_role(self.role_required)

# add to api permission classes
class IsManagerPermission(CheckRolePermissions):

    role_required = ModelRoles.ROLE_MANAGER

class IsAdministratorPermission(CheckRolePermissions):

    role_required = ModelRoles.ROLE_ADMINISTRATOR
    



class ChangeMyStuff(permissions.BasePermission):
    """
    If you entered it you can change it
    """

    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request,
        # so we'll always allow GET, HEAD or OPTIONS requests.
        if request.method in permissions.SAFE_METHODS:
            return True

        # Instance must have an attribute named `owner`.
        return obj.creator == request.user
