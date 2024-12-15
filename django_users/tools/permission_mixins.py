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
from tools.permissions import IsOrganiser4EventPermission, IsAnyRole4EventPermission, \
    get_event, user_role_check, user_can_enter_check
from tools.exceptions import NoEventSpecified, EventPermissionDenied

ModelRoles = import_string(settings.MODEL_ROLES_PATH)
Disciplines = import_string(settings.DISCIPLINES_PATH)

logger = logging.getLogger('django')

# for APIView and APIModelViews




class EventAPIMixin(APIView):
    '''extract event and place in class'''
    event = None


    def initial(self, request, *args, **kwargs):

        if request.user.is_authenticated:
            self.user = request.user

        # middleware is extracting event but it's not getting through to main request - why???
        if request._request.event:
            self.event = request._request.event

        self.event = get_event(request, kwargs)

        super().initial(request, *args, **kwargs)

class EventRequiredAPIMixin(APIView):
    '''extract event and place in class'''
    event = None

    def initial(self, request, *args, **kwargs):

        if request.user.is_authenticated:
            self.user = request.user

        # middleware is extracting event but it's not getting through to main request - why???
        # if request._request.event:
        #     self.event = request._request.event



        self.event = get_event(request, kwargs)
        if not self.event:
            raise NoEventSpecified()

        super().initial(request, *args, **kwargs)

    def get_queryset(self):
        '''add event to filter'''
        qs = super().get_queryset()
        return qs.filter(event_ref=self.event.ref)

class PublicEventRequiredAPIMixin(APIView):
    '''extract event and place in class - event must be public'''
    event = None

    def initial(self, request, *args, **kwargs):

        if request.user.is_authenticated:
            self.user = request.user

        # middleware is extracting event but it's not getting through to main request - why???
        if request._request.event:
            self.event = request._request.event

        self.event = get_event(request, kwargs)
        if not self.event or not self.event.is_accessible(request.user):
            raise NoEventSpecified()

        super().initial(request, *args, **kwargs)

class UnpublishedEventRequiredAPIMixin(APIView):
    '''generally events cannot be changed once they are published'''
    event = None

    def initial(self, request, *args, **kwargs):

        if not self.event:
            raise PermissionDenied("Mixin in wrong order or no event supplied")

        if self.event.is_published:
            raise EventPermissionDenied("Event is published and cannot be changed")

        super().initial(request, *args, **kwargs)

class EventOrganiserWriteTeamReadPermissionMixin(EventRequiredAPIMixin):

            def get_permissions(self):

                # write requires organiser, eventteam get read:
                if self.request.method in permissions.SAFE_METHODS:
                    permission_classes = (IsAuthenticated, IsAnyRole4EventPermission)
                # elif self.event.is_published:
                #     permission_classes = (IsAuthenticated, IsAnyRole4EventPermission)
                else:
                    permission_classes = (IsAuthenticated, IsOrganiser4EventPermission)

                return [permission() for permission in permission_classes]


class EventOpenForEntryAPIMixin(EventRequiredAPIMixin):

    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)

        # if not self.event.is_open_for_entries():
        if not self.event.can_enter(request.user):
            if not self.event.is_open_for_entries():
                raise EventPermissionDenied(f"Event is not open for {{self.event.booking_name_plural}}")
            else:
                raise EventPermissionDenied(f"You do not have permission to add {{self.event.booking_name_plural}} to this event")

    def get_permissions(self):
        # write requires organiser, eventteam get read:
        if self.request.method in permissions.SAFE_METHODS:
            permission_classes = (IsAuthenticated, IsAnyRole4EventPermission)
        else:
            permission_classes = (IsAuthenticated, IsOrganiser4EventPermission)

        return [permission() for permission in permission_classes]

class EventOpenForEntryAnonAPIMixin(EventRequiredAPIMixin):

    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)

        if not self.event.is_open_for_entries():
            raise EventPermissionDenied("Event is not open for entries")


    def get_permissions(self):


        return []

# for django view


class EventIsPublicMixin(AccessMixin):
    event = None

    def dispatch(self, request, *args, **kwargs):

        if not self.event:
            self.event = get_event(self.request, kwargs)

        # and not self.event.is_private and not self.event.can_organise(request.user):
        if not self.event.is_accessible(request.user):
            return self.handle_no_permission()

        return super().dispatch(request, *args, **kwargs)

    def handle_no_permission(self):
        return redirect('no-access')

# for django view
class EventIsPublicOrEventTeamMixin(AccessMixin):
    event = None

    def dispatch(self, request, *args, **kwargs):

        if not self.event:
            try:
                self.event = get_event(self.request, kwargs)
            except:
                return self.handle_no_permission()

        if not (self.event.is_accessible(request.user) or self.event.has_role4event(request.user, "__any__")) :
            return self.handle_no_permission()

        return super().dispatch(request, *args, **kwargs)

    def handle_no_permission(self):

        if not self.event:
            return redirect('no-access')
        elif not self.event.is_public:
            return redirect('not-public-event', event_ref= self.event.ref)
        else:
            return redirect('no-access')

# for django view
class EventAccessMixin(AccessMixin):
    '''extract event and place in class'''

    def dispatch(self, request, *args, **kwargs):
        try:
            if not self.event:
                self.event = get_event(self.request, kwargs)
        except:
            pass

        return super().dispatch(request, *args, **kwargs)

class LoginAndEventIsPublicMixin(AccessMixin):
    event = None

    def dispatch(self, request, *args, **kwargs):

        if not self.event:
            self.event = get_event(self.request, kwargs)


        if not request.user.is_authenticated or not self.event.is_accessible(request.user):
            return self.handle_no_permission()

        return super().dispatch(request, *args, **kwargs)

    def handle_no_permission(self):

            if not self.event.is_public:
                return redirect('not-public')
            else:
                return redirect('login')

# for django view
class LoginOrEventIsPublishedMixin(AccessMixin):
    event = None

    def dispatch(self, request, *args, **kwargs):

        if not self.event:
            self.event = get_event(self.request, kwargs)

        #NOTE THIS IS USING IS_PUBLISHED - WHICH IS FINE FOR RESULTS BUT COULD BE WRONG FOR OTHER USES.
        if not request.user.is_authenticated and not self.event.is_published:
            return self.handle_no_permission()

        return super().dispatch(request, *args, **kwargs)

    def handle_no_permission(self):

        if not self.event.is_public:
            return redirect('not-public')
        else:
            return redirect('no-access')


# for django view
class RequiresEventMixin(AccessMixin):
    event = None

    def dispatch(self, request, *args, **kwargs):

        if not self.event:
            self.event = get_event(self.request, kwargs)

        return super().dispatch(request, *args, **kwargs)

def get_context_data(self, **kwargs):

    context = super().get_context_data(**kwargs)
    context['event'] = self.event
    return context

class UserIsCompetitorEventMixin(UserPassesTestMixin):
    event = None
    me = None

    def test_func(self):

        if not self.request.user.is_authenticated:
            logger.info("Non-autheticated user requested access ")
            return False

        if not self.event:
            self.event = get_event(self.request, self.kwargs)

        if self.event:
            parent = self.event.get_parent()

            self.me = self.request.user

            Competitor = apps.get_model('web', 'Competitor')
            try:
                competitor = Competitor.objects.get(event=parent, user=self.me)
            except Competitor.DoesNotExist:
                competitor = None
            except Competitor.MultipleObjectsReturned:
                logger.error(f"Multiple competitors for user {self.me} in event {self.event}")
                competitor = Competitor.objects.filter(event=parent, user=self.me).first()

            return competitor is not None
        else:
            return False

    def handle_no_permission(self):
        if self.raise_exception or self.request.user.is_authenticated:
            raise PermissionDenied(self.get_permission_denied_message())
        else:
            if not self.request.user.is_authenticated:
                user = auth.get_user(self.request)
                raise PermissionDenied(
                    _("Your login has timed out.  Try logging in again. "));
            else:
                    return redirect('no-access')

class CheckEventPermissionsMixin(UserPassesTestMixin):
    '''user must be logged in and check this user has permission for this event
    '''
    event = None
    event_group = None
    me = None
    my_roles = []
    current_mode = None

    role_required = "__any__"

    def test_func(self):

        if not self.request.user.is_authenticated:
            logger.info("Non-autheticated user requested access ")
            return False


        if not self.event:
            try:
                self.event = get_event(self.request, self.kwargs)
            except Exception as e:
                return False
            else:
                self.event_group = self.event.event_group


        self.me = self.request.user
        self.my_roles_list = [item.role_type for item in self.event.user_event_roles(self.me)]

        if settings.SUPERUSER_EVENT_ACCESS and self.me.is_superuser:
            # don't think this is a good idea!
            #self.my_roles_list = [role for role, description in ModelRoles.EVENT_ROLES.items()]

            self.my_roles_list = [ModelRoles.ROLE_ADMINISTRATOR, ModelRoles.ROLE_MANAGER, ModelRoles.ROLE_ORGANISER]
        if self.me.is_administrator:
            self.my_roles_list = [ ModelRoles.ROLE_MANAGER, ModelRoles.ROLE_ORGANISER]
        #TODO: allow manager to access if they created, though they should have organiser by default

        my_roles = self.my_roles_list

        if not my_roles:
            my_roles = [ModelRoles.ROLE_COMPETITOR,]

        if not type(self.role_required) == type([]):
            self.role_required = [self.role_required,]

        # check if user has ANY of the roles required
        result = False

        result = set(self.role_required).intersection(set(self.my_roles_list))
        # for role in self.role_required:
        #     result = result or user_role_check(self.request, self.event, self.role_required)



        if not bool(result):

            logger.info("User %s requested access but does not have role(s) %s - has roles %s" % (self.me, self.role_required, self.my_roles_list))

        return bool(result)

    def handle_no_permission(self):
        if self.raise_exception or self.request.user.is_authenticated:
            raise PermissionDenied(self.get_permission_denied_message())
        else:
            if not self.request.user.is_authenticated:
                user = auth.get_user(self.request)
                raise PermissionDenied(
                    _("Your login has timed out.  Try logging in again. "));
            else:
                    return redirect('no-access')


# for django view
class UserCanOrganiseEventMixin(CheckEventPermissionsMixin):

    role_required = ModelRoles.ROLE_ORGANISER

    def test_func(self):
            result = super().test_func()

            # can_enter also checks event is open for entries
            return result or (self.event and self.event.can_organise(self.request.user))

# for django view



class UserCanJudgeEventMixin(CheckEventPermissionsMixin):

    role_required = [ModelRoles.ROLE_JUDGE, ModelRoles.ROLE_AUXJUDGE]

class UserCanOrganiseOrJudgeEventMixin(CheckEventPermissionsMixin):

    role_required = [ModelRoles.ROLE_ORGANISER,ModelRoles.ROLE_JUDGE, ModelRoles.ROLE_AUXJUDGE]

class UserCanOrganiseOrCompetitorEventMixin(CheckEventPermissionsMixin):

    role_required = [ModelRoles.ROLE_ORGANISER,ModelRoles.ROLE_COMPETITOR]

# for django view
class UserCanScoreEventMixin(CheckEventPermissionsMixin):

    role_required = [ModelRoles.ROLE_ORGANISER, ModelRoles.ROLE_SCORER]

# for django view
class UserCanWriteEventMixin(CheckEventPermissionsMixin):

    role_required = ModelRoles.ROLE_WRITER

# for django view
class UserCanEnterEventMixin(CheckEventPermissionsMixin):
    # don't use this for API calls - sometimes user is not instantiated and requires logout/login

    def test_func(self):

        if not self.event:
            self.event = get_event(self.request, self.kwargs)

        if not self.request.user.is_authenticated:
            logger.info("Non-autheticated user requested access ")
            return False

        self.me = self.request.user

        print(self.me.is_competitor)

        # can_enter also checks event is open for entries
        return self.event.can_enter(self.me)



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

class UserCanJudgeMixin(HasRoleMixin):

    role_required = ModelRoles.JUDGE_ROLES

class UserCanAdministerOrIssuerMixin(HasRoleMixin):

    role_required = [ModelRoles.ROLE_ADMINISTRATOR, ModelRoles.ROLE_ISSUER]




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
