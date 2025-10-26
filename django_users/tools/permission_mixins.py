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

from django_users.exceptions import NoEventSpecified

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
        if not self.event or not self.event.is_public:
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
                    permission_classes = [IsAuthenticated & (IsOrganiser4EventPermission | IsAdministratorPermission)]
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

        # THIS DIFFERS IN SKORIE1 AND 2?
        if not self.event.is_public and not self.event.is_private and not self.event.can_organise(request.user):
            return self.handle_no_permission()

        return super().dispatch(request, *args, **kwargs)

    def handle_no_permission(self):
        return redirect('no-access')

# for django view
class EventIsPublicOrEventTeamMixin(AccessMixin):
    event = None

    def dispatch(self, request, *args, **kwargs):
        me = request.user

        if not self.event:
            try:
                self.event = get_event(request, kwargs)
            except:
                return self.handle_no_permission()


        if not (self.event.is_public or self.event.has_role4event(request.user, "__any__") or (settings.SUPERUSER_EVENT_ACCESS and me.is_superuser)) :

            # if event is private and this user has it in their MyEvent then they can continue
            if not self.event.is_accessible(me):

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


        if not request.user.is_authenticated or (not self.event.is_public and not self.event.can_organise(self.request.user)):
            return self.handle_no_permission()


        return super().dispatch(request, *args, **kwargs)

    def handle_no_permission(self):

        if  self.event and not self.event.is_public:
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

class CheckEventPermissionsMixin(UserPassesTestMixin):
    '''user must be logged in and check this user has permission for this event
    '''
    event = None
    event_group = None
    me = None
    my_roles = []    # list of objects
    current_mode = None
    my_roles_list = []   # list of role codes

    role_required = "__any__"

    def test_func(self):

        if not self.request.user.is_authenticated:
            logger.info("Non-autheticated user requested access ")
            return False

        self.me = self.request.user

        if not self.event:
            try:
                self.event = get_event(self.request, self.kwargs)
            except Exception as e:
                logger.error(f"Error on get_event - {e}")
                return False
            else:
                if self.event:
                    self.event_group = self.event.event_group

        if self.event:

            # note, this only pulls back active roles where user has accepted role so for now going to allow unaccepted as users like judges are not logging in
            self.my_roles = self.event.user_event_roles(self.me, active=False)
            self.my_roles_list = [item.role_type for item in self.my_roles]
        else:
            # if we don't have an event then we can't check permissions
            logger.info(f"User {self.me} requested access but no event supplied")
            return False
        if settings.SUPERUSER_EVENT_ACCESS and self.me.is_superuser:
            self.my_roles_list = [role for role, description in ModelRoles.EVENT_ROLES.items()]

        if not type(self.role_required) == type([]):
            self.role_required = [self.role_required,]

        # check if user has ANY of the roles required
        result = False


        # list of roles that intersect with the roles required
        required_roles = [role for role in self.my_roles_list if role in self.role_required]



        if not required_roles:
            self.permission_denied_message = f"User {self.me} requested access but does not have role(s){self.role_required} - has roles {self.my_roles_list}"

            logger.info(self.permission_denied_message)
            return False
        else:
            self.set_user_mode(required_roles)

            return True

    def set_user_mode(self, required_roles):
        # if we already have a user mode then don't change it

        self.request.session['user_mode'] = self.request.session.get('user_mode', required_roles[0])
        if not self.request.session['user_mode'] in required_roles:
            self.request.session['user_mode'] = required_roles[0]

        return True

    def handle_no_permission(self):
        if self.raise_exception or self.request.user.is_authenticated:
            raise PermissionDenied(self.get_permission_denied_message())
        else:

            #Redirect to login page if user is not authenticated, otherwise show no access to this event.
            if not self.request.user.is_authenticated:
                return redirect_to_login(self.request.get_full_path(), login_url=settings.LOGIN_URL)
            else:
                logger.warning(f"User {self.me} does not have permission to access event {self.event} page {self.request.get_full_path()}")
                return redirect('no-access')



# for django view
class UserCanOrganiseEventMixin(CheckEventPermissionsMixin):

    role_required = ModelRoles.ROLE_ORGANISER

    def test_func(self):
        result = super().test_func()

        return result or (self.event and self.event.can_organise(self.request.user))
        self.user_mode = first_match
        self.request.session['user_mode'] = ModelRoles.ROLE_ORGANISER
# for django view


class UserCanJudgeEventMixin(CheckEventPermissionsMixin):

    role_required = [ModelRoles.ROLE_JUDGE, ModelRoles.ROLE_AUXJUDGE]

class UserCanOrganiseOrJudgeEventMixin(CheckEventPermissionsMixin):

    role_required = [ModelRoles.ROLE_JUDGE, ModelRoles.ROLE_AUXJUDGE, ModelRoles.ROLE_ORGANISER,]

class UserCanOrganiseOrCompetitorEventMixin(CheckEventPermissionsMixin):

    role_required = [ModelRoles.ROLE_ORGANISER,ModelRoles.ROLE_COMPETITOR]


class UserInEventTeamMixin(CheckEventPermissionsMixin):

    role_required = ModelRoles.EVENT_ROLES_LIST

class UserCanScoreEventMixin(CheckEventPermissionsMixin):

    role_required = [ModelRoles.ROLE_ORGANISER, ModelRoles.ROLE_SCORER, ModelRoles.ROLE_SCORER_BASIC]

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
                for item in competitor:
                    print(f"Competitor {item} {item.pk} for user {self.me} in event {self.event}")

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


#
#
# class UserCanChangeOldEvent(CheckEventPermissionsMixin):
#     '''readonly for current events or this is for riders entering old sheets - they can add events and competitions if the event is in the past and
#     the status is incomplete OR readonly for event team of unpublished events
#     use UserCanChangeOldEventDRF for API'''
#
#     role_required = ModelRoles.ROLE_RIDER
#
#
#     def test_func(self):
#
#         if not self.event:
#             self.event = get_event(self.request, kwargs)
#
#         if self.request.method == "GET":
#             #TODO: check event is viewable
#             return self.request.user.is_authenticated and ( self.event.is_public or
#                                                             self.event.can_organise(self.request.user))
#
#         if not self.request.user.is_authenticated:
#             logger.info("Non-autheticated user requested access ")
#             return False
#
#         self.me = self.request.user
#
#         # special case if creating an event
#         if not self.event and self.request.method == "POST" and (self.role_required == ModelRoles.ROLE_RIDER):
#             return True
#
#         # can only alter event if status is 0
#         if not self.event or self.event.status > self.event.EVENT_STATUS_INCOMPLETE:
#             return False
#
#
#         return True
#
# class UserCanChangeOldEventDRF(permissions.BasePermission):
#     # use this one for API calls
#     message = 'User does not have permissions to add entries to event.'
#
#     def has_permission(self, request, view):
#         self.me = request.user
#         if not self.event:
#             self.event = get_event(request, self.kwargs)
#         return user_can_change_old_event_check(request, self.event)
#
# def user_can_change_old_event_check(request, event):
#
#     if not request.user.is_authenticated:
#         logger.info("Non-autheticated user requested access ")
#         return False
#
#     # can_enter also checks event is open for entries
#     return event.can_enter(request.user)



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
