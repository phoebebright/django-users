import logging
from django.conf import settings
# mixins.py

from django.contrib.auth.mixins import UserPassesTestMixin
from django.shortcuts import redirect

from django.urls import reverse
from django.views.generic import TemplateView
from rest_framework import status
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response

from tools.exceptions import EventPermissionDenied
from tools.permission_mixins import EventAPIMixin
from web.models import Event, EventTeam
from users.models import CustomUser as User

logger = logging.getLogger('django')

def get_next(request, event_ref):
    '''try and pick out next url - next may contain the name of a url or the url itself'''

    url = None

    next = request.POST.get('go_next', None)
    if not next:
        next = request.GET.get('go_next', None)
    if not next:
        next = request.GET.get('next', None)



    # next is a url
    if next and '/' in next:
        url = next
        if 'anchor' in request.GET:
          url += f"#{request.GET['anchor']}"

    # go to next url if specified
    if not url and next:
        try:
            url = reverse(next, args=[event_ref])
        except:
            pass

    # otherwise got to event page appropriate for this users role/mode
    if not url and event_ref:
        url = reverse('event-home', args=[event_ref])


    return url if url else "/"


class GoNextMixin():
    '''used for event views to work out where to go next'''

    def get_success_url(self):
        '''some forms put a url name in 'go_next' - respect this, otherwise go to event home'''
        if hasattr(self, 'event'):
            event = self.event
            if type(event) != type("duck"):
                event = event.ref
        else:
            event = None

        return get_next(self.request, event)

    def get_context_data(self, **kwargs):
        '''some forms put a url name in 'go_next' - respect this, otherwise go to event home'''


        context = super().get_context_data(**kwargs)

        event_ref = None
        if 'event_ref' in kwargs:
            event_ref = kwargs['event_ref']
        elif 'event_ref' in self.kwargs:
            event_ref = self.kwargs['event_ref']
        elif hasattr(self, 'event') and self.event:
            event_ref = self.event.ref
        elif hasattr(self.request, 'event') and self.request.event :
            event_ref = self.request.event.ref

        context['next'] = get_next(self.request, event_ref )
        return context

        # otherwise got to event page appropriate for this users role/mode

        return reverse_lazy('event-home', args=[self.object.ref])



class GoNextTemplateMixin(TemplateView):
    '''used for event views to work out where to go next'''

    def get_context_data(self, **kwargs):
        '''some forms put a url name in 'go_next' - respect this, otherwise go to event home'''
        context = super().get_context_data(**kwargs)

        event_ref = None
        if 'event_ref' in kwargs:
            event_ref = kwargs['event_ref']
        elif 'event_ref' in self.kwargs:
            event_ref = self.kwargs['event_ref']
        elif hasattr(self, 'event') and self.event:
            event_ref = self.event.ref

        context['next'] = get_next(self.request, event_ref )
        return context




class EventUserMixin(EventAPIMixin):
    '''extract event and user and add to class'''
    user = None


    def get(self, request, format=None, **kwargs):

        if not request.user.is_authenticated:
            try:
                self.user = User.objects.get(email=request.query_params['username'])
            except User.DoesNotExist:
                logger.warning(f"In EventUserMixin User {request.query_params['username']} not found")
                raise PermissionDenied(detail=f"Not valid user In EventUserMixin User {request.query_params['username']} not found")
        else:
            self.user = request.user

        if 'event_ref' in request.query_params:
            try:
                self.event = Event.objects.get(ref=request.query_params.get('event_ref'))
            except:
                raise EventPermissionDenied('Invalid event_ref passed')



        return super().get(request, format, **kwargs)

    def create(self, request, *args, **kwargs):

        data = request.data

        if 'roles' in data:
            # is this supposed to be here?
            obj, _ = EventTeam.objects.get_or_create(event = self.event, user_id=data['user'], creator=self.user, roles=data['roles'])

            serializer = self.get_serializer(obj)
            headers = self.get_success_headers(serializer.data)
            return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

        else:
            return super().create(request, *args, **kwargs)



class CheckLoginRedirectMixin:
    """
    Mixin to check if the user is logged in or not, and redirect accordingly.

    Attributes one or the other:
        login_redirect_url: The URL to redirect to if the user is not logged in.
        not_login_redirect_url: The URL to redirect to if the user is already logged in.
    """
    login_redirect_url = None  # Default to LOGIN_URL in settings
    not_login_redirect_url = None  # Redirect for logged-in users

    def dispatch(self, request, *args, **kwargs):
        # If user is not logged in, redirect to login page
        if not request.user.is_authenticated:
            if self.not_login_redirect_url:
                return redirect(self.not_login_redirect_url)

        else:
            if self.login_redirect_url:
                return redirect(self.login_redirect_url)

        # Otherwise, proceed as usual
        return super().dispatch(request, *args, **kwargs)
