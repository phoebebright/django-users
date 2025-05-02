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
from django.contrib.auth import get_user_model

User = get_user_model()

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
        try:
            url = reverse('event-home', args=[event_ref])
        except:
            url = None


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
