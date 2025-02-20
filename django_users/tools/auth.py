from django.conf import settings
from rest_framework.authentication import TokenAuthentication

from tb_devices.models import Device

from rest_framework import authentication
from rest_framework import exceptions
from logging import getLogger

from django.contrib.auth import get_user_model
User = get_user_model()

class TinyCloudAuthentication(authentication.BaseAuthentication):

    def authenticate(self, request):
        bearer = request.META.get('HTTP_AUTHORIZATION')

        if not bearer:
            return None

        _,username = bearer.split(" ")

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:

            getLogger('django.auth').error(f"[CUSTOM AUTH] User {username} does not exist  {settings.SITE_URL}")
            raise exceptions.AuthenticationFailed('No such user')

        getLogger('django.auth').debug("[CUSTOM AUTH] User %s found" % username)
        return (user, None)


class DeviceKeyAuthentication(TokenAuthentication):
    '''call from registered device with devicekey in header

        Clients should authenticate by passing the token key in the 'Authorization'
    HTTP header, prepended with the string 'Token '.  For example:

        Authorization: Token 956e252a-513c-48c5-92dd-bfddc364e812
        '''

    def authenticate(self, request):

        keyword = "Device"

        auth = authentication.get_authorization_header(request).split()

        try:
            device = Device.objects.get(key=auth[1].decode("utf-8") )
        except Exception as e:
            raise exceptions.AuthenticationFailed("Invalid authentication key")

        return device.user, device
