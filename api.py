import logging
import random
import string

import requests
from django.conf import settings
from django.contrib.auth.decorators import user_passes_test
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from rest_framework import status, viewsets
from rest_framework.authentication import SessionAuthentication
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_api_key.permissions import HasAPIKey

from tools.auth import DeviceKeyAuthentication
from tools.exceptions import ChangePasswordException
from tools.permissions import IsAdministratorPermission
from users.serializers import EmailExistsSerializer, UserShortSerializer
from .keycloak_tools import get_access_token, search_user_by_email_in_keycloak, set_temporary_password

from .models import CustomUser, Role
from .serializers import UserSerializer

from skorie.common.api import UserProfileUpdate as BaseUserProfileUpdate

logger = logging.getLogger('django')



def is_superuser(user):
    return user.is_superuser

def is_administrator(user):
    return user.is_administrator





class UserViewset(viewsets.ModelViewSet):
    # use this one to retrieve a single user
    permission_classes = (IsAuthenticated, IsAdministratorPermission)
    queryset = CustomUser.objects.all().select_related('person',)
    serializer_class = UserSerializer
    http_method_names = ['get', ]
    filterset_fields = ('email', )


class UserListViewset(viewsets.ReadOnlyModelViewSet):
    '''list of users'''
    permission_classes = (IsAuthenticated, IsAdministratorPermission)
    queryset = CustomUser.objects.all().exclude(is_active=False).select_related('person',)
    serializer_class = UserShortSerializer
    http_method_names = ['get', ]


    def get_queryset(self):
        queryset = self.queryset

        if not settings.DEBUG:
            queryset = queryset.exclude(test=True)

        return queryset






class ChangePassword(APIView):
    """
    Only for use when called with a valid device key
    The device key authentication will set the request.user to the associated user
    """

    authentication_classes = [DeviceKeyAuthentication,]
    permission_classes = []


    def post(self, request):

        new_password = request.data.get('pw', None)

        if not new_password:
            raise ChangePasswordException("Supply new password")

        # check password appears reasonable
        if not new_password.isalnum() or len(new_password) < 6 or len(new_password) > 20:
            raise ChangePasswordException()

        request.user.set_password(new_password)
        request.user.save()

        return Response("OK", status=status.HTTP_200_OK)


@api_view(['POST'])
#TODO: need throttle
def email_exists(request):
    '''check an email exists in the system'''
    response = "N"
    try:
        CustomUser.objects.get(email = request.data['email'])
        response = "Y"
    except CustomUser.DoesNotExist:
        pass

    return Response(response)


class CheckActivation(APIView):
    """
    Check for user activation - if the activ_code value matches the activation code in the invitation return {"status": 'OK'}
    otherwise return {"status": 'Error'}
    """

    authentication_classes = []
    permission_classes = []

    def get(self, request, format=None):

        if not request.user.is_authenticated:
            user = CustomUser.objects.get(email=request.query_params['email'])
        else:
            user = request.user

        if user.activation_code == int(request.GET.get('activ_code', 0)):
            user.activate()
            return Response({"status": 'OK'})
        elif  user.activation_code == int(request.query_params.get('activ_code', 0)):
            user.activate()
            return Response({"status": 'OK'})
        else:
            return Response({"status": 'Error'})



class CheckPin(APIView):
    """
    Check this a valid upload pin and has not already been used
    """

    authentication_classes = []
    permission_classes = [HasAPIKey | IsAuthenticated]


    def post(self, request, format=None):

        if not request.user.is_authenticated:
            user = CustomUser.objects.get(email=request.query_params['email'])
        else:
            user = request.user

        if user.activation_code == int(request.GET.get('activ_code', 0)):
            user.activate()
            return Response({"status": 'OK'})
        elif  user.activation_code == int(request.query_params.get('activ_code', 0)):
            user.activate()
            return Response({"status": 'OK'})
        else:
            return Response({"status": 'Error'})



@api_view(['GET'])
def resend_activation(request):
    '''trigger resend of activation email for email address specified'''

    if not request.user.is_authenticated:
        user = CustomUser.objects.get(email = request.query_params['email'])
    else:
        user = request.user

    user.send_activation()
    return Response("OK")


class UserProfileUpdate(BaseUserProfileUpdate):
    '''update user profile - only the user can update their own profile'''

    serializer_class = UserSerializer



class CheckEmailInKeycloak(APIView):
    '''
    check if an email has already been registered in the keycloak
    '''

    def post(self, request, *args, **kwargs):
        email = request.POST.get('email', None)
        if email:

            users = search_user_by_email_in_keycloak(email, request.user)
            if len(users) > 0:
                return Response(users[0], status=status.HTTP_200_OK)
            else:
                return Response({"status": "N"}, status=status.HTTP_200_OK)
        else:
            return Response({"status": "N"}, status=status.HTTP_400_BAD_REQUEST)

class CheckEmail(viewsets.ReadOnlyModelViewSet):
    '''
    check if an email has already been registered in the users file
    '''

    serializer_class = EmailExistsSerializer
    queryset = CustomUser.objects.none()
    lookup_field = 'email'
    http_method_names = ['post', ]  # using post so we can hide email in request
    filterset_fields = ('email',)

    def get_serializer_class(self):
        detailed = self.request.query_params.get('detail', False)
        if detailed:
            return UserSerializer
        else:
            return EmailExistsSerializer

    def post(self, request, *args, **kwargs):
        email = request.POST.get('email', None)
        # logger.warning(f"CheckEmail used to check {email}")

        # check this is an email
        try:
            validate_email(email)
        except ValidationError as e:
            raise ValidationError("Not an email")

        queryset = CustomUser.objects.filter(email__iexact=email).first()

        serializer = self.get_serializer(queryset)
        return Response(serializer.data)

    def retrieve(self, request, *args, **kwargs):

        return self.list(request, *args, **kwargs)



class SetTemporaryPassword(APIView):

    permission_classes([IsAuthenticated, IsAdministratorPermission])


    def post(self, request, *args, **kwargs):
        user_id = request.data.get('username')  # User ID in Keycloak
        new_password = request.data.get('new_password')  # New temporary password

        if not user_id or not new_password:
            return Response({"error": "user_id and new_password are required."}, status=status.HTTP_400_BAD_REQUEST)

        payload = {
            "type": "password",
            "value": new_password,
            "temporary": True
        }

        status_code = set_temporary_password(user_id, payload, request.user)


        if status_code == 204:
            return Response({"message": "Temporary password set successfully."})

        else:
            return Response({"error": "Failed to set temporary password."}, status=status_code)




@api_view(['PATCH'])
@user_passes_test(is_administrator)
def toggle_role(request, personref):
    '''add or remove role for user'''

    me = request.user
    role = request.data['role']

    role, created = Role.objects.get_or_create(person_id=personref, role_type=role)

    if not created:
        role.delete()
        logger.info(f"User {me} removed role {role}")
    else:
        logger.info(f"User {me} created role {role}")

    return Response({"status": "OK"})
