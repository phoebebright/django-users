import logging
import random
import string
from venv import create

import requests
from django.conf import settings
from django.contrib.auth.decorators import user_passes_test
from django.contrib.auth import get_user_model
from django.core.checks import messages
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import transaction
from django.http import JsonResponse
from django.urls import reverse_lazy, reverse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from rest_framework import status, viewsets
from rest_framework.authentication import SessionAuthentication
from rest_framework.decorators import api_view, permission_classes, authentication_classes, action
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView
from rest_framework_api_key.permissions import HasAPIKey


from .tools.auth import DeviceKeyAuthentication
from .tools.exceptions import ChangePasswordException
from .tools.permission_mixins import UserCanAdministerMixin, IsAdministrator
from .tools.permissions import IsAdministratorPermission
from .keycloak import get_access_token, search_user_by_email_in_keycloak, set_temporary_password, \
    verify_user_without_email

from .views import send_sms, set_current_user
from rest_framework.throttling import SimpleRateThrottle

logger = logging.getLogger('django')


class CustomAnonRateThrottle(AnonRateThrottle):
    rate = '5/minute'


def is_administrator(user):
    return user.is_administrator


class CommsChannelRateThrottle(SimpleRateThrottle):
    scope = 'comms_channel'

    def get_cache_key(self, request, view):
        # Use user ID for authenticated requests, or IP address for anonymous
        if request.user.is_authenticated:
            return f"throttle_{self.scope}_{request.user.id}"
        return self.get_ident(request)

    def allow_request(self, request, view):
        # Check if the request is allowed by the throttle
        is_allowed = super().allow_request(request, view)

        if not is_allowed:
            # Log the throttle event
            user = request.user if request.user.is_authenticated else "Anonymous"
            ip_address = self.get_ident(request)
            path = request.path
            logger.warning(f"Throttle limit exceeded for {user} (IP: {ip_address}) on path: {path}")

            # Add a message to inform the user
            messages.add_message(request, messages.WARNING,
                                 "You have exceeded the request limit. Please try again in a minute.")

        return is_allowed


class UserViewsetBase(viewsets.ModelViewSet):
    # use this one to retrieve a single user
    permission_classes = (IsAuthenticated, IsAdministratorPermission)
    # queryset = CustomUser.objects.all().select_related('person','preferred_channel')
    # serializer_class = UserSerializer
    http_method_names = ['get', ]
    filterset_fields = ('email',)

    def get_queryset(self):
        if not hasattr(self, 'queryset') or self.queryset is None:
            raise NotImplementedError("Define `queryset` in the child class.")
        return self.queryset

    def get_serializer_class(self):
        if not hasattr(self, 'serializer_class') or self.serializer_class is None:
            raise NotImplementedError("Define `serializer_class` in the child class.")
        return self.serializer_class


class UserListViewsetBase(viewsets.ReadOnlyModelViewSet):
    '''list of users'''
    permission_classes = (IsAuthenticated, IsAdministratorPermission)
    # queryset = CustomUser.objects.all().exclude(is_active=False).select_related('person',)
    # serializer_class = UserShortSerializer
    http_method_names = ['get', ]

    def get_queryset(self):
        queryset = self.queryset

        if not settings.DEBUG:
            queryset = queryset.exclude(test=True)

        return queryset

    def get_serializer_class(self):
        if not hasattr(self, 'serializer_class') or self.serializer_class is None:
            raise NotImplementedError("Define `serializer_class` in the child class.")
        return self.serializer_class


class ChangePassword(APIView):
    """
    Only for use when called with a valid device key
    The device key authentication will set the request.user to the associated user
    """

    authentication_classes = [DeviceKeyAuthentication, ]
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
# TODO: need throttle
def email_exists(request):
    '''check an email exists in the system'''
    response = "N"
    User = get_user_model()
    try:
        User.objects.get(email=request.data['email'])
        response = "Y"
    except User.DoesNotExist:
        pass

    return Response(response)


class CheckActivationBase(APIView):
    """
    Check for user activation - if the activ_code value matches the activation code in the invitation return {"status": 'OK'}
    otherwise return {"status": 'Error'}
    """

    authentication_classes = []
    permission_classes = []

    def get(self, request, format=None):
        User = get_user_model()
        if not request.user.is_authenticated:
            user = User.objects.get(email=request.query_params['email'])
        else:
            user = request.user

        if user.activation_code == int(request.GET.get('activ_code', 0)):
            user.activate()
            return Response({"status": 'OK'})
        elif user.activation_code == int(request.query_params.get('activ_code', 0)):
            user.activate()
            return Response({"status": 'OK'})
        else:
            return Response({"status": 'Error'})


class CheckPinBase(APIView):
    """
    Check this a valid upload pin and has not already been used
    """

    authentication_classes = []
    permission_classes = [HasAPIKey | IsAuthenticated]

    def post(self, request, format=None):
        User = get_user_model()
        if not request.user.is_authenticated:
            user = User.objects.get(email=request.query_params['email'])
        else:
            user = request.user

        if user.activation_code == int(request.GET.get('activ_code', 0)):
            user.activate()
            return Response({"status": 'OK'})
        elif user.activation_code == int(request.query_params.get('activ_code', 0)):
            user.activate()
            return Response({"status": 'OK'})
        else:
            return Response({"status": 'Error'})


@api_view(['GET'])
def resend_activation(request):
    '''trigger resend of activation email for email address specified'''
    User = get_user_model()
    if not request.user.is_authenticated:
        user = User.objects.get(email=request.query_params['email'])
    else:
        user = request.user

    user.send_activation()
    return Response("OK")


class UserProfileUpdateBase(APIView):
    '''update user profile - only the user can update their own profile'''

    authentication_classes = (SessionAuthentication,)

    def get_serializer_class(self):
        if not hasattr(self, 'serializer_class') or self.serializer_class is None:
            raise NotImplementedError("Define `serializer_class` in the child class.")
        return self.serializer_class

    def patch(self, request, username):

        User = get_user_model()
        user = User.objects.get(username=username)


        # can only edit your own
        if user != request.user:
            raise PermissionDenied()

        # remove username and id
        serializer = self.get_serializer_class(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()

            return Response(serializer.data, status=status.HTTP_206_PARTIAL_CONTENT)

        return Response(status=status.HTTP_400_BAD_REQUEST)


class CheckEmailInKeycloak(UserCanAdministerMixin, APIView):
    '''
    check if an email has already been registered in the keycloak
    '''

    def post(self, request, *args, **kwargs):
        email = request.POST.get('email', None)
        if email:

            user = search_user_by_email_in_keycloak(email, request.user)
            if user:
                return Response(user, status=status.HTTP_200_OK)
            else:
                return Response({"status": "N"}, status=status.HTTP_200_OK)
        else:
            return Response({"status": "N"}, status=status.HTTP_400_BAD_REQUEST)


class SendVerificationPinPublic(APIView):
    '''request keycloak send verification email and wait from response'''
    authentication_classes = []
    permission_classes = []
    throttle_classes = [CustomAnonRateThrottle]

    def post(self, request, *args, **kwargs):
        user_id = request.POST.get('user_id', None)
        phone_no = request.POST.get('phone_no', None)
        pin = ''.join(random.choices(string.digits, k=6))

        if user_id and phone_no:

            try:
                send_sms(user_id, phone_no, pin, request.user)
            except Exception as e:
                return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            else:
                return Response({'pin': pin}, status=status.HTTP_200_OK)

        else:
            return Response(status=status.HTTP_404_NOT_FOUND)


#
# class VerifyUserWithSMS(APIView):
#     '''set keycloak account as verified even though email is not verified'''
#     authentication_classes = []
#     permission_classes = []
#     throttle_classes = [CustomAnonRateThrottle]
#
#     def post(self, request, *args, **kwargs):
#         user_id = request.POST.get('user_id', None)
#         phone_no = request.POST.get('phone_no', None)
#
#         # activate in keycloak
#         verify_user_without_email(user_id)
#
#         # add phone and status
#         return Response({'status': 'success'}, status=200)


class SendVerificationCode(APIView):
    '''set keycloak account as verified even though email is not verified'''
    authentication_classes = []
    permission_classes = []
    throttle_classes = [CustomAnonRateThrottle]

    def post(self, request, *args, **kwargs):
        User = get_user_model()
        VerificationCode = apps.get_model('users', 'VerificationCode')
        user_id = request.session.get('user_id')
        user = User.objects.get(id=user_id)
        channel = user.comms_channels.get(pk=request.POST.get('channel_pk'))
        if channel:
            vc = VerificationCode.create_verification_code(channel)
            success = vc.send_verification_code()

        if success:
            return Response({'status': 'success'}, status=200)
        else:
            return Response({'status': 'error'}, status=500)


class CheckEmailInKeycloakPublic(APIView):
    '''
    check if an email has already been registered in the keycloak
    '''
    authentication_classes = []
    permission_classes = []
    throttle_classes = [CustomAnonRateThrottle]

    def post(self, request, *args, **kwargs):
        User = get_user_model()
        create_in_django = True  # for now we are defaulting to creating the django user if the keycloak one is created
        email = request.POST.get('email', None)
        if email:
            channels = []

            # get user in django
            try:
                # username will be set by keycloak so use email as key
                django_user = User.objects.get(email=email)
            except User.DoesNotExist:
                django_user = None
            else:
                set_current_user(request, django_user.id, "PROBLEM")
                channels = []

                # migrate existing channels
                django_user.migrate_channels()

                for item in django_user.comms_channels.all():
                    channels.append(
                        {'channel_id': item.pk, 'channel_type': item.channel_type, 'email': item.obfuscated_email,
                         'mobile': item.obfuscated_mobile, 'verified': item.is_verified})

                # django_user = django_user.keycloak_id

            keycloak_user = search_user_by_email_in_keycloak(email, request.user)

            # make sure we can link users
            if django_user and keycloak_user and not django_user.keycloak_id == keycloak_user['id']:
                django_user.keycloak_id = keycloak_user['id']
                django_user.save(update_fields=['keycloak_id', ])

            elif not django_user and keycloak_user and create_in_django:
                # remove this code when all users transitioned to new signup system as should not apply

                with transaction.atomic():
                    # create user in django
                    django_user = User.objects.create_user(email=email, username=email,
                                                                 first_name=keycloak_user['firstName'],
                                                                 last_name=keycloak_user['lastName'],
                                                                 )
                    django_user.keycloak_id = keycloak_user['id']
                    django_user.save(update_fields=['keycloak_id', ])

                    for item in django_user.comms_channels.all():
                        channels.append(
                            {'channel_id': item.pk, 'channel_type': item.channel_type, 'email': item.obfuscated_email,
                             'mobile': item.obfuscated_mobile, 'verified': item.is_verified})

                set_current_user(request, django_user.id, "REGISTER")

            if keycloak_user:
                data = {
                    "keycloak_user_id": keycloak_user['id'],
                    "keycloak_created": keycloak_user['createdTimestamp'],
                    "keycloak_enabled": keycloak_user['enabled'],
                    "keycloak_actions": keycloak_user['requiredActions'],
                    "keycloak_verified": keycloak_user['emailVerified'],
                    "django_user_keycloak_id": django_user.keycloak_id if django_user else 0,
                    "django_user_id": django_user.pk if django_user else 0,
                    "django_is_active": django_user.is_active,
                    "channels": channels,
                }

                return JsonResponse(data)
            else:
                return JsonResponse({
                    "keycloak_user_id": '',
                    "django_user_keycloak_id": django_user.keycloak_id if django_user else 0,
                    "django_user_id": django_user.pk if django_user else 0,
                    "channels": channels,
                })

        else:
            return Response(status=status.HTTP_404_NOT_FOUND)


class CheckEmailBase(viewsets.ReadOnlyModelViewSet):
    '''
    check if an email has already been registered in the users file
    '''

    # serializer_class = EmailExistsSerializer
    # queryset = CustomUser.objects.none()
    lookup_field = 'email'
    http_method_names = ['post', ]  # using post so we can hide email in request
    filterset_fields = ('email',)

    def get_queryset(self):
        User = get_user_model()
        return User.objects.none()

    def get_serializer_class(self):
        if not hasattr(self, 'serializer_class') or self.serializer_class is None:
            raise NotImplementedError("Define `serializer_class` in the child class.")
        return self.serializer_class

    def post(self, request, *args, **kwargs):
        User = get_user_model()
        email = request.POST.get('email', None)
        # logger.warning(f"CheckEmail used to check {email}")

        # check this is an email
        try:
            validate_email(email)
        except ValidationError as e:
            raise ValidationError("Not an email")

        queryset = User.objects.filter(email__iexact=email).first()

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


class CommsChannelViewSetBase(viewsets.ModelViewSet):
    authentication_classes = []
    permission_classes = []
    # queryset = CommsChannel.objects.none()
    # serializer_class = CommsChannelSerializer
    http_method_names = ['patch', 'delete', 'post', 'get']

    # throttle_classes = [CommsChannelRateThrottle]

    def get_serializer_context(self):
        # Add user to the context for the serializer
        context = super().get_serializer_context()
        context['user'] = self.request.user

        return context

    def get_serializer_class(self):
        if not hasattr(self, 'serializer_class') or self.serializer_class is None:
            raise NotImplementedError("Define `serializer_class` in the child class.")
        return self.serializer_class

    def get_queryset(self):
        return self.request.user.comms_channels.all()

    def get_object(self):
        return self.get_queryset().get(pk=self.kwargs['pk'])

    def partial_update(self, request, *args, **kwargs):
        instance = self.get_object()

        preferred_channel_id = instance

        # Fetch the user's comms channels and set the preferred one
        comms_channels = request.user.comms_channels.all()
        comms_channels.update(is_preferred=False)  # Unset all as preferred
        comms_channels.filter(id=preferred_channel_id).update(is_preferred=True)  # Set selected as preferred

        return Response("OK")

    def create(self, request, *args, **kwargs):
        '''create a new comms channel for the user'''
        CommsChannel = apps.get_model('users','CommsChannel')
        username_code = request.POST.get('username_code', None)
        if username_code:
            User = get_user_model()
            try:
                user = User.objects.get(password=username_code)
            except User.DoesNotExist:
                raise PermissionDenied
        else:
            user = request.user

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # check we don't already have this one
        channel_type = serializer.validated_data['channel_type']
        email = serializer.validated_data['email']
        mobile = serializer.validated_data['mobile']

        created = False

        if channel_type == "email":
            channel, created = CommsChannel.objects.get_or_create(user=user, channel_type=channel_type, email=email)
        else:
            channel, created = CommsChannel.objects.get_or_create(user=user, channel_type=channel_type, mobile=mobile)

        if not created:
            # if channel exists but is unverified then continue to verificiation step else return error
            # if channel.is_verified:
            #     return Response({'errors': 'exists'}, status=400)
            # let's continue and let it be reverified rather than adding to the confusion
            pass

        back = request.POST.get('back', '')

        # could be adding channels from various points to trying to pass through where to go once verifieid
        return Response({'next': reverse('users:verify_channel', args=[channel.pk]) + '?next=' + back},
                        status=status.HTTP_200_OK)

    @action(methods=['post'], detail=True, permission_classes=[IsAdministrator])
    def manually_verify(self, request, pk):
        '''manually verify a channel'''
        CommsChannel = apps.get_model('users', 'CommsChannel')
        channel = CommsChannel.objects.get(pk=pk)
        channel.verified_at = timezone.now()
        channel.note = request.POST.get("note", "")
        channel.verified_by = request.user
        channel.save()

        return Response("OK")


class OrganisationViewSetBase(viewsets.ReadOnlyModelViewSet):
    '''When filtering on country we include Organisations that have no country (ie. worldwide)'''

    # serializer_class = OrganisationSerializer
    filterset_fields = ('default_authority',)

    def get_serializer_class(self):
        if not hasattr(self, 'serializer_class') or self.serializer_class is None:
            raise NotImplementedError("Define `serializer_class` in the child class.")
        return self.serializer_class

    def get_queryset(self):
        Organisation = apps.get_model('users', 'Organisation')
        queryset = Organisation.objects.filter(active=True)

        if not settings.DEBUG:
            queryset = queryset.exclude(test=True)

        # ignore default_authority=0
        if self.request.query_params.get('default_authority', None) and self.request.query_params.get(
                'default_authority') == '0':
            # remove from filter
            del self.request.query_params['default_authority']

        country = self.request.query_params.get('country', None)
        if country:
            queryset = queryset.filter(country__in=[country, None])

        return queryset


@api_view(['PATCH'])
@user_passes_test(is_administrator)
def toggle_role(request, personref):
    '''add or remove role for user'''

    me = request.user
    role = request.data['role']
    Role = apps.get_model('users', 'Role')
    role, created = Role.objects.get_or_create(person_id=personref, role_type=role)

    if not created:
        role.active = not role.active
        role.save()

    return Response({"status": "OK"})
