from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _

from rest_framework import status, viewsets

from rest_framework.response import Response

class SyncUser(viewsets.ModelViewSet):
    '''external client sending info on a new user or with updated info about a user.
    return whether user created or not
    Will be authenticating '''


    http_method_names = ['post', ]

    def get_queryset(self):
        User = get_user_model()
        return User.objects.none()

    def get_serializer_class(self):
        try:
            from users.serializers import UserSyncSerializer  # Dynamically import the serializer
            return UserSyncSerializer
        except ImportError:
            raise NotImplementedError("UserSyncSerializer must be implemented in the project's `users.serializers` module")

    def create(self, request, *args, **kwargs):

        # currently passing in the users access token so if they didn't already exists, we have just updated them
        # removed code that created or updated a user from post data on 20Jun20

        if request.user and not request.user.is_anonymous:
            serializer = self.get_serializer(data=request.data)
            response_data = serializer(request.user).data
        else:

            serializer = self.get_serializer(data=request.data)
            if serializer.is_valid(raise_exception=False):

                # user does not already exist
                if not serializer.obj:
                    self.perform_create(serializer)
                    serializer.message=_("Created user")
                    serializer.obj = serializer.instance
                    status_code = status.HTTP_201_CREATED
                else:
                    # user already exists - so report 200
                    status_code = status.HTTP_200_OK

            else:
                if 'email' in serializer.errors:
                    serializer.message = serializer.errors['email'][0] + ". "
                if 'username' in serializer.errors:
                    serializer.message += serializer.errors['username'][0] + ". "
                serializer.message += _("Bad API request")
                serializer.obj = None
                status_code = status.HTTP_400_BAD_REQUEST

            response_data = serializer.message

        return Response(response_data)
