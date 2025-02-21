from rest_framework import status
from rest_framework.exceptions import APIException, _get_error_details




class UserPermissionDenied(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = "Cannot authenticate with user details provided"

class ChangePasswordException(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "Invalid password - alphanumeric and between 6 and 20 characters"
