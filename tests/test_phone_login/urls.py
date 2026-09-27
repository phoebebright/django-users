from django.urls import include, path

from django_users.views_phone_login import PhoneLoginQRView, PhoneLoginView

users_patterns = ([
    path("qr_login/", PhoneLoginQRView.as_view(), name="qr-login"),
    path("phone/", PhoneLoginView.as_view(), name="phone_login"),
], "users")

urlpatterns = [path("users/", include(users_patterns))]
