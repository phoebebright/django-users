from django.urls import include, path

from django_users.urls import urlpatterns as django_users_patterns

urlpatterns = [path("users/", include((django_users_patterns, "users")))]
