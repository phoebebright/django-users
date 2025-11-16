
from django_users.urls import urlpatterns as django_users_patterns  # import patterns

app_name = "users"  # keep the same namespace if you want reverse('django_users:profile')

'''
note when choose where to put patterns:
Inbound matching (request → view):
Django checks urlpatterns top to bottom. The first pattern that matches the path wins.

Reversing by name (view name → URL with {% url %} / reverse()):
If multiple patterns share the same name, Django’s reverse resolver will let the last one defined “win” (it overwrites earlier entries in the reverse map).
'''
urlpatterns =  django_users_patterns  # append the django_users patterns at the end to avoid name conflicts
