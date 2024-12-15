from django.utils.decorators import decorator_from_middleware
from django.utils import timezone
from skorie.common.middleware import RequestLogMiddleware


class RequestLogViewMixin(object):
    """
    Adds RequestLogMiddleware to any Django View by overriding as_view.
    """

    @classmethod
    def as_view(cls, *args, **kwargs):
        view = super(RequestLogViewMixin, cls).as_view(*args, **kwargs)
        view = decorator_from_middleware(RequestLogMiddleware)(view)
        return view

class InjectCreatorUpdatorMixin(object):

    def perform_create(self, serializer):
        serializer.save(creator=self.request.user)


    def perform_update(self, serializer):
        serializer.save(updator=self.request.user, updated=timezone.now())
