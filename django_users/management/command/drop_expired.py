from django.contrib.auth import get_user_model, apps
from django.core.management import BaseCommand


class Command(BaseCommand):
    help = "Drop expired data related to users."

    def add_arguments(self, parser):
        parser.add_argument("--csv", dest="csv_path", help="Write results to CSV at this path")

    def handle(self, *args, **opts):
        User = get_user_model()
        VerificationCode = apps.get_model('users', 'VerificationCode')


        VerificationCode.objects.expired().delete()
