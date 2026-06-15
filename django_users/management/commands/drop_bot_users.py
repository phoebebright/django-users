from django.contrib.auth import get_user_model
from django.core.management import BaseCommand
from django.db.models import ProtectedError

from django_users.utils import looks_like_bot_name


class Command(BaseCommand):
    help = (
        "Find and delete users whose first_name/last_name look machine-generated "
        "(UUID/hex blobs), i.e. bot registrations. Dry-run by default; pass "
        "--delete to actually remove them."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--delete",
            action="store_true",
            help="Actually delete the matched users. Without this flag the command only reports.",
        )

    def handle(self, *args, **opts):
        User = get_user_model()

        matched = [
            u
            for u in User.objects.only("pk", "email", "first_name", "last_name").iterator()
            if looks_like_bot_name(u.first_name, u.last_name)
        ]

        if not matched:
            self.stdout.write(self.style.SUCCESS("No bot-like users found."))
            return

        self.stdout.write(f"Found {len(matched)} bot-like user(s):")
        for u in matched:
            self.stdout.write(f"  {u.pk}\t{u.email}\t{u.first_name!r} {u.last_name!r}")

        if not opts.get("delete"):
            self.stdout.write(
                self.style.WARNING("Dry run — no users deleted. Re-run with --delete to remove them.")
            )
            return

        # Delete one at a time so a single user referenced by protected foreign keys
        # doesn't abort the whole batch — skip and warn about those instead.
        deleted = 0
        skipped = []
        for u in matched:
            try:
                u.delete()
                deleted += 1
            except ProtectedError as e:
                skipped.append((u, e))

        self.stdout.write(self.style.SUCCESS(f"Deleted {deleted} user(s)."))
        if skipped:
            self.stdout.write(self.style.WARNING(
                f"Skipped {len(skipped)} user(s) referenced by protected foreign keys:"
            ))
            for u, e in skipped:
                self.stdout.write(self.style.WARNING(f"  {u.pk}\t{u.email}\t{e}"))
