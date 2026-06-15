import csv

from django.contrib.auth import get_user_model
from django.core.management import BaseCommand

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
        parser.add_argument(
            "--csv",
            dest="csv_path",
            help="Write the matched users to a CSV at this path before deleting.",
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

        if opts.get("csv_path"):
            with open(opts["csv_path"], "w", newline="") as fh:
                writer = csv.writer(fh)
                writer.writerow(["id", "email", "first_name", "last_name"])
                for u in matched:
                    writer.writerow([u.pk, u.email, u.first_name, u.last_name])
            self.stdout.write(self.style.SUCCESS(f"Wrote {len(matched)} row(s) to {opts['csv_path']}"))

        if not opts.get("delete"):
            self.stdout.write(
                self.style.WARNING("Dry run — no users deleted. Re-run with --delete to remove them.")
            )
            return

        deleted, _ = User.objects.filter(pk__in=[u.pk for u in matched]).delete()
        self.stdout.write(self.style.SUCCESS(f"Deleted {len(matched)} user(s) ({deleted} object(s) total)."))
