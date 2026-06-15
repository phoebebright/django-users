import csv

from django.apps import apps
from django.core.management import BaseCommand


class Command(BaseCommand):
    help = (
        "Drop expired verification codes. Dry-run by default; pass --delete to "
        "actually remove them."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--delete",
            action="store_true",
            help="Actually delete the expired codes. Without this flag the command only reports.",
        )
        parser.add_argument(
            "--csv",
            dest="csv_path",
            help="Write the expired codes to a CSV at this path before deleting.",
        )

    def handle(self, *args, **opts):
        VerificationCode = apps.get_model('users', 'VerificationCode')

        expired = VerificationCode.objects.expired()
        count = expired.count()

        if not count:
            self.stdout.write(self.style.SUCCESS("No expired verification codes found."))
            return

        self.stdout.write(f"Found {count} expired verification code(s).")

        if opts.get("csv_path"):
            with open(opts["csv_path"], "w", newline="") as fh:
                writer = csv.writer(fh)
                writer.writerow(["id", "user", "channel", "purpose", "created_at", "expires_at"])
                for vc in expired.iterator():
                    writer.writerow([
                        vc.pk, vc.user_id, vc.channel_id, vc.purpose, vc.created_at, vc.expires_at,
                    ])
            self.stdout.write(self.style.SUCCESS(f"Wrote {count} row(s) to {opts['csv_path']}"))

        if not opts.get("delete"):
            self.stdout.write(
                self.style.WARNING("Dry run — nothing deleted. Re-run with --delete to remove them.")
            )
            return

        deleted, _ = expired.delete()
        self.stdout.write(self.style.SUCCESS(f"Deleted {count} expired code(s) ({deleted} object(s) total)."))
