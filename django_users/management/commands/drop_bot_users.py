from django.apps import apps
from django.contrib.auth import get_user_model
from django.core.management import BaseCommand
from django.db import IntegrityError, transaction

from django_users.utils import looks_like_bot_name


def _get_model(app_label, model_name):
    """Resolve a model, returning None if its app/model isn't installed.

    Lets the command run in projects that don't ship every optional dependency
    (e.g. django-helpdesk) or model.
    """
    try:
        return apps.get_model(app_label, model_name)
    except LookupError:
        return None


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

        # Optional related records that hold a foreign key to the user and would
        # otherwise block its deletion. Resolved defensively so the command works in
        # projects that don't have these models.
        HelpdeskUserSettings = _get_model("helpdesk", "UserSettings")
        Person = _get_model("users", "Person")

        # Delete one at a time so a single user referenced by a protected or
        # database-level foreign key doesn't abort the whole batch. Each delete runs
        # in its own transaction so a failure rolls back cleanly (Postgres aborts the
        # whole transaction on an IntegrityError); skip and warn about those instead.
        # ProtectedError is a subclass of IntegrityError, so this covers both.
        deleted = 0
        skipped = []
        for u in matched:
            try:
                with transaction.atomic():
                    # Capture the linked Person before deleting the user (the
                    # Person.user FK is SET_NULL, so the link is lost afterwards).
                    person_ids = set()
                    if Person is not None:
                        person_ids.update(
                            Person.objects.filter(user=u).values_list("pk", flat=True)
                        )
                        if u.person_id:
                            person_ids.add(u.person_id)

                    if HelpdeskUserSettings is not None:
                        HelpdeskUserSettings.objects.filter(user=u).delete()

                    u.delete()

                    if person_ids:
                        Person.objects.filter(pk__in=person_ids).delete()
                deleted += 1
            except IntegrityError as e:
                skipped.append((u, e))

        self.stdout.write(self.style.SUCCESS(f"Deleted {deleted} user(s)."))
        if skipped:
            self.stdout.write(self.style.WARNING(
                f"Skipped {len(skipped)} user(s) still referenced by other records:"
            ))
            for u, e in skipped:
                self.stdout.write(self.style.WARNING(f"  {u.pk}\t{u.email}\t{e}"))
