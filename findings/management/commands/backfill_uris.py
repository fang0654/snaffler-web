from django.core.management.base import BaseCommand

from findings.backfill import backfill_uris


class Command(BaseCommand):
    help = "Recompute uris / uri_search from finding text for rows that need it."

    def add_arguments(self, parser):
        parser.add_argument(
            "--limit",
            type=int,
            default=None,
            help="Max rows to process (default: all).",
        )

    def handle(self, *args, **options):
        n = backfill_uris(limit=options["limit"])
        self.stdout.write(self.style.SUCCESS(f"Updated {n} row(s)."))
