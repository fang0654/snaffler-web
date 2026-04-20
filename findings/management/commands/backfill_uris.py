from django.core.management.base import BaseCommand

from findings.models import Finding
from findings.plugin_extract import extract_plugin_name
from findings.smb_parse import smb_fields_from_uris
from findings.uri_extract import extract_uris


class Command(BaseCommand):
    help = "Recompute uris / uri_search from finding text for rows that need it."

    def add_arguments(self, parser):
        parser.add_argument(
            "--limit",
            type=int,
            default=None,
            help="Max rows to update (default: all).",
        )

    def handle(self, *args, **options):
        limit = options["limit"]
        qs = Finding.objects.all().order_by("pk")
        if limit:
            qs = qs[:limit]
        n = 0
        for row in qs.iterator(chunk_size=2000):
            uris = extract_uris(row.finding)
            new_search = "\n".join(uris)
            h, sh, cd = smb_fields_from_uris(uris)
            plugin_name = extract_plugin_name(row.finding)
            if (
                row.uris != uris
                or row.uri_search != new_search
                or row.smb_host != h
                or row.smb_share != sh
                or row.smb_cd_path != cd
                or row.plugin_name != plugin_name
            ):
                Finding.objects.filter(pk=row.pk).update(
                    uris=uris,
                    uri_search=new_search,
                    smb_host=h,
                    smb_share=sh,
                    smb_cd_path=cd,
                    plugin_name=plugin_name,
                )
                n += 1
        self.stdout.write(self.style.SUCCESS(f"Updated {n} row(s)."))
