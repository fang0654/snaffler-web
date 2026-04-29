from __future__ import annotations

from .models import Finding
from .plugin_extract import extract_plugin_name
from .smb_parse import smb_fields_from_uris
from .uri_extract import extract_uris


def backfill_uris(*, limit: int | None = None) -> int:
    """
    Recompute ``uris``, ``uri_search``, SMB fields, and ``plugin_name`` from finding text.

    Returns the number of rows updated.
    """
    qs = Finding.objects.all().order_by("pk")
    cnt = qs.count()
    if limit is not None:
        qs = qs[:limit]
    n = 0

    for row in qs:
        uris = extract_uris(row.finding)
        # new_search = "\n".join(uris)
        # h, sh, cd = smb_fields_from_uris(uris)
        # plugin_name = extract_plugin_name(row.finding)
        # if (
        #     row.uris != uris
        #     or row.uri_search != new_search
        #     or row.smb_host != h
        #     or row.smb_share != sh
        #     or row.smb_cd_path != cd
        #     or row.plugin_name != plugin_name
        # ):
        Finding.objects.filter(pk=row.pk).update(
            uris=uris,
            # uri_search=new_search,
            # smb_host=h,
            # smb_share=sh,
            # smb_cd_path=cd,
            # plugin_name=plugin_name,
        )
        n += 1
        print(f"{n}/{cnt}")
    return n
