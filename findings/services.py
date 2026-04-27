from __future__ import annotations

from django.db import transaction

from .models import Finding, Source
from .plugin_extract import extract_plugin_name
from .smb_parse import smb_fields_from_uris
from .uri_extract import extract_uris
from .parsers import (
    detect_tsv_user_prefix,
    detect_user_prefix,
    is_tsv_snaffler_head,
    iter_rows,
    iter_tsv_rows,
    iter_text_lines,
    parse_dt,
    read_head_lines,
)


BATCH_SIZE = 5000


def import_snaffler_upload(uploaded_file) -> Source:
    """
    Parse an uploaded Snaffler log and persist rows in a transaction.
    `uploaded_file` is a Django UploadedFile.

    Supports the usual space-separated log and TSV; see the module docstring on
    ``findings.parsers`` for the tab-separated column order (computer, datetime,
    type, Severity, plugin, R, then three often-empty fields, then the rest).
    """
    raw = uploaded_file.file
    if hasattr(raw, "seek"):
        raw.seek(0)

    head = read_head_lines(raw, 5000)
    if is_tsv_snaffler_head(head):
        prefix = detect_tsv_user_prefix(head)
        row_iter = iter_tsv_rows
    else:
        prefix = detect_user_prefix(head)
        row_iter = iter_rows
    if not prefix:
        raise ValueError("Could not detect Snaffler user prefix from file.")

    raw.seek(0)
    name = getattr(uploaded_file, "name", "upload.txt") or "upload.txt"
    name = name[:512]

    with transaction.atomic():
        source = Source.objects.create(
            original_name=name,
            user_prefix=prefix,
            row_count=0,
        )
        batch: list[Finding] = []
        total = 0
        for row in row_iter(iter_text_lines(raw), prefix):
            uris = extract_uris(row.finding)
            smb_host, smb_share, smb_cd_path = smb_fields_from_uris(uris)
            plugin_name = extract_plugin_name(row.finding)
            batch.append(
                Finding(
                    source=source,
                    occurred_at=parse_dt(row.dt),
                    kind=row.kind,
                    severity=row.severity,
                    plugin_name=plugin_name,
                    finding=row.finding,
                    uris=uris,
                    uri_search="\n".join(uris),
                    smb_host=smb_host,
                    smb_share=smb_share,
                    smb_cd_path=smb_cd_path,
                )
            )
            if len(batch) >= BATCH_SIZE:
                Finding.objects.bulk_create(batch)
                total += len(batch)
                batch = []
        if batch:
            Finding.objects.bulk_create(batch)
            total += len(batch)
        source.row_count = total
        source.save(update_fields=["row_count"])

    return source
