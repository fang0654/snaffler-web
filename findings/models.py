from django.db import models


class Source(models.Model):
    """One imported Snaffler log file."""

    original_name = models.CharField(max_length=512)
    user_prefix = models.TextField()
    imported_at = models.DateTimeField(auto_now_add=True)
    row_count = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["-imported_at"]

    def __str__(self) -> str:
        return f"{self.original_name} ({self.row_count} rows)"


class Finding(models.Model):
    source = models.ForeignKey(
        Source, on_delete=models.CASCADE, related_name="findings"
    )
    occurred_at = models.DateTimeField(db_index=True)
    kind = models.CharField(max_length=64, db_index=True)
    severity = models.CharField(max_length=32, blank=True, db_index=True)
    # From finding text: substring between first '<' and first '|' (Snaffler plugin tag)
    plugin_name = models.CharField(max_length=255, blank=True, default="", db_index=True)
    finding = models.TextField()
    # Parsed URIs (http(s), file://, res://, UNC→file://); uri_search for icontains filters
    uris = models.JSONField(default=list, blank=True)
    uri_search = models.TextField(blank=True, default="")
    # First SMB file:// mapping (from UNC normalization)
    smb_host = models.CharField(max_length=255, blank=True, default="")
    smb_share = models.CharField(max_length=255, blank=True, default="")
    smb_cd_path = models.TextField(blank=True, default="")

    class Meta:
        ordering = ["occurred_at"]
        indexes = [
            models.Index(fields=["source", "occurred_at"]),
            models.Index(fields=["source", "kind"]),
        ]
