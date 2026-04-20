from django.contrib import admin

from .models import Finding, Source


@admin.register(Source)
class SourceAdmin(admin.ModelAdmin):
    list_display = ("id", "original_name", "row_count", "imported_at")
    search_fields = ("original_name",)


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "source",
        "occurred_at",
        "kind",
        "severity",
        "plugin_name",
        "smb_host",
        "smb_share",
        "uri_count",
    )
    list_filter = ("kind", "severity")
    search_fields = ("finding", "uri_search")
    raw_id_fields = ("source",)

    @admin.display(description="URIs")
    def uri_count(self, obj: Finding) -> int:
        return len(obj.uris or [])
