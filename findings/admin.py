from django.contrib import admin

from .models import ExclusionFilter, Finding, Source, ValidFilter


@admin.register(Source)
class SourceAdmin(admin.ModelAdmin):
    list_display = ("id", "original_name", "row_count", "imported_at")
    search_fields = ("original_name",)


@admin.register(ExclusionFilter)
class ExclusionFilterAdmin(admin.ModelAdmin):
    list_display = ("id", "source", "substring_preview", "created_at")
    list_filter = ("source",)
    search_fields = ("substring",)
    raw_id_fields = ("source",)

    @admin.display(description="Substring")
    def substring_preview(self, obj: ExclusionFilter) -> str:
        s = obj.substring.replace("\n", " ")
        return s[:120] + ("…" if len(s) > 120 else "")


@admin.register(ValidFilter)
class ValidFilterAdmin(admin.ModelAdmin):
    list_display = ("id", "source", "substring_preview", "created_at")
    list_filter = ("source",)
    search_fields = ("substring",)
    raw_id_fields = ("source",)

    @admin.display(description="Substring")
    def substring_preview(self, obj: ValidFilter) -> str:
        s = obj.substring.replace("\n", " ")
        return s[:120] + ("…" if len(s) > 120 else "")


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "source",
        "occurred_at",
        "kind",
        "severity",
        "is_valid",
        "not_valid",
        "plugin_name",
        "smb_host",
        "smb_share",
        "uri_count",
    )
    list_filter = ("kind", "severity", "is_valid", "not_valid")
    search_fields = ("finding", "uri_search")
    raw_id_fields = ("source",)

    @admin.display(description="URIs")
    def uri_count(self, obj: Finding) -> int:
        return len(obj.uris or [])
