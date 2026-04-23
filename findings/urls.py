from django.urls import path

from . import views

app_name = "findings"

urlpatterns = [
    path("", views.home, name="home"),
    path("source/<int:pk>/", views.source_detail, name="source_detail"),
    path(
        "source/<int:pk>/export/valid.json",
        views.export_valid_findings_json,
        name="export_valid_json",
    ),
    path(
        "source/<int:pk>/exclusion-filter/",
        views.create_exclusion_filter,
        name="create_exclusion_filter",
    ),
    path(
        "source/<int:pk>/valid-filter/",
        views.create_valid_filter,
        name="create_valid_filter",
    ),
    path(
        "source/<int:pk>/exclusion-filter/<int:filter_pk>/delete/",
        views.delete_exclusion_filter,
        name="delete_exclusion_filter",
    ),
    path(
        "source/<int:pk>/valid-filter/<int:filter_pk>/delete/",
        views.delete_valid_filter,
        name="delete_valid_filter",
    ),
    path(
        "source/<int:pk>/finding/<int:finding_pk>/is-valid/",
        views.set_finding_is_valid,
        name="set_finding_is_valid",
    ),
    path("credentials/smb/", views.smb_credentials, name="smb_credentials"),
    path("terminal/smb/", views.smb_terminal, name="smb_terminal"),
]
