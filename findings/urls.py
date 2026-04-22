from django.urls import path

from . import views

app_name = "findings"

urlpatterns = [
    path("", views.home, name="home"),
    path("source/<int:pk>/", views.source_detail, name="source_detail"),
    path(
        "source/<int:pk>/exclusion-filter/",
        views.create_exclusion_filter,
        name="create_exclusion_filter",
    ),
    path(
        "source/<int:pk>/exclusion-filter/<int:filter_pk>/delete/",
        views.delete_exclusion_filter,
        name="delete_exclusion_filter",
    ),
    path("credentials/smb/", views.smb_credentials, name="smb_credentials"),
    path("terminal/smb/", views.smb_terminal, name="smb_terminal"),
]
