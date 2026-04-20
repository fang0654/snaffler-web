from django.urls import path

from . import views

app_name = "findings"

urlpatterns = [
    path("", views.home, name="home"),
    path("source/<int:pk>/", views.source_detail, name="source_detail"),
    path("credentials/smb/", views.smb_credentials, name="smb_credentials"),
    path("terminal/smb/", views.smb_terminal, name="smb_terminal"),
]
