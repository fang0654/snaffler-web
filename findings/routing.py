from django.urls import path

from . import consumers

websocket_urlpatterns = [
    path("ws/smb/", consumers.SMBTerminalConsumer.as_asgi()),
]
