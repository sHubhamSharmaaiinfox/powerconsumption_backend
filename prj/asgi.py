"""
ASGI config for prj project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.0/howto/deployment/asgi/
"""

import os
import django
from channels.routing import ProtocolTypeRouter,URLRouter
from channels.auth import AuthMiddlewareStack 
from django.core.asgi import get_asgi_application

from django.urls import path
from .consumer import *

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "prj.settings")

application = ProtocolTypeRouter({ 
  "http": get_asgi_application(), 
  "websocket": AuthMiddlewareStack(
        URLRouter( 
            [
            path("ws/live-data/<str:meter_id>/", GetMeterData.as_asgi()),
            path("ws/card-data/<str:meter_id>/", GetCardsData.as_asgi()),
            path('ws/kw-data/<str:meter_id>/',GetKwData.as_asgi())
            ]
    ))
}) 