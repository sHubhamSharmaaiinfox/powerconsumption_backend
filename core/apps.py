from django.apps import AppConfig


class CoreConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "core"
    def ready(self):
        from .mqtt_client import start_mqtt
        start_mqtt()