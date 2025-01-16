import json
import paho.mqtt.client as mqtt
from django.conf import settings
KEYS = getattr(settings, "KEY", None)
import jwt
from .serializer import *
from .models import *


MQTT_BROKER = "13.127.126.37"  
MQTT_PORT = 1883         
MQTT_TOPIC = "test/topic"

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Connected to MQTT broker")
        client.subscribe(MQTT_TOPIC)  
    else:
        print(f"Failed to connect, return code {rc}")


def on_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload.decode("utf-8"))
        print(data)
        token = data.get("token")
        power = data.get("power")
        data_ = data.get('data')
        d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
        meter_id = UserMeters.objects.get(id=d.get('meter_id'))
        UserMeterReadings.objects.create(user_token=token,power=power,meter_id=meter_id,data=data_)
        print("created successfully")   
    except Exception as e:
        print(f"Error processing MQTT message: {e}")


def start_mqtt():
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    try:
        print("connecting mqttserver")
        client.connect(MQTT_BROKER, MQTT_PORT, 60)
        print("MQTT client started")
        client.loop_start()  
    except Exception as e:
        print(f"Error connecting to MQTT broker: {e}")
