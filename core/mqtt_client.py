import json
import paho.mqtt.client as mqtt


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
    data = json.loads(msg.payload.decode("utf-8"))
    print(data)
    #print(f'{msg.payloaxd.decode()} on topic: {msg.topic}')
    # try:
    #     data = json.loads(msg.payload.decode("utf-8"))
    #     print(data)
    # except Exception as e:
    #     print(f"Error processing MQTT message: {e}")


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
