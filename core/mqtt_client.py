import json
import paho.mqtt.client as mqtt
from django.conf import settings
KEYS = getattr(settings, "KEY", None)
import jwt
from .serializer import *
from .models import *
import time
from datetime import datetime


token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtZXRlcl9pZCI6MSwiZXhwIjoxNzc3OTc1MTAzfQ.SLn6l6iIqVuz2TqGNRR7gxmjMQgU3sKmd4lR0F0QLFg"

#MQTT_BROKER = "13.127.126.37"  
MQTT_BROKER = "13.233.103.147"
MQTT_PORT = 1883         
MQTT_TOPIC = "#"
MQTT_USERNAME = "mqttuser"
MQTT_PASSWORD = "admin"

# Register address to parameter mapping based on manual
register_map = {
    # Total RMS block (page 59)
    "3909": ("Voltage_P_P", "R_N", lambda x: x), # VLL (avg, used for all phases)
    "3911": ("Voltage_P_N", "R_N", lambda x: x), # VLN (avg, used for all phases)
    "3913": ("Current", "R", lambda x: x),      # A (avg, used for all phases)
    "3915": ("Frequency", "R", lambda x: x),    # F (used for all phases)
    "3903": ("ActivePower_K_W", "R", lambda x: x / 1000), # W (total, scaled to kW)
    "3901": ("ApparentPower_KVA", "R", lambda x: x / 1000), # VA (total, scaled to kVA)
    "3907": ("PowerFactor", "R", lambda x: x * 100), # PF (scaled to percentage)
    # R Phase RMS block (page 59)
    "3001": ("Voltage_P_P", "R_N", lambda x: x), # V12
    "3003": ("Voltage_P_P", "Y_N", lambda x: x), # V23
    "3005": ("Voltage_P_P", "B_N", lambda x: x), # V31
    "3007": ("Voltage_P_N", "R_N", lambda x: x), # V1
    "3009": ("Voltage_P_N", "Y_N", lambda x: x), # V2
    "3011": ("Voltage_P_N", "B_N", lambda x: x), # V3
    "3013": ("Current", "R", lambda x: x),       # A1
    "3015": ("Current", "Y", lambda x: x),       # A2
    "3017": ("Current", "B", lambda x: x),       # A3
    "3025": ("ActivePower_K_W", "R", lambda x: x / 1000), # W1
    "3027": ("ActivePower_K_W", "Y", lambda x: x / 1000), # W2
    "3029": ("ActivePower_K_W", "B", lambda x: x / 1000), # W3
    "3031": ("ApparentPower_KVA", "R", lambda x: x / 1000), # VA1
    "3033": ("ApparentPower_KVA", "Y", lambda x: x / 1000), # VA2
    "3035": ("ApparentPower_KVA", "B", lambda x: x / 1000), # VA3
    "3043": ("PowerFactor", "R", lambda x: x * 100), # PF1
    "3045": ("PowerFactor", "Y", lambda x: x * 100), # PF2
    "3047": ("PowerFactor", "B", lambda x: x * 100), # PF3
    # Phase Angle block (page 64)
    "3061": ("PhaseAngle", "R", lambda x: x), # A°1
    "3063": ("PhaseAngle", "Y", lambda x: x), # A°2
    "3065": ("PhaseAngle", "B", lambda x: x), # A°3
    # Forward Integrated block (page 61)
    "3201": ("TotalActivePower_KWH", "KWH", lambda x: x / 1000), # Wh
    "3203": ("TotalApparentPower_KVA", "KVAH", lambda x: x / 1000), # VAh
    # Hypothetical THD registers (not in standard EM6400, for demonstration)
    "3501": ("THD_Voltage", "R", lambda x: x),
    "3503": ("THD_Voltage", "Y", lambda x: x),
    "3505": ("THD_Voltage", "B", lambda x: x),
    "3507": ("THD_Current", "R", lambda x: x),
    "3509": ("THD_Current", "Y", lambda x: x),
    "3511": ("THD_Current", "B", lambda x: x),
    # Add any missing registers that you receive from your device
    "3019": ("TotalActivePower_KWH", "KWH", lambda x: x / 1000),  # Additional register if present in your data
}

# Class to handle Modbus data collection and conversion
class ModbusDataCollector:
    def __init__(self):
        self.collected_data = []
        self.last_save_time = datetime.now()
        self.save_interval = 60  # Save data every 60 seconds
    
    def add_data(self, data):
        """Add Modbus data entry to collection"""
        if isinstance(data, dict) and 'Type' in data and data.get('Type') == 'MR':
            self.collected_data.append(data)
            
            # Check if it's time to process the data
            current_time = datetime.now()
            elapsed_seconds = (current_time - self.last_save_time).total_seconds()
            
            # Process data if we have collected enough entries or enough time has passed
            if len(self.collected_data) >= 20 or elapsed_seconds >= self.save_interval:
                result = self.process_data()
                self.collected_data = []  # Reset collection
                self.last_save_time = current_time
                return result
        return None
    
    def process_data(self):
        """Process collected Modbus data into desired output format"""
        # Initialize the output JSON structure
        output = {
            "power": 0.0,  # Will be calculated from ActivePower_K_W
            "data": {
                "Voltage_P_N": {"R_N": 0, "Y_N": 0, "B_N": 0},
                "Voltage_P_P": {"R_N": 0, "Y_N": 0, "B_N": 0},
                "Current": {"R": 0, "Y": 0, "B": 0},
                "Frequency": {"R": 0, "Y": 0, "B": 0},
                "ActivePower_K_W": {"R": 0, "Y": 0, "B": 0},
                "ApparentPower_KVA": {"R": 0, "Y": 0, "B": 0},
                "PowerFactor": {"R": 0, "Y": 0, "B": 0},
                "TotalActivePower_KWH": {"KWH": 0},
                "TotalApparentPower_KVA": {"KVAH": 0},
                "PhaseAngle": {"R": 0, "Y": 0, "B": 0},
                "THD_Voltage": {"R": 0, "Y": 0, "B": 0},
                "THD_Current": {"R": 0, "Y": 0, "B": 0}
            }
        }

        # Process each Modbus register entry
        for entry in self.collected_data:
            reg_ad = entry.get("RegAd")
            try:
                value = float(entry.get("D1", "0"))
                # Skip extremely large negative values
                if value < -1e30:
                    continue
                    
                if reg_ad in register_map:
                    param, sub_param, transform = register_map[reg_ad]
                    # Filter out extremely large values (positive or negative)
                    transformed_value = transform(value)
                    if abs(transformed_value) > 1e10:
                        transformed_value = 0
                        
                    if param == "ActivePower_K_W" and sub_param == "R" and output["power"] == 0.0:
                        # Use total active power for the top-level power value
                        output["power"] = transformed_value
                    
                    # For all other parameters, store in the data structure
                    output["data"][param][sub_param] = transformed_value
            except ValueError as e:
                print(f"Invalid value for register {reg_ad}: {entry.get('D1')}, error: {e}")
            except Exception as e:
                print(f"Error processing register {reg_ad}: {e}")

        # For parameters where average values were used, replicate across phases if needed
        for param in ["Voltage_P_N", "Voltage_P_P", "Current", "Frequency", "ActivePower_K_W", "ApparentPower_KVA", "PowerFactor"]:
            first_key = "R_N" if param in ["Voltage_P_N", "Voltage_P_P"] else "R"
            if first_key in output["data"][param] and output["data"][param][first_key] is not None:
                for phase in ["Y_N" if param in ["Voltage_P_N", "Voltage_P_P"] else "Y", 
                              "B_N" if param in ["Voltage_P_N", "Voltage_P_P"] else "B"]:
                    if phase in output["data"][param] and output["data"][param][phase] is None:
                        output["data"][param][phase] = output["data"][param][first_key]

        # Sum up the phase active powers for the total active power if not already set
        if output["power"] == 0.0 and all(val is not None for val in output["data"]["ActivePower_K_W"].values()):
            output["power"] = sum(output["data"]["ActivePower_K_W"].values())

        # Replace any remaining null values with 0
        self.replace_null_with_zero(output)
        
        return output
    
    def replace_null_with_zero(self, data):
        """Replace all null values with 0 in the data dictionary"""
        if isinstance(data, dict):
            for key, value in data.items():
                if value is None:
                    data[key] = 0
                elif isinstance(value, dict):
                    self.replace_null_with_zero(value)
                elif isinstance(value, list):
                    for i, item in enumerate(value):
                        if item is None:
                            value[i] = 0
                        elif isinstance(item, (dict, list)):
                            self.replace_null_with_zero(item)

# Create a global instance of the data collector
modbus_collector = ModbusDataCollector()

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Connected to MQTT Broker!")
        client.subscribe(MQTT_TOPIC)  # Subscribe to all topics
    else:
        print(f"Failed to connect, return code {rc}")


def on_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload.decode("utf-8"))
        print(data, msg.topic)
        
        # Check if this is a Modbus data format
        if isinstance(data, dict) and 'Type' in data and data.get('Type') == 'MR':
            # Add data to collector
            processed_data = modbus_collector.add_data(data)
            
            if processed_data:
                # Now we have a complete set of processed data
                token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtZXRlcl9pZCI6MSwiZXhwIjoxNzc3OTc1MTAzfQ.SLn6l6iIqVuz2TqGNRR7gxmjMQgU3sKmd4lR0F0QLFg"
                power = processed_data.get("power")
                data_ = processed_data.get('data')
                
                # Database operations
                d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
                meter_id = UserMeters.objects.get(id=d.get('meter_id'))
                UserMeterReadings.objects.create(user_token=token, power=power, meter_id=meter_id, data=data_)
                

                
                
                print("Processed Modbus data successfully")
                print("Output:", json.dumps(processed_data, indent=4))
                
                # Optionally save to file for debugging
                try:
                    with open("power_meter_data.json", "w") as f:
                        json.dump(processed_data, f, indent=4)
                except Exception as file_error:
                    print(f"Error saving to file: {file_error}")
            
            print("created successfully")
        else:
            # Handle the original JSON format
            #token = data.get("token")
            token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtZXRlcl9pZCI6MSwiZXhwIjoxNzc3OTc1MTAzfQ.SLn6l6iIqVuz2TqGNRR7gxmjMQgU3sKmd4lR0F0QLFg"
            power = data.get("power")
            data_ = data.get('data')
            #time.sleep(1)
            #d = jwt.decode(token, key=KEYS, algorithms=['HS256'])

            #meter_id = UserMeters.objects.get(id=d.get('meter_id'))
            #UserMeterReadings.objects.create(user_token=token,power=power,meter_id=meter_id,data=data_)
            print("created successfully")
            
    except Exception as e:
        import traceback
        print(f"Error processing MQTT message: {e}")
        print(traceback.format_exc())  # Print stack trace for debugging


def start_mqtt():
    client = mqtt.Client()
    client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
    client.on_connect = on_connect
    client.on_message = on_message
    try:
        print("connecting mqttserver")
        client.connect(MQTT_BROKER, MQTT_PORT, 60)
        print("MQTT client started")
        client.loop_start()  
    except Exception as e:
        print(f"Error connecting to MQTT broker: {e}")
