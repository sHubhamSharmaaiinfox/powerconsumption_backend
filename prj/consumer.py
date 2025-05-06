from djangochannelsrestframework.generics import GenericAsyncAPIConsumer
from djangochannelsrestframework.mixins import (
    ListModelMixin,  
)
import asyncio
from random import randint,choice,uniform
from datetime import datetime,timedelta
import json
from channels.generic.websocket import AsyncWebsocketConsumer
import threading
import time
from asgiref.sync import sync_to_async,async_to_sync
from django.contrib.auth import get_user_model
from core.models import *
from core.serializer import *
from django.db.models import Max, Sum  
from django.utils.timezone import now,make_aware
from django.db.models.functions import TruncMonth,TruncHour


def sanitize_value(value):
    """Sanitize a value to handle large numbers and None values"""
    try:
        # Convert to float if it's a string
        if isinstance(value, str):
            value = float(value)
            
        # Handle None values
        if value is None:
            return 0
            
        # Check for extremely large values
        if abs(value) > 1e10:
            return 0
            
        # Round to 4 decimal places
        return round(float(value), 4)
    except (ValueError, TypeError):
        return 0

def sanitize_data(data):
    """Recursively sanitize all numeric values in a nested dictionary"""
    if isinstance(data, dict):
        return {k: sanitize_data(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_data(item) for item in data]
    elif isinstance(data, (int, float)) and not isinstance(data, bool):
        return sanitize_value(data)
    else:
        return data


def getdata(meter_id):
    data = UserMeterReadings.objects.filter(meter_id = meter_id)
    data_ = data.last()
    data_ = UserMeterReadingsSerial(data_).data
    return sanitize_data(data_)

def cards(meter_id):
    year = now().year
    meter = UserMeters.objects.get(id=meter_id)
    MeterData = UserMeterReadings.objects.filter(meter_id = meter_id)
    
    # Safely get power values
    powers = [sanitize_value(i.power) for i in MeterData]
    kwh = sum(powers)
    
    # Safely extract and sum apparent power values
    serialized_data = UserMeterReadingsSerial(MeterData, many=True).data
    kvah_values = []
    
    for entry in serialized_data:
        try:
            data = entry.get("data", {})
            apparent_power = data.get("ApparentPower_KVA", {})
            r_val = sanitize_value(apparent_power.get("R"))
            y_val = sanitize_value(apparent_power.get("Y"))
            b_val = sanitize_value(apparent_power.get("B"))
            kvah_values.append(r_val + y_val + b_val)
        except Exception:
            # Skip entries with missing or invalid data
            pass
    
    kvah = sum(kvah_values)
    
    try:
        kvarh = round(abs(((kvah)**2 - (kwh)**2)**(1/2)), 4)
    except:
        kvarh = 0
    
    records = UserMeterReadings.objects.filter(
                meter_id=meter.id,
                datetime__year=year
            ).annotate(month=TruncMonth('datetime')) \
             .values('month') \
             .annotate(total_power=Sum('power')) \
             .order_by('month')
    
    monthly_data = {record["month"].month: sanitize_value(record["total_power"]) for record in records}
    consumption_data = [
                monthly_data.get(month, 0)  
                for month in range(1, 13)  
                ]
    
    data = {
        "kwh": round(kwh, 4),
        "kvah": round(kvah, 4),
        "kvarh": kvarh,
        "chart_data": consumption_data
    }
    
    return data
    

def kwdata(meter_id):
    data = UserMeterReadings.objects.filter(meter_id = meter_id)
    data = data.last()
    data = UserMeterReadingsSerial(data).data
    try:
        active_power = data.get("data", {}).get("ActivePower_K_W", {})
        data = [
            sanitize_value(active_power.get("R")),
            sanitize_value(active_power.get("Y")),
            sanitize_value(active_power.get("B"))
        ]
    except:
        data = []
    
    return data


class GetKwData(AsyncWebsocketConsumer):
    async def connect(self):
        self.meter_id = self.scope['url_route']['kwargs']['meter_id']
        self.group_name = f"meter_{self.meter_id}_kw"
        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )
        await self.accept()
        message={"message":f"Connected to meter {self.meter_id}"}
        await self.send(json.dumps(message))
        self.keep_sending = True
        asyncio.create_task(self.send_live_data())
    async def disconnect(self, close_code):
        self.keep_sending = False
        await self.channel_layer.group_discard(
            self.group_name,
            self.channel_name
        )
    async def send_live_data(self):
        while self.keep_sending:
            data = await sync_to_async(kwdata)(self.meter_id,)
           
            await self.channel_layer.group_send(
                self.group_name,
                {
                    "type": "send_meter_data",
                    "data": data
                }
            )
            await asyncio.sleep(2)
    async def send_meter_data(self, event):
        await self.send(text_data=json.dumps(event["data"]))




class GetCardsData(AsyncWebsocketConsumer):
    async def connect(self):
        self.meter_id = self.scope['url_route']['kwargs']['meter_id']
        self.group_name = f"meter_{self.meter_id}_cards"
        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )
        await self.accept()
        message={"message":f"Connected to meter {self.meter_id}"}
        await self.send(json.dumps(message))
        self.keep_sending = True
        asyncio.create_task(self.send_live_data())
    async def disconnect(self, close_code):
        self.keep_sending = False
        await self.channel_layer.group_discard(
            self.group_name,
            self.channel_name
        )
    async def send_live_data(self):
        while self.keep_sending:
            data = await sync_to_async(cards)(self.meter_id,)
            print(data)
            await self.channel_layer.group_send(
                self.group_name,
                {
                    "type": "send_meter_data",
                    "data": data
                }
            )
            await asyncio.sleep(2)
    async def send_meter_data(self, event):
        await self.send(text_data=json.dumps(event["data"]))



class GetMeterData(AsyncWebsocketConsumer):
    async def connect(self):
        self.meter_id = self.scope['url_route']['kwargs']['meter_id']
        self.group_name = f"meter_{self.meter_id}"
        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )
        await self.accept()
        message={"message":f"Connected to meter {self.meter_id}"}
        await self.send(json.dumps(message))
        self.keep_sending = True
        asyncio.create_task(self.send_live_data())
    async def disconnect(self, close_code):
        self.keep_sending = False
        await self.channel_layer.group_discard(
            self.group_name,
            self.channel_name
        )
    async def send_live_data(self):
        while self.keep_sending:
            data = await sync_to_async(getdata)(self.meter_id,)
            print(data)
            await self.channel_layer.group_send(
                self.group_name,
                {
                    "type": "send_meter_data",
                    "data": data
                }
            )
            await asyncio.sleep(2)
    async def send_meter_data(self, event):
        await self.send(text_data=json.dumps(event["data"]))
