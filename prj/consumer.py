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




def getdata(meter_id):
    data = UserMeterReadings.objects.filter(meter_id = meter_id)
    data_ = data.last()
    data_ = UserMeterReadingsSerial(data_).data
    return data_

def cards(meter_id):
    year = now().year
    meter = UserMeters.objects.get(id=meter_id)
    MeterData = UserMeterReadings.objects.filter(meter_id = meter_id)
    kwh = sum([float(i.power) for i in MeterData])
    kvah = sum([(float(i.get("data").get("ApparentPower_KVA").get("R"))+float(i.get("data").get("ApparentPower_KVA").get("Y"))+float(i.get("data").get("ApparentPower_KVA").get("B"))) for i in UserMeterReadingsSerial(MeterData,many=True).data])
    try:
        kvarh = round(abs(((kvah)**2 - (kwh)**2)**(1/2)),3)
    except:
        kvarh = 0
    records = UserMeterReadings.objects.filter(
                meter_id=meter.id,
                datetime__year=year
            ).annotate(month=TruncMonth('datetime')) \
             .values('month') \
             .annotate(total_power=Sum('power')) \
             .order_by('month')
    monthly_data = {record["month"].month: record["total_power"] for record in records}
    consumption_data = [
                monthly_data.get(month, 0)  
                for month in range(1, 13)  
                ]
    data = {
        "kwh":kwh,
        "kvah":kvah,
        "kvarh":kvarh,
        "chart_data":consumption_data
    }
    return data
    


def kwdata(meter_id):
    data = UserMeterReadings.objects.filter(meter_id = meter_id)
    data = data.last()
    data = UserMeterReadingsSerial(data).data
    try:
            
        data = [data.get("data").get("ActivePower_K_W").get("R"),data.get("data").get("ActivePower_K_W").get("Y"),data.get("data").get("ActivePower_K_W").get("B")]
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
