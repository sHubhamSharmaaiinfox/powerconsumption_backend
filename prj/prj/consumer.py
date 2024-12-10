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


class GetMeterData(AsyncWebsocketConsumer):
    async def connect(self):
        self.group_name = str(datetime.now().timestamp())
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()
        message={"message":"connected"}
        print("Connected")
        await self.send(json.dumps(message))

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data):
        #getting here all the meter data
        pass
    