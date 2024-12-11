from django.db import models
from django.contrib.auth.models import AbstractUser
from datetime import datetime
import uuid
from django.db.models.signals import post_save
from django.dispatch import receiver



class User(AbstractUser):
    email=models.EmailField(unique=True)
    verified_at = models.CharField(max_length=200,default='False')
    role =models.CharField(max_length=200,default='user')
    status = models.CharField(max_length=20, default='1')
    updated_at = models.CharField(max_length=200,default=datetime.utcnow())
    created_at = models.CharField(max_length=200,default=datetime.utcnow())
    remember_token=models.CharField(max_length=200,default='False')
    phone_no=models.CharField(max_length=200,null=True)
    activation_date=models.CharField(max_length=200,default='N/A')
    class Meta:
        db_table='users'



class Memberships(models.Model):
    name= models.CharField(max_length=250)
    amount = models.CharField(max_length=250)
    plan_period=models.CharField(max_length=100,null=True)
    status=models.CharField(max_length=200,default='1')
    limit = models.CharField(max_length=200)
    updated_at = models.CharField(max_length=200,default=datetime.utcnow())
    created_at = models.CharField(max_length=200,default=datetime.utcnow())
    class Meta:
        db_table='memberships'



class UserMemberships(models.Model):
    user_id=models.ForeignKey("core.User", db_column='user_id', on_delete=models.CASCADE)
    plan_id=models.ForeignKey("core.Memberships", db_column='plan_id', on_delete=models.CASCADE)
    status=models.CharField(max_length=200,default='1')
    date=models.CharField(max_length=200,default=datetime.utcnow())
    expire_date = models.CharField(max_length=250,null=True)
    class Meta:
        db_table='usermemberships'


class UserMeters(models.Model):
    member_id = models.ForeignKey("core.UserMemberships",db_column='member_id',on_delete=models.CASCADE)
    name= models.CharField(max_length=250)
    status=models.CharField(max_length=200,default='1')
    location = models.TextField()
    created_at = models.CharField(max_length=200,default=datetime.utcnow())
    class Meta:
        db_table = 'userdevices'



class UserMeterReadings(models.Model):
    user_token=models.CharField(max_length=250)
    meter_id = models.ForeignKey("core.UserMeters",db_column="meter_id",on_delete=models.CASCADE)
    power= models.CharField(max_length=200)
    datetime = models.DateTimeField(default=datetime.now())
    data = models.JSONField()
    # Amphere= models.CharField(max_length=250,default='1')
    # volt = models.CharField(max_length=250,default='1')
    status= models.CharField(max_length=250,default='1')
    class Meta:
        db_table='usermeterreadings'




class Alerts(models.Model):
    meter_id = models.ForeignKey("core.UserMeters",db_column="meter_id",on_delete=models.CASCADE)
    alert_name = models.CharField(max_length=250)
    description = models.TextField()
    status = models.CharField(max_length=200)
    level = models.CharField(max_length=200)

    class Meta:
        db_table = 'alerts'



class MeterPowerConsumption(models.Model):
    meter_id = models.CharField(max_length=250)
    datetime= models.CharField(max_length=250)
    power = models.CharField(max_length=250)
    Amphere= models.CharField(max_length=250,default='1')
    volt = models.CharField(max_length=250,default='1')
    status= models.CharField(max_length=200,default='1')
    class Meta:
        db_table='meterpowerconsumption'





class Transactions(models.Model):
    user_id=models.ForeignKey("core.User", db_column='user_id', on_delete=models.CASCADE)
    date=models.CharField(max_length=200,default=datetime.utcnow())
    status= models.CharField(max_length=200,default='1')
    amount = models.CharField(max_length=250)
    class Meta:
        db_table='transactions'


class EmailSender(models.Model):
    EMAIL_BACKEND = models.CharField(max_length=255)
    EMAIL_HOST = models.CharField(max_length=255)
    EMAIL_PORT = models.CharField(max_length=255)
    status = models.BooleanField(default=False) 
    EMAIL_HOST_PASSWORD = models.CharField(max_length=255)
    DEFAULT_FROM_EMAIL = models.CharField(max_length=255)

    class Meta:
        db_table = 'emailsender'


class WsGroupNames(models.Model):
    name=models.CharField(max_length=100)
    status= models.CharField(max_length=50)
    meterid= models.CharField(max_length=50)
    class Meta:
        db_table = 'wsgroupnames'


class Payment(models.Model):
    user_id=models.ForeignKey("core.User", db_column='user_id', on_delete=models.CASCADE)
    amount= models.CharField(max_length=255, default=100)
    currrency= models.CharField(max_length=255, default=100)
    status=models.CharField(max_length=200,default='1') #0- pending ,1-completed ,2-cancelled
    comment= models.CharField(max_length=255, null=True)
    image= models.CharField(max_length=255, null=True)
    class Meta:
        db_table='payment'