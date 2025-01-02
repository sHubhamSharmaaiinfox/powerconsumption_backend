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
    refferal_code  = models.CharField(max_length = 200,default = '')
    refferal_by  = models.CharField(max_length=200,default = '')
    class Meta:
        db_table='users'



class Packages(models.Model):
    name= models.CharField(max_length=250)
    amount = models.CharField(max_length=250)
    plan_period=models.CharField(max_length=100,null=True)
    status=models.CharField(max_length=200,default='1')
    limit = models.CharField(max_length=200)
    updated_at = models.CharField(max_length=200,default=datetime.utcnow())
    created_at = models.CharField(max_length=200,default=datetime.utcnow())
    class Meta:
        db_table='packages'




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
    amount=models.CharField(max_length=250,default=0)
    expire_date = models.CharField(max_length=250,null=True)
    class Meta:
        db_table='usermemberships'



class AdminMembership(models.Model):
    user_id=models.ForeignKey("core.User", db_column='user_id', on_delete=models.CASCADE)
    plan_id=models.ForeignKey("core.Packages", db_column='plan_id', on_delete=models.CASCADE)
    status=models.CharField(max_length=200,default='1')
    date=models.CharField(max_length=200,default=datetime.utcnow())
    amount=models.CharField(max_length=250,default=0)
    expire_date = models.CharField(max_length=250,null=True)
    class Meta:
        db_table='adminmemberships'



class UserMeters(models.Model):
    member_id = models.ForeignKey("core.UserMemberships",db_column='member_id',on_delete=models.CASCADE)
    token = models.TextField(default='')
    name= models.CharField(max_length=250)
    status=models.CharField(max_length=200,default='1')
    location = models.TextField()
    created_at = models.CharField(max_length=200,default=datetime.utcnow())
    class Meta:
        db_table = 'userdevices'


class UserMeterReadings(models.Model):
    user_token=models.CharField(max_length=250,default=0)
    meter_id = models.ForeignKey("core.UserMeters",db_column="meter_id",on_delete=models.CASCADE)
    power= models.CharField(max_length=200)
    datetime = models.DateTimeField(default=datetime.now())
    data = models.JSONField(default=0,null=True)
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
    created_at = models.DateTimeField(default=datetime.now())

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




#Usermembership instance in payment table
class Payment(models.Model):
    user_id=models.ForeignKey("core.User", db_column='user_id', on_delete=models.CASCADE)
    amount= models.CharField(max_length=255, default=100)
    currrency= models.CharField(max_length=255, default=100)
    status=models.CharField(max_length=200,default='1') #0- pending ,1-completed ,2-cancelled
    comment= models.CharField(max_length=255, null=True)
    image= models.TextField(default = "")
    created_at = models.CharField(max_length=255,default=datetime.now())
    class Meta:
        db_table='payment'





class UPIID_data(models.Model):
    Merchant_name=models.CharField(max_length=255,default="")
    upi_id = models.CharField(max_length=255,default="")
    class Meta:
        db_table='upiid_data'           


class Feedback(models.Model):
    user_id=models.ForeignKey("core.User", db_column='user_id', on_delete=models.CASCADE)
    feedback = models.TextField(verbose_name="Feedback")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Submitted At")
    class Meta:
        db_table ="feedback"




class UserLinked(models.Model):
    parent_id=models.ForeignKey("core.User", related_name='%(class)s_parent_id', on_delete=models.CASCADE)
    child_id=models.ForeignKey("core.User",related_name='%(class)s_child_id', on_delete=models.CASCADE)
    date=models.CharField(max_length=100,default=datetime.utcnow())
    status=models.CharField(max_length=100,default='1')
    class Meta:
        db_table='user_linked'
