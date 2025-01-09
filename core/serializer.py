from rest_framework import serializers
from django.contrib.auth import get_user_model
User=get_user_model()
from .models import *

class UserSerial(serializers.ModelSerializer):
    class Meta:
        model=User
        fields='__all__'


class MembershipsSerial(serializers.ModelSerializer):
    class Meta:
        model=Memberships
        fields='__all__'


class UserMembershipsSerial(serializers.ModelSerializer):
    class Meta:
        model=UserMemberships
        fields='__all__'


class MeterPowerConsumptionSerial(serializers.ModelSerializer):
    class Meta:
        model=MeterPowerConsumption
        fields='__all__'


class TransactionsSerial(serializers.ModelSerializer):
    class Meta:
        model=Transactions
        fields='__all__'

class UserMeterReadingsSerial(serializers.ModelSerializer):
    class Meta:
        model=UserMeterReadings
        fields='__all__'

class EmailSenderSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmailSender
        fields='__all__'

class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = '__all__'



class AlertsSerial(serializers.ModelSerializer):
    class Meta:
        model= Alerts
        fields = '__all__'



class UserMeterSerial(serializers.ModelSerializer):
    class Meta:
        model = UserMeters
        fields = '__all__'


class UPIID_dataSerial(serializers.ModelSerializer):
    class Meta:
        model = UPIID_data
        fields = "__all__"



class UserLinkedSerial(serializers.ModelSerializer):
    class Meta:
        model = UserLinked
        fields = "__all__"


class PackagesSerial(serializers.ModelSerializer):
    class Meta:
        model = Packages
        fields = "__all__"

class AdminMembershipSerial(serializers.ModelSerializer):
    class Meta:
        model = AdminMembership
        fields = "__all__"