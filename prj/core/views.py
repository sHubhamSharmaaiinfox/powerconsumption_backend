from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from django.core.mail import send_mail
from rest_framework import status
from django.contrib.auth import authenticate
from django.conf import settings
KEYS = getattr(settings, "KEY", None)
from datetime import datetime,timedelta
from django.contrib.auth.hashers import make_password
from django.contrib.auth import get_user_model
User=get_user_model()
import time
import requests
import jwt
FRONTEND_URL = getattr(settings, "FRONTEND_URL", None)
from .serializer import *
import pandas as pd


class LoginAPIView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        if not email or not password:
            return Response(
                {"error": "Email and password are required."},
                status=status.HTTP_400_BAD_REQUEST
            )
        try:
            usr= User.objects.get(email=email)
        except:
            return Response(
                {"error": "Email not exists"},
                status=status.HTTP_400_BAD_REQUEST
            )
        user = authenticate(username=usr.username, password=password)
        if user is not None:
            payload_ = {'email': user.email,"role":user.role,'exp': datetime.utcnow() + timedelta(days=1),"method":"verified"}
            token = jwt.encode(payload=payload_,
                                   key=KEYS
                                   )
            return Response(
                {'status':True,"message": "Login successful", "token": token, "role":user.role},
                status=status.HTTP_200_OK
            )
        else:
            return Response(
                {"error": "Invalid username or password."},
                status=status.HTTP_401_UNAUTHORIZED
            )


class ForgotPasswordApi(APIView):
    def post(self,request,format=None):
        email = request.data.get('email')
        if not email:
            return Response({"error": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User with this email does not exist."}, status=status.HTTP_400_BAD_REQUEST)
        payload_ = {'email': user.email, 'exp': datetime.utcnow() + timedelta(minutes=5),'method':"change password"}
        token = jwt.encode(payload=payload_,
                                   key=KEYS
                                   )
        url = f"{FRONTEND_URL}/reset-password?token={token}"                           
        return Response({"status":True,"message": "Password reset link sent to your email.",'Url':url}, status=status.HTTP_200_OK)


        
class ResetPassword(APIView):
    def post(self,request,format=None): 
        data = request.data
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        token = request.META.get('HTTP_AUTHORIZATION') 
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            if d.get('method')!="change password":
                return Response({"status":False,"message":"Unauthorized"},status=status.HTTP_401_UNAUTHORIZED)   
        except:
            return Response({'status': False, 'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        print(d.get('email'))
        try:
            usr = User.objects.get(email = d.get("email"))
            print(usr)
        except:
            return Response(
                {"error": "Email not exists"},
                status=status.HTTP_400_BAD_REQUEST
            )
        if usr.verified_at == False:
            return Response(
                {"error": "Email not verified"},
                status=status.HTTP_400_BAD_REQUEST
            )
        if password != confirm_password:
            return Response(
                {"error": "Password and confirm password mismatch"},
                status=status.HTTP_400_BAD_REQUEST
            )
        usr.password = make_password(password)
        usr.save()
        payload_ = {'email': usr.email,"role":usr.role,'exp': datetime.utcnow() + timedelta(days=1),"method":"verified"}
        token = jwt.encode(payload=payload_,
                                   key=KEYS
                                   )
        return Response(
                {'status':True,"message": "Password Reset Sucessfully", "token": token, "role":usr.role},
                status=status.HTTP_200_OK
        )

class UploadData(APIView):
    def get(self,request):
        df = pd.read_csv(r'multiple_readings_per_meter.csv')
        print(df.columns)
        for i in range(len(df)):
            MeterPowerConsumption.objects.create(meter_id=df.loc[i,'Meter_ID'],datetime=df.loc[i,'Timestamp'],power=df.loc[i,'Meter_Consumption'],volt=df.loc[i,'Volt'],Amphere=df.loc[i,'Ampere'])
        return Response(
            {"status":True},
            status= status.HTTP_200_OK
        )

class CreateUserMeter(APIView):
    def get(self,request):
        df = pd.read_csv(r'multiple_readings_per_meter.csv')
        print(df.columns)
        user = User.objects.get(email='shubham.sharma@aiinfox.com')
        member_id = UserMemberships.objects.get(user_id=user.id)
        for i in range(len(df)):
            try:
                meter = UserMeters.objects.get(name= df.loc[i,'Meter_ID'])
            except:
                UserMeters.objects.create(member_id=member_id,name=df.loc[i,'Meter_ID'],location='chd')
        return Response(
            {"status":True},
            status= status.HTTP_200_OK
        )



class CreateUserMeterReadings(APIView):
    def get(self,request):
        df = pd.read_csv(r'multiple_readings_per_meter.csv')
        print(df.columns)
        user = User.objects.get(email='shubham.sharma@aiinfox.com')
        member_id = UserMemberships.objects.get(user_id=user.id)
        for i in range(len(df)):
            meter_id = UserMeters.objects.get(name = df.loc[i,'Meter_ID'])
            UserMeterReadings.objects.create(meter_id=meter_id,power=df.loc[i,'Meter_Consumption'],Amphere=df.loc[i,'Ampere'],volt=df.loc[i,'Volt'],datetime=df.loc[i,'Timestamp'])
        return Response(
            {"status":True},
            status= status.HTTP_200_OK
        )




# class FixTimeAPI(APIView):
#     def get(self,request):
#         data = UserMeterReadings.objects.all()
#         df= pd.read_csv(r"C:\Users\NAVNEET\Downloads\multiple_readings_per_meter (1).csv")
#         time_stamp=df['Timestamp']
#         for i in range(1,len(time_stamp)):
#             ob=UserMeterReadings.objects.get(id=i)
#             datetime_obj = datetime.strptime(time_stamp[i], "%d-%m-%Y %H:%M")
#             ob.datetime=datetime_obj
#             ob.save()
#         return Response({"status":True,"message":"success"},status=status.HTTP_200_OK)


