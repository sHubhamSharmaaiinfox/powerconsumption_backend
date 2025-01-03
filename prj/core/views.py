import base64
import os
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
from django.core.mail import EmailMessage



def convert_image_to_base64(image_path):
    """Convert image to base64 string."""
    image_path = os.path.join(settings.BASE_DIR, 'static', 'images', image_path)
    with open(image_path, "rb") as image_file:
        encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
    return f"data:image/png;base64,{encoded_string}"


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
    def generate_email_template(self, username,reset_url):
        """Generate the HTML email template."""
        base64_email_image = convert_image_to_base64('enerygy.png')
        return f"""
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Password Reset</title>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.7.2/css/all.min.css" 
                integrity="sha512-Evv84Mr4kqVGRNSgIGL/F/aIDqQb7xQ2vcrdIwxfjThSH8CSR7PBEakCr51Ck+w+/U6swU2Im1vVX0SVk9ABhg==" 
                crossorigin="anonymous" referrerpolicy="no-referrer" />
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" 
                integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" 
                crossorigin="anonymous">
        </head>
        <body>
            <section style="display: flex; justify-content: center; align-items: center; height: 100vh;">
                <div class="container" style="box-shadow: rgba(99, 99, 99, 0.2) 0px 2px 8px 0px; padding: 25px; border-radius: 5px;">
                    <div class="col-lg-12 d-flex justify-content-center align-items-center flex-column  main-con-top">
                    <div class="col-lg-12 d-flex justify-content-center align-items-center flex-column  main-con-bottom">
                        <img src="{base64_email_image}" class="img-fluid" alt="Email" style="margin-top: 10px; margin-bottom:20px; width:20%;">
                        <h1 style="font-family: poppins;">Hi {username}!</h1>
                        <p style="padding-top: 10px; margin-bottom: 0px; font-family: poppins;">Password Reset</p>
                        <span style="padding-top: 10px; font-family: poppins; width: 60%; text-align: center; font-size: 14px;">
                            Please create a strong and secure password for your account to complete the setup process. A strong password includes a mix of uppercase, lowercase, numbers, and special characters.
                        </span>
                        <a href="{reset_url}" style="margin-top: 20px; padding: 10px 20px; border: none; border-radius: 4px; background: #2D4AF1; color: white; font-family: Poppins, sans-serif; text-decoration: none; transition: box-shadow 0.5s ease-in-out;" 
                            onmouseover="this.style.boxShadow='rgba(0, 0, 0, 0.25) 0px 54px 55px, rgba(0, 0, 0, 0.12) 0px -12px 30px, rgba(0, 0, 0, 0.12) 0px 4px 6px, rgba(0, 0, 0, 0.17) 0px 12px 13px, rgba(0, 0, 0, 0.09) 0px -3px 5px';" 
                            onmouseout="this.style.boxShadow='none';">
                            <i class="fa-regular fa-circle-check"></i> Reset Password
                        </a>
                        <span style="padding-top: 10px; font-family: poppins; width: 60%; text-align: center; font-size: 14px;">
                            2025 - EMS. All Rights Reserved
                        </span>
                    </div>
                </div>
            </section>
        </body>
        </html>
        """
    
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
        
        subject = "Password Reset Request"
        url = f"{FRONTEND_URL}/reset-password?token={token}" 
        message = self.generate_email_template(user.username,url)

        
        email_message=EmailMessage(subject, message,settings.EMAIL_HOST_USER, to=[email])
        email_message.content_subtype = "html"
        email_message.send()
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



class UserMeterDataCreation(APIView):
    def post(self,request):
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            meter = UserMeters.objects.get(id=d.get("meter_id"))
        except jwt.ExpiredSignatureError:
            return Response({"status": False, "message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        data = request.data
        data['meter_id']= d.get('meter_id')
        serial = UserMeterReadingsSerial(data=data)
        if serial.is_valid():
            serial.save()
            return Response({'status':True,'message':'record created successfully'},status=status.HTTP_201_CREATED)
        else:
            return Response({'status':False,'message':serial.errors},status=status.HTTP_200_OK)