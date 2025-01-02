from django.shortcuts import render, redirect
from django.contrib.auth.hashers import make_password
from core.models import User
from rest_framework.views import APIView
from rest_framework.response import Response
from django.conf import settings
KEYS = getattr(settings, "KEY", None)
import jwt
from rest_framework import status
from django.contrib.auth import get_user_model
User=get_user_model()
from datetime import datetime,timedelta
import time
import requests
from django.core.mail import send_mail
from core.serializer import *
from core.models import *
from django.utils.timezone import now
from django.db.models import Max, Sum ,F
from django.db.models.functions import ExtractMonth
from django.db.models import Func
from collections import defaultdict 
from django.utils.timezone import now,make_aware
from django.db.models.functions import TruncMonth,TruncHour
from django.db.models.functions import Cast, TruncMonth
from django.db.models import Count, DateTimeField


class ProfileApi(APIView):
    def get(self, request):
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'superadmin':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.ExpiredSignatureError:
            return Response({"status": False, "message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"status": False, "message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        data = UserSerial(usr).data
        return Response(
            {"status":True,"message":"User Profile","data":data},status=status.HTTP_200_OK
        )



class ChangeProfile(APIView):
    def post(self,request):
        token = request.META.get('HTTP_AUTHORIZATION')
        data = request.data
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'superadmin':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
       
        except jwt.ExpiredSignatureError:
            return Response({"status": False, "message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"status": False, "message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        serial = UserSerial(usr,data=data,partial=True)
        if serial.is_valid():
            serial.save()
            return Response({"status":True,"message":"Profile update successfully"},status=status.HTTP_200_OK)
        


class ChangePassword(APIView):
    def post(self,request):
        token = request.META.get('HTTP_AUTHORIZATION')
        data = request.data
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'superadmin':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
       
        except jwt.ExpiredSignatureError:
            return Response({"status": False, "message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"status": False, "message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        if data.get("password") == data.get('confirm_password'):
            print(usr)
            usr.password = make_password(data.get('password'))
            usr.save()
            return  Response({'status':True,'message':'password updated successfully'},status=status.HTTP_200_OK)
        else:
            return Response({
                "status":False,'message':"password and confirm password mismatch"
            },
            status=status.HTTP_400_BAD_REQUEST)
        

class GetAllAdmins(APIView):
    def get(self,request):
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email = d.get("email"))
            if d.get('method')!="verified" or usr.role!='superadmin':
                return Response({"status":False,"message":"Unauthorized"},status=status.HTTP_401_UNAUTHORIZED)  
        except:
            return Response({'status': False, 'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        
        user = User.objects.filter(role="admin",verified_at=True)
        serial = UserSerial(user,many=True)
        return Response({"status": True, "message": "All User Data","data": serial.data}, status=status.HTTP_200_OK)
      

class ActiveAdmins(APIView):
    def get(self,request):
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email = d.get("email"))
            if d.get('method')!="verified" or usr.role!='superadmin':
                return Response({"status":False,"message":"Unauthorized"},status=status.HTTP_401_UNAUTHORIZED)  
        except:
            return Response({'status': False, 'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        
        user = User.objects.filter(role="admin",verified_at=True,status='1')
        serial = UserSerial(user,many=True)
        return Response({"status": True, "message": "All User Data","data": serial.data}, status=status.HTTP_200_OK)


class InactiveAdmin(APIView):
    def get(self,request):
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email = d.get("email"))
            if d.get('method')!="verified" or usr.role!='superadmin':
                return Response({"status":False,"message":"Unauthorized"},status=status.HTTP_401_UNAUTHORIZED)  
        except:
            return Response({'status': False, 'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        
        user = User.objects.filter(role="admin",verified_at=True,status='0')
        serial = UserSerial(user,many=True)
        return Response({"status": True, "message": "All User Data","data": serial.data}, status=status.HTTP_200_OK)

    
      
class CreateAdmin(APIView):
    def post(self,request):
        data=request.data
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email = d.get("email"))
            if d.get('method')!="verified" or usr.role!='superadmin':
                return Response({"status":False,"message":"Unauthorized"},status=status.HTTP_401_UNAUTHORIZED)  
        except:
            return Response({'status': False, 'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        password = data.get('password')
        cpassword = data.get('confirm_password')
        username=data.get('username')
        email= data.get('email')
        existing_user = User.objects.filter(username=username).exists()
        existing_email = User.objects.filter(email=email).exists()
        if existing_user and existing_email:
            message = "Both username and email already exist"
        elif existing_user:
            message = "Username already exists"
        elif existing_email:
            message = "Email already exists"
        else:
            message = None
        if message:
            print(message, "--------------------------------------------")
            return Response({"status": False, "message": message}, status=status.HTTP_400_BAD_REQUEST)
        if password==cpassword:      
            User.objects.create(username=username,password=make_password(password),first_name=first_name,email=email,last_name=last_name,verified_at=True,role='admin') 
            payload_ = {'email': email,"method":"verified", 'exp': datetime.utcnow() + timedelta(minutes=5)}
            token = jwt.encode(payload=payload_,
                                   key=KEYS
                                   )   
            # Send email verification
            #send_email_verification(email, token)
            return Response({"status": True, "message": "Verify your email"}, status=status.HTTP_200_OK)
        else:
            return Response({"status": False, "message": "Password and confirm password do not match"}, status=status.HTTP_400_BAD_REQUEST)


FRONTEND_URL = "http://localhost:8000"  

def send_email_verification(email, token):
    verification_url = f"{FRONTEND_URL}/admin/verify-account?token={token}"   
    subject = "Verify your email address"
    message = f"Please click the following link to verify your email: {verification_url}"
    
    # Send email using Django's send_mail function
    send_mail(
        subject,
        message,
        'ats789456123@gmail.com',  # From email, should match EMAIL_HOST_USER
        [email],  # Recipient email
        fail_silently=False,
    )


class UpdateAdmin(APIView):
    def post(self, request):
        token = request.META.get('HTTP_AUTHORIZATION')  
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'superadmin':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
        except:
            return Response({'status': False, 'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)

        user_id = request.data.get('id')  

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        data = request.data
        user = User.objects.get(id=data.get('id'))
        serial = UserSerial(user,data=data,partial=True)
        if serial.is_valid():
            serial.save()
            return Response({"status": True, "message": "User details updated successfully"}, status=status.HTTP_200_OK)
        else:
            return Response({"status":False,"message":serial.errors},status=status.HTTP_400_BAD_REQUEST)
  

class AdminStatus(APIView):
    def post(self, request):
        token = request.META.get('HTTP_AUTHORIZATION')  
        try:
            
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))

            
            if d.get('method') != "verified" or usr.role != 'superadmin':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.ExpiredSignatureError:
            return Response({"status": False, "message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"status": False, "message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        user_id = request.data.get('id')
        

        if user_id is None :
            return Response(
                {"status": False, "message": "User id required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            # Fetch the user by ID
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        # Update the user's status
        if user.status == "1":
            user.status = "0"  
            message = "User disabled successfully"
        else:
            user.status = "1"  
            message = "User enabled successfully"
        user.updated_at = datetime.now()
        user.save()  
        return Response({"status": True, "message": message}, status=status.HTTP_200_OK)


class GetUserDetails(APIView):
    def get(self,request):
        token = request.META.get('HTTP_AUTHORIZATION')  
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'superadmin':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.ExpiredSignatureError:
            return Response({"status": False, "message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"status": False, "message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        data = [{"id":i.child_id.id,"created_by":i.parent_id.username,"username":i.child_id.username,"email":i.child_id.email,"first_name":i.child_id.first_name,"last_name":i.child_id.last_name,"status":i.status,"date":i.date} for i in UserLinked.objects.all()]
        return Response({"status":True,"message":"success","data":data},status=status.HTTP_200_OK)


class ActiveUser(APIView):
    def get(self,request):
        token = request.META.get('HTTP_AUTHORIZATION')  
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'superadmin':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.ExpiredSignatureError:
            return Response({"status": False, "message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"status": False, "message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        data = [{"id":i.child_id.id,"created_by":i.parent_id.username,"username":i.child_id.username,"email":i.child_id.email,"first_name":i.child_id.first_name,"last_name":i.child_id.last_name,"status":i.status,"date":i.date} for i in UserLinked.objects.all() if i.child_id.status=="1"]
        return Response({"status":True,"message":"success","data":data},status=status.HTTP_200_OK)

        
class InactiveUsers(APIView):
    def get(self,request):
        token = request.META.get('HTTP_AUTHORIZATION')  
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'superadmin':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.ExpiredSignatureError:
            return Response({"status": False, "message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"status": False, "message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        data = [{"id":i.child_id.id,"created_by":i.parent_id.username,"username":i.child_id.username,"email":i.child_id.email,"first_name":i.child_id.first_name,"last_name":i.child_id.last_name,"status":i.status,"date":i.date} for i in UserLinked.objects.all() if i.child_id.status=="0"]
        return Response({"status":True,"message":"success","data":data},status=status.HTTP_200_OK)




class CreateMembership(APIView):
    def post(self, request):
        token = request.META.get('HTTP_AUTHORIZATION') 
        try:
            d = jwt.decode(token, key= KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'superadmin':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
            
        except jwt.ExpiredSignatureError:
            return Response({"status": False, "message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"status": False, "message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        if 'created_at' not in request.data:
            request.data['created_at'] = datetime.utcnow().isoformat()  
        if 'updated_at' not in request.data:
            request.data['updated_at'] = datetime.utcnow().isoformat()  

        
        serializer = MembershipsSerial(data=request.data)
        if serializer.is_valid():
            
            serializer.save()
            return Response({"status": True, "message": "Membership created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
        else:
            
            return Response({"status": False, "message": "Invalid data", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)



class UpdateMembership(APIView):
    def post(self, request):
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'superadmin':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.ExpiredSignatureError:
            return Response({"status": False, "message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"status": False, "message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)


        membership_id = request.data.get('id')
        if not membership_id:
            return Response({"status": False, "message": "Membership ID is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            membership = Memberships.objects.get(id=membership_id)
        except Memberships.DoesNotExist:
            return Response({"status": False, "message": "Membership not found"}, status=status.HTTP_404_NOT_FOUND)
        request.data['updated_at'] = datetime.utcnow().isoformat()  
        serializer = MembershipsSerial(membership, data=request.data, partial=True)  
        if serializer.is_valid():
            serializer.save()
            return Response({"status": True, "message": "Membership updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        else:
            return Response({"status": False, "message": "Invalid data", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


class GetAllMemberships(APIView):
    def get(self, request):
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'superadmin':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
        
        except jwt.ExpiredSignatureError:
            return Response({"status": False, "message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"status": False, "message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        memberships = Memberships.objects.all()
        serializer = MembershipsSerial(memberships, many=True)
        return Response({"status": True, "message": "Memberships fetched successfully", "data": serializer.data}, status=status.HTTP_200_OK)


class GetMembershipById(APIView):
    def get(self, request):
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'superadmin':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
        
        except jwt.ExpiredSignatureError:
            return Response({"status": False, "message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"status": False, "message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        id = request.data.get('id')

        try:
            membership = Memberships.objects.get(id=id)
        except Memberships.DoesNotExist:
            return Response({"status": False, "message": "Membership not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = MembershipsSerial(membership)
        return Response({"status": True, "message": "Membership fetched successfully", "data": serializer.data}, status=status.HTTP_200_OK)
    



class UpdateMembershipStatus(APIView):
    def post(self, request):
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'superadmin':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.ExpiredSignatureError:
            return Response({"status": False, "message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"status": False, "message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        id = request.data.get('id')  
        try:
            membership = Memberships.objects.get(id=id)
        except Memberships.DoesNotExist:
            return Response({"status": False, "message": "Membership not found"}, status=status.HTTP_404_NOT_FOUND)
        if membership.status == '1':
            membership.status = "0"
        else:
            membership.status = '1'
        membership.updated_at = datetime.now()
        membership.save()
        return Response({"status": True, "message": "Membership status updated successfully", "data": {"id": membership.id, "status": membership.status}}, status=status.HTTP_200_OK)



class DashCards(APIView):
    def get(self,request):
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'superadmin':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.ExpiredSignatureError:
            return Response({"status": False, "message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"status": False, "message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        

        # users
        total_users = len(User.objects.filter(role='user'))
        active_users = len(User.objects.filter(role='user',status='1'))
        inactive_users = len(User.objects.filter(role='user',status='0'))

        # Admins

        total_admin = len(User.objects.filter(role='admin'))
        active_admin = len(User.objects.filter(role = 'admin',status='1'))
        inactive_admin = len(User.objects.filter(role='admin',status='0'))


        # subscribers

        total_subscribers = len(UserMemberships.objects.exclude(status='0'))
        subs_amount = sum([float(i.amount) for i in UserMemberships.objects.exclude(status='0')])

        # Total Devices

        total_devices = len(UserMeters.objects.all())


        data = {
            "total_users":total_users,
            "active_user":active_users,
            "inactive_users":inactive_users,
            "total_admin":total_admin,
            "active_admin":active_admin,
            "inactive_admin":inactive_admin,
            "total_subs":total_subscribers,
            "subs_amount":subs_amount,
            "total_devices":total_devices
        }

        return Response({"status":True,"message":"Dashboard card data","data":data},status=status.HTTP_200_OK)


