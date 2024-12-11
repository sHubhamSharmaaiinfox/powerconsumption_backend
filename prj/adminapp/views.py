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




class CreateUser(APIView):
    def post(self,request):
        data=request.data
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email = d.get("email"))
            if d.get('method')!="verified" or usr.role!='admin':
                return Response({"status":False,"message":"Unauthorized"},status=status.HTTP_401_UNAUTHORIZED)  
        except:
            return Response({'status': False, 'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        
        first_name = data.get('first_name')
        print(data)
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
            
            User.objects.create(username=username,password=make_password(password),first_name=first_name,email=email,last_name=last_name) 

            payload_ = {'email': email,"method":"verified", 'exp': datetime.utcnow() + timedelta(minutes=5)}
            token = jwt.encode(payload=payload_,
                                   key=KEYS
                                   )
            
            # Send email verification
            send_email_verification(email, token)


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





class VerifyAccount(APIView):
    def get(self, request, pk=None):
        token = request.query_params.get('token')  # Get the token from the URL
        
        if not token:
            return Response({"status": False, "message": "Token not provided"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Decode the token
            decoded_token = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            email = decoded_token.get('email')
            
            if email:
                user = User.objects.get(email=email)
                print(user,"user")
                
                
                user.verified_at = True
                user.save()
                
                return Response({"status": True, "message": "Email verified successfully"}, status=status.HTTP_200_OK)
            else:
                return Response({"status": False, "message": "Invalid token or expired token"}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.ExpiredSignatureError:
            return Response({"status": False, "message": "Token has expired"}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.DecodeError:
            return Response({"status": False, "message": "Error decoding token"}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)



class GetAllUser(APIView):
    def get(self,request):
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email = d.get("email"))
            if d.get('method')!="verified" or usr.role!='admin':
                return Response({"status":False,"message":"Unauthorized"},status=status.HTTP_401_UNAUTHORIZED)  
        except:
            return Response({'status': False, 'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        
        user = User.objects.filter(role="user",verified_at=True)
        serial = UserSerial(user,many=True)
        
        return Response({"status": True, "message": "Email verified successfully","data": serial.data}, status=status.HTTP_200_OK)
      

class GetUserID(APIView):
    def get(self, request):  # 'id' is passed as part of the URL
        user_id = request.query_params.get('user_id')  # Get the token from query params
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            # Decode the JWT token
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            # Check if the user is authorized and the role is admin
            if d.get('method') != "verified" or usr.role != 'admin':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
        except:
            return Response({'status': False, 'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        
        try:
            # Fetch the user by 'id' from the URL parameter
            user = User.objects.get(id=user_id)
            # Serialize the user data
            serial = UserSerial(user)  # No need for 'many=True' as you are fetching a single user
            return Response({"status": True, "message": "User data fetched successfully", "data": serial.data}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found or not verified"}, status=status.HTTP_404_NOT_FOUND)



class UpdateUser(APIView):
    def put(self, request):
        token = request.META.get('HTTP_AUTHORIZATION')  
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'admin':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
        except:
            return Response({'status': False, 'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)

        user_id = request.data.get('id')  

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        first_name = request.data.get('first_name')
        last_name = request.data.get('last_name')
        
      
        if first_name:
            user.first_name = first_name
        if last_name:
            user.last_name = last_name


        user.save()
        return Response({"status": True, "message": "User details updated successfully"}, status=status.HTTP_200_OK)


class VerifiedUsers(APIView):
    def get(self, request):
 
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'admin':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.ExpiredSignatureError:
            return Response({"status": False, "message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"status": False, "message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        # Fetch all verified users
        verified_users = User.objects.filter(status="1")

        # Serialize user data
        user_data = [
            {
                "id": user.id,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "verified_at":user.verified_at
            }
            for user in verified_users
        ]

        return Response(
            {"status": True, "message": "Verified users fetched successfully", "data": user_data},
            status=status.HTTP_200_OK,
        )


class UnverifiedUsers(APIView):
    def get(self, request):
        # Extract token from the header
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            # Decode the JWT token
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            
            # Check if the logged-in user is authorized (e.g., admin access)
            if d.get('method') != "verified" or usr.role != 'admin':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.ExpiredSignatureError:
            return Response({"status": False, "message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"status": False, "message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        # Fetch all unverified users
        unverified_users = User.objects.filter(status="0")

        # Serialize user data
        user_data = [
            {
                "id": user.id,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "verified_at":user.verified_at
            }
            for user in unverified_users
        ]

        return Response(
            {"status": True, "message": "Unverified users fetched successfully", "data": user_data},
            status=status.HTTP_200_OK,
        )

class DisableUser(APIView):
    def put(self, request):
        token = request.META.get('HTTP_AUTHORIZATION')  # Extract token from the header
        try:
            # Decode the JWT token
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))

            # Check if the logged-in user is authorized (e.g., admin access)
            if d.get('method') != "verified" or usr.role != 'admin':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.ExpiredSignatureError:
            return Response({"status": False, "message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"status": False, "message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        # Extract `id` and `status` from the request body
        user_id = request.data.get('id')
        status_value = request.data.get('status')

        if user_id is None or status_value is None:
            return Response(
                {"status": False, "message": "Both 'id' and 'status' are required in the request body"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            # Fetch the user by ID
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        # Update the user's status
        if status_value == 1:
            user.status = 1  
            message = "User enabled successfully"
        elif status_value == 0:
            user.status = 0  
            message = "User disabled successfully"
        else:
            return Response(
                {"status": False, "message": "'status' must be 1 (enable) or 0 (disable)"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.save()  # Save the updated status
        return Response({"status": True, "message": message}, status=status.HTTP_200_OK)

# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

class CreateEmailSender(APIView):
    def post(self, request):
        token = request.META.get('HTTP_AUTHORIZATION') 
        try:
            d = jwt.decode(token, key= KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'admin':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
            
        except jwt.ExpiredSignatureError:
            return Response({"status": False, "message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"status": False, "message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        


        required_fields = ['EMAIL_BACKEND', 'EMAIL_HOST', 'EMAIL_PORT', 'EMAIL_HOST_PASSWORD', 'DEFAULT_FROM_EMAIL']
        for field in required_fields:
            if field not in request.data:
                return Response({"status": False, "message": f"{field} is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Create a new EmailSender record using the provided data
        email_config = EmailSender(
            EMAIL_BACKEND=request.data.get('EMAIL_BACKEND'),
            EMAIL_HOST=request.data.get('EMAIL_HOST'),
            EMAIL_PORT=request.data.get('EMAIL_PORT'),
            EMAIL_HOST_PASSWORD=request.data.get('EMAIL_HOST_PASSWORD'),
            DEFAULT_FROM_EMAIL=request.data.get('DEFAULT_FROM_EMAIL')
        )
        
        # Save the new email configuration to the database
        email_config.save()

        return Response({"status": True, "message": "Email configuration created successfully."}, status=status.HTTP_201_CREATED)

    
    
    

class UpdateEmailSender(APIView):
    def put(self, request):
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'admin':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

        except jwt.ExpiredSignatureError:
            return Response({"status": False, "message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"status": False, "message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        

        usermail_id = request.data.get('id')

        # Try to get the existing EmailSender object
        try:
            email_config = EmailSender.objects.get(id=usermail_id)
        except EmailSender.DoesNotExist:
            return Response({"status": False, "message": "Email configuration not found"}, status=status.HTTP_404_NOT_FOUND)

        # Validate and update the data using the serializer
        serializer = EmailSenderSerializer(email_config, data=request.data, partial=False) 

        if serializer.is_valid():
            # Save the updated configuration
            serializer.save()
            return Response({"status": True, "message": "Email configuration updated successfully."}, status=status.HTTP_200_OK)
        else:
            return Response({"status": False, "message": "Invalid data", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)




class GetAllEmails(APIView):
    def get(self, request):
        # Extract the token and validate it
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key= KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'admin':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

        except jwt.ExpiredSignatureError:
            return Response({"status": False, "message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"status": False, "message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        # Retrieve all email configurations from the database
        email_configs = EmailSender.objects.all()

        # Serialize the data
        serializer = EmailSenderSerializer(email_configs, many=True)

        return Response({"status": True, "message": "All email configurations fetched successfully.", "data": serializer.data}, status=status.HTTP_200_OK)


class GetEmailId(APIView):
    def get(self, request):
        # Extract the token and validate it
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'admin':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

        except jwt.ExpiredSignatureError:
            return Response({"status": False, "message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"status": False, "message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

      
        usermail_id = request.data.get('id')
        
        if not usermail_id:
            return Response({"status": False, "message": "ID is required"}, status=status.HTTP_400_BAD_REQUEST)
      
        try:
            email_config = EmailSender.objects.get(id=usermail_id)
        except EmailSender.DoesNotExist:
            return Response({"status": False, "message": "Email configuration not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = EmailSenderSerializer(email_config)

        return Response({"status": True, "message": "Email configuration fetched successfully.", "data": serializer.data}, status=status.HTTP_200_OK)


class UpdateEmailStatus(APIView):
    def put(self, request):
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'admin':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

        except jwt.ExpiredSignatureError:
            return Response({"status": False, "message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"status": False, "message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        mail_id = request.data.get('id')
        is_enabled = request.data.get('status')  
        
        if mail_id is None or is_enabled is None:
            return Response({"status": False, "message": "ID and status are required"}, status=status.HTTP_400_BAD_REQUEST)       
        try:
            email_config = EmailSender.objects.get(id=mail_id)
        except EmailSender.DoesNotExist:
            return Response({"status": False, "message": "Email configuration not found"}, status=status.HTTP_404_NOT_FOUND)

        email_config.status = is_enabled
        email_config.save()

        return Response({"status": True, "message": f"Email configuration {'enabled' if is_enabled else 'disabled'} successfully."}, status=status.HTTP_200_OK)

# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------


class CreateMembership(APIView):
    def post(self, request):
        token = request.META.get('HTTP_AUTHORIZATION') 
        try:
            d = jwt.decode(token, key= KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'admin':
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
    def put(self, request):
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'admin':
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
        
        # Update the membership using the serializer
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
            if d.get('method') != "verified" or usr.role != 'admin':
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
            if d.get('method') != "verified" or usr.role != 'admin':
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
    def put(self, request):
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'admin':
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

        
        new_status = request.data.get('status')
        if new_status is None:
            return Response({"status": False, "message": "Missing 'status' in request"}, status=status.HTTP_400_BAD_REQUEST)
        
        if not isinstance(new_status, bool):
            return Response({"status": False, "message": "'status' must be a boolean value"}, status=status.HTTP_400_BAD_REQUEST)

        membership.status = new_status
        membership.updated_at = datetime.utcnow()
        membership.save()

        return Response({"status": True, "message": "Membership status updated successfully", "data": {"id": membership.id, "status": membership.status}}, status=status.HTTP_200_OK)


class CreatePayment(APIView):
    def post(self, request):
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified":
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.ExpiredSignatureError:
            return Response({"status": False, "message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"status": False, "message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        # Ensure 'status' is set to '0' (pending) by default
        request.data['status'] = '0'

        serializer = PaymentSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"status": True, "message": "Payment created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
        else:
            return Response({"status": False, "message": "Invalid data", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


class GetPaymentsID(APIView):
    def get(self, request):
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified":
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.ExpiredSignatureError:
            return Response({"status": False, "message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"status": False, "message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        user_id = request.data.get('user_id')    
        if user_id:
            payments = Payment.objects.filter(user_id=user_id)
            if not payments.exists():
                return Response(
                    {"status": False, "message": "No payments found for the given user ID"},
                    status=status.HTTP_404_NOT_FOUND,
                )
        else:
            payments = Payment.objects.all()

        serializer = PaymentSerializer(payments, many=True)
        return Response(
            {"status": True, "message": "Payments retrieved successfully", "data": serializer.data},
            status=status.HTTP_200_OK,
        )
    

class GetPayment(APIView):
    def get(self,request):
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email = d.get("email"))
            if d.get('method')!="verified" or usr.role!='admin':
                return Response({"status":False,"message":"Unauthorized"},status=status.HTTP_401_UNAUTHORIZED)  
        except:
            return Response({'status': False, 'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        
        user = Payment.objects.all()
        serial = PaymentSerializer(user,many=True)
        
        return Response({"status": True, "message": "Payments retrieved successfully", "data": serial.data},status=status.HTTP_200_OK)

class UpdatePaymentStatus(APIView):
    def put(self, request):
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'admin':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.ExpiredSignatureError:
            return Response({"status": False, "message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"status": False, "message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        # Get the payment ID and new status from the request
        payment_id = request.data.get('id')
        new_status = request.data.get('status')  # Expected values: '0', '1', or '2'

        if not payment_id:
            return Response({"status": False, "message": "Payment ID is required"}, status=status.HTTP_400_BAD_REQUEST)

        if new_status is None:
            return Response({"status": False, "message": "Missing 'status' in request"}, status=status.HTTP_400_BAD_REQUEST)
        
        if new_status not in ['0', '1', '2']:  # Validate that status is one of the allowed values
            return Response({"status": False, "message": "'status' must be '0', '1', or '2'"}, status=status.HTTP_400_BAD_REQUEST)

        # Find the payment record by ID
        try:
            payment = Payment.objects.get(id=payment_id)
        except Payment.DoesNotExist:
            return Response({"status": False, "message": "Payment not found"}, status=status.HTTP_404_NOT_FOUND)
        
        # Update the payment status
        payment.status = new_status
        payment.save()

        return Response({"status": True, "message": "Payment status updated successfully", "data": {"id": payment.id, "status": payment.status}}, status=status.HTTP_200_OK)


class meterreading(APIView):
    def post(self,request):
        data=request.data
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email = d.get("email"))
            if d.get('method')!="verified" or usr.role!='admin':
                return Response({"status":False,"message":"Unauthorized"},status=status.HTTP_401_UNAUTHORIZED)  
        except:
            return Response({'status': False, 'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        tokenuser=data.get('tokenuser')
        print(tokenuser)
        meterid=data.get('meterid')
        if meterid:
            meterid = UserMeters.objects.get(id=meterid)
            print(meterid)
        power=data.get('power')
        print(power)
        # datetime=data.get('datetime')
        metere_data=data.get('data')
        print(metere_data)
        meter_status=data.get('status')
        print(meter_status)
        userreading=UserMeterReadings.objects.create(user_token=tokenuser,meter_id=meterid,power=power,data=metere_data,status=meter_status)
        print(userreading)
        userreading.save()
        return Response({"status": True, "message": "Meter reading created successfully"}, status=status.HTTP_201_CREATED)
    
class getmeterreading(APIView):
    def get(self,request):
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email = d.get("email"))
            if d.get('method')!="verified" or usr.role!='admin':
                return Response({"status":False,"message":"Unauthorized"},status=status.HTTP_401_UNAUTHORIZED)  
        except:
            return Response({'status': False, 'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        usertoken= '112w123dwqqwdwqwq'
        if usertoken:
            user = UserMeterReadings.objects.filter(user_token=usertoken)
            serial = UserMeterReadingsSerial(user,many=True)
            return Response({"status": True, "message": "Meter reading fetched successfully","data": serial.data}, status=status.HTTP_200_OK)
        else:
            return Response({"status": False, "message": "User token is required"}, status=status.HTTP_400_BAD_REQUEST)
        # user = UserMeterReadings.objects.all()
        # serial = UserMeterReadingsSerial(user,many=True)
        
        # return Response({"status": True, "message": "Meter reading fetched successfully","data": serial.data}, status=status.HTTP_200_OK)
