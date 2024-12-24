from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from core.models import *
from rest_framework import status
from django.conf import settings
KEYS = getattr(settings, "KEY", None)
import jwt
import json
from django.db.models import Sum, Q
from django.db.models.functions import Cast
from datetime import datetime,timedelta
from math import isfinite
from core.serializer import *
from django.db.models import Max, Sum  
from django.utils.timezone import now,make_aware
from django.db.models.functions import TruncMonth,TruncHour
from django.contrib.auth.hashers import make_password



def parse_power(value):
    try:
        return float(value)
    except ValueError:
        return 0.0


class MetersData(APIView):
    def get(self,request):
        token = request.META.get('HTTP_AUTHORIZATION') 
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email = d.get("email"))
            if d.get('method')!="verified" or usr.role!='user':
                return Response({"status":False,"message":"Unauthorized"},status=status.HTTP_401_UNAUTHORIZED)  
        except:
            return Response({'status': False, 'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        members_id = [i.id for i in UserMemberships.objects.filter(user_id=usr.id)]
        meter_id = [i.id for i in UserMeters.objects.filter(member_id__in = members_id)]
        meter_readings =  UserMeterReadings.objects.filter(meter_id__in=meter_id)
        overall_consumption = sum([float(i.power) for i in meter_readings])
        max_power_row = UserMeterReadings.objects.filter(meter_id__in=meter_id).order_by('-power').first().power
        current_date = now().date()
        current_month = now().month
        current_year = now().year
        today_records = UserMeterReadings.objects.filter(datetime__startswith=current_date,meter_id__in=meter_id)
        
        # Query this month's records
        month_records = UserMeterReadings.objects.filter(datetime__year=current_year, datetime__month=current_month,meter_id__in=meter_id)

        # 1. Today's Power Consumed
        todays_power_consumed = sum(parse_power(record.power) for record in today_records)


        # 2. This Month's Power Consumed    
        monthly_power_consumed = sum(parse_power(record.power) for record in month_records)

        # 3. Peak Power Today
        peak_power_today = today_records.aggregate(Max('power'))['power__max']
        if peak_power_today is None:
            peak_power_today=0


        # 4. Peak Power This Month
        peak_power_this_month = month_records.aggregate(Max('power'))['power__max']
        if peak_power_this_month is None:
            peak_power_this_month=0

        # 5. All-Time Peak Power
        all_time_peak_power = UserMeterReadings.objects.filter(meter_id__in=meter_id).aggregate(Max('power'))['power__max']


        return Response(
            {"status":True,
            "Total_meters":len(meter_id),
            "overall_consumption":overall_consumption,
            'max_dropdown':max_power_row,
            'todays_power_consumed':todays_power_consumed,
            'monthly_power_consumed':monthly_power_consumed,
            "peak_power_today":float(peak_power_today),
            "peak_power_this_month":float(peak_power_this_month),
            "all_time_peak_power":float(all_time_peak_power)
            },status=status.HTTP_200_OK
            )


class KwhData(APIView):
    def get(self,request):
        token = request.META.get('HTTP_AUTHORIZATION') 
        try:
        
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email = d.get("email"))
            if d.get('method')!="verified" or usr.role!='user':
                return Response({"status":False,"message":"Unauthorized"},status=status.HTTP_401_UNAUTHORIZED)  
        except:
            return Response({'status': False, 'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)

        members_id = [i.id for i in UserMemberships.objects.filter(user_id=usr.id)]
        meter_id = [i.id for i in UserMeters.objects.filter(member_id__in = members_id)]
        current_date = now().date()
        current_month = now().month
        current_year = now().year

        data = (
            UserMeterReadings.objects.filter(
                datetime__year=current_year,
                datetime__month=current_month,
                meter_id__in = meter_id
                )
                .values("meter_id")  # Group by meter_id
                .annotate(
                total_power_today=Sum("power", filter=models.Q(datetime__date=current_date)),  # Today's total power
                peak_power_today=Max("power", filter=models.Q(datetime__date=current_date)),   # Today's peak power
                total_power_month=Sum("power"),  # This month's total power
                peak_power_month=Max("power")   # This month's peak power
                )
            )

        result = [
            {
                "meter_id": entry["meter_id"],
                "total_power_today": entry["total_power_today"] or 0,
                "peak_power_today": entry["peak_power_today"] or 0,
                "total_power_month": entry["total_power_month"] or 0,
                "peak_power_month": entry["peak_power_month"] or 0,
            }
            for entry in data
        ]
        
        return Response(
            {"status":True,"data":data[:8]},
            status = status.HTTP_200_OK
            )


class KwhAPI(APIView):
    def get(self, request):
        token = request.META.get('HTTP_AUTHORIZATION') 
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'user':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
        except:
            return Response({'status': False, 'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)

        members_id = [i.id for i in UserMemberships.objects.filter(user_id=usr.id)]
        meter_id = [i.id for i in UserMeters.objects.filter(member_id__in=members_id)]
    
        current_date = now().date()
        current_month = now().month
        current_year = now().year
        print(current_year)
        print(current_month)

        data = (
            UserMeterReadings.objects.filter(
                datetime__year=current_year,
                datetime__month=current_month,
                meter_id__in=meter_id
            )
            .values("meter_id")
            .annotate(
                total_power_today=Sum("power", filter=models.Q(datetime__date=current_date)),
                peak_power_today=Max("power", filter=models.Q(datetime__date=current_date)),
                total_power_month=Sum("power"),
                peak_power_month=Max("power")
            )
        )
        print( UserMeterReadings.objects.filter(
                datetime__year=current_year,
                datetime__month=current_month,
                meter_id__in=meter_id
            ))

        print(data)  # Debugging: Check the raw data output

        result = [
            {
                "meter_id": entry["meter_id"],
                "total_power_today": float(entry["total_power_today"]) if entry["total_power_today"] is not None else 0,
                "peak_power_today": float(entry["peak_power_today"]) if entry["peak_power_today"] is not None else 0,
                "total_power_month": float(entry["total_power_month"]) if entry["total_power_month"] is not None else 0,
                "peak_power_month": float(entry["peak_power_month"]) if entry["peak_power_month"] is not None else 0,
            }
            for entry in data
        ]

        return Response(
            {"status": True, "data": result},
            status=status.HTTP_200_OK
        )


class AmpereReading(APIView):
    def get(self,request):
        token = request.META.get('HTTP_AUTHORIZATION') 
        try:
            
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            
            usr = User.objects.get(email = d.get("email"))
            if d.get('method')!="verified" or usr.role!='user':
                return Response({"status":False,"message":"Unauthorized"},status=status.HTTP_401_UNAUTHORIZED)  
        except:
            return Response({'status': False, 'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        members_id = [i.id for i in UserMemberships.objects.filter(user_id=usr.id)]
        meter_id = [i.id for i in UserMeters.objects.filter(member_id__in = members_id)]
        amps=[i.Amphere for i in UserMeterReadings.objects.filter(meter_id__in = meter_id)]
        return Response(
            {"status":True,"data":amps},
            status= status.HTTP_200_OK
        )


class AltersAPI(APIView):
    def get(self,request):
        token = request.META.get('HTTP_AUTHORIZATION') 
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email = d.get("email"))
            if d.get('method')!="verified" or usr.role!='user':
                return Response({"status":False,"message":"Unauthorized"},status=status.HTTP_401_UNAUTHORIZED)  
        except:
            return Response({'status': False, 'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)

        members_id = [i.id for i in UserMemberships.objects.filter(user_id=usr.id)]
        meter_id = [i.id for i in UserMeters.objects.filter(member_id__in = members_id)]
        alertsdata=Alerts.objects.filter(meter_id__in = meter_id)
        serial = AlertsSerial(alertsdata,many=True).data
        return Response(
            {"status":True,"data":serial[-7:]},
            status=status.HTTP_200_OK
        )



class AllAlters(APIView):
    def get(self,request):
        token = request.META.get('HTTP_AUTHORIZATION') 
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email = d.get("email"))
            if d.get('method')!="verified" or usr.role!='user':
                return Response({"status":False,"message":"Unauthorized"},status=status.HTTP_401_UNAUTHORIZED)  
        except:
            return Response({'status': False, 'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)

        members_id = [i.id for i in UserMemberships.objects.filter(user_id=usr.id)]
        meter_id = [i.id for i in UserMeters.objects.filter(member_id__in = members_id)]
        alertsdata=Alerts.objects.filter(meter_id__in = meter_id)
        serial = AlertsSerial(alertsdata,many=True).data
        return Response(
            {"status":True,"data":serial},
            status=status.HTTP_200_OK
        )






class MeterList(APIView):
    def get(self,request):
        token = request.META.get('HTTP_AUTHORIZATION') 
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email = d.get("email"))
            if d.get('method')!="verified" or usr.role!='user':
                return Response({"status":False,"message":"Unauthorized"},status=status.HTTP_401_UNAUTHORIZED)  
        except:
            return Response({'status': False, 'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)

        members_id = [i.id for i in UserMemberships.objects.filter(user_id=usr.id)]
        meters = UserMeterSerial(UserMeters.objects.filter(member_id__in = members_id),many=True)
        return Response(
            {"status":True,"data":meters.data},
            status=status.HTTP_200_OK
        )




class MeterChart(APIView):
    def post(self,request):
        data = request.data
        token = request.META.get('HTTP_AUTHORIZATION') 
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email = d.get("email"))
            if d.get('method')!="verified" or usr.role!='user':
                return Response({"status":False,"message":"Unauthorized"},status=status.HTTP_401_UNAUTHORIZED)  
        except:
            return Response({'status': False, 'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        id_ = data.get('id')
        year = now().year
        members_id = [i.id for i in UserMemberships.objects.filter(user_id=usr.id)]
        meter_id = [i for i in UserMeters.objects.filter(member_id__in = members_id) if i.id==int(id_)]
        records = UserMeterReadings.objects.filter(
                meter_id__in=meter_id,
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
        print(consumption_data)
        return Response({
            "status":True,
            "data":[{"data":consumption_data,"name":"This Month"}]
        },status=status.HTTP_200_OK
        )

class MeterChartDaily(APIView):
    def post(self, request):
        data = request.data
        token = request.META.get('HTTP_AUTHORIZATION') 
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'user':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)  
        except:
            return Response({'status': False, 'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        id_ = data.get('id')
        members_id = [i.id for i in UserMemberships.objects.filter(user_id=usr.id)]
        meter_id = [i for i in UserMeters.objects.filter(member_id__in=members_id) if i.id == int(id_)]
        current_date = now().date()
        records = UserMeterReadings.objects.filter(
            meter_id__in=meter_id,
            datetime__date=current_date 
        ).annotate(hour=TruncHour('datetime')) \
         .values('hour') \
         .annotate(total_power=Sum('power')) \
         .order_by('hour')

        hourly_data = {record["hour"].hour: record["total_power"] for record in records}
        consumption_data = [
            hourly_data.get(hour, 0)  
            for hour in range(24)  
        ]

        return Response({
            "status": True,
            "data": [{"data": consumption_data, "name": "Today's Consumption"}]
        }, status=status.HTTP_200_OK)


class MeterConsumptionLogs(APIView):
    def post(self, request):
        data = request.data
        token = request.META.get('HTTP_AUTHORIZATION') 
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'user':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)  
        except:
            return Response({'status': False, 'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        id_ = data.get('id')
        members_id = [i.id for i in UserMemberships.objects.filter(user_id=usr.id)]
        meter_id = [i for i in UserMeters.objects.filter(member_id__in=members_id) if i.id == int(id_)]
        data  = UserMeterReadings.objects.filter(meter_id__in = meter_id)

        serial = UserMeterReadingsSerial(data,many=True).data

        return Response(
            {"status":True,
            "message":"success",
            "data":serial},
            status=status.HTTP_200_OK 
        )


class Membershipplans(APIView):
    def get(self, request):
        data = request.data
        token = request.META.get('HTTP_AUTHORIZATION') 
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'user':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)  
        except:
            return Response({'status': False, 'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        
        membership=Memberships.objects.filter(status="1")
        membership=MembershipsSerial(membership,many=True).data
        return Response(
            {"status":True,
            "message":"success",
            "data":membership},
            status=status.HTTP_200_OK 
        )


class Paymentreceived(APIView):
    def post(self, request):
        data = request.data
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'user':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)  
        except:
            return Response({'status': False, 'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        id_ = usr
        plan_id = data.get('plan_id')
        plan= Memberships.objects.get(id=plan_id)
        comments= data.get('comment')
        image_path = data.get('imagepath') 
        start_date_obj = datetime.now()
        expiry_date = start_date_obj + timedelta(days=int(plan.plan_period) * 30)
        UserMemberships.objects.create(user_id=usr,plan_id=plan,status="0",amount=plan.amount,expire_date=expiry_date)
 
        Payment.objects.create(user_id= usr,amount=plan.amount,currrency="INR",status="0",comment=comments,image=image_path)     
 
        return Response(
            {"status":True,
            "message":"success"},
            status=status.HTTP_200_OK
        )
   


class getMembership(APIView):
    def post(self, request):
        data = request.data
        token = request.META.get('HTTP_AUTHORIZATION') 
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'user':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)  
        except:
            return Response({'status': False, 'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        id=data.get("plan_id")
        membership=Memberships.objects.get(id=id)
        membership=MembershipsSerial(membership).data
        return Response(
            {"status":True,
            "message":"success",
            "data":membership},
            status=status.HTTP_200_OK 
        )

    


 
class metercreate(APIView):
    def post(self, request):
        data = request.data
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'user':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)  
        except:
            return Response({'status': False, 'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        
        name = data.get('name')
        location = data.get('location')
        plan_id = UserMemberships.objects.get(user_id=usr.id,status='1')
        meter_count = Memberships.objects.get(id=plan_id.plan_id.id)
        experiy_date=plan_id.expire_date
        user_meter_count = UserMeters.objects.filter(member_id=plan_id.id).count()
        
        if int(user_meter_count)<int(meter_count.plan_period):
            meter = UserMeters.objects.create(member_id=plan_id,name=name,location=location) # Enter Here Detail
            given_date = datetime.strptime(f"{experiy_date}", "%Y-%m-%d %H:%M:%S.%f")
 
            # Convert given_date to timezone-aware
            aware_given_date = make_aware(given_date)
 
            # Current timezone-aware datetime
            current_time = now()
 
            # Calculate the difference
            difference = current_time - aware_given_date
            days_difference = difference.days
            print("fdata",days_difference)
            payload_ = {'meter_id': meter.id,'exp': datetime.utcnow() + timedelta(days=abs(days_difference))} # calculate days left in usermembership | Enter Days dynamically
            token = jwt.encode(payload=payload_,
                                   key=KEYS
                                   )
            meter.token = token
            meter.save()
            serial = UserMeterSerial(meter).data
            return Response({"status":True,"Message":"created success","data":serial},status=status.HTTP_200_OK )
        else:
            return Response({"status":False,"message":"Limit Exceede"},status=status.HTTP_400_BAD_REQUEST)
 
 
class craeteqrcode(APIView):
    def post(self, request):
        data = request.data
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            print(d.get("email"))
            if d.get('method') != "verified" or usr.role != 'user':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)  
        except:
            return Response({'status': False, 'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        id_ = data.get('plan_id')
        print(id_)
        
        if True:
            plan_amount=Memberships.objects.get(id=id_).amount
            print(plan_amount)
            
            upidata=UPIID_data.objects.all()[0]
            
            print(upidata)
            try:
                
                qr_code_content = f"upi://pay?pa={upidata.upi_id}&pn={upidata.Merchant_name}&am={plan_amount}&cu=INR"
                print(qr_code_content)
            except Exception as e:
                print("expection ",e)
            # Generate QR code
            return Response({"status":True,"Message":"UPI Data","data":qr_code_content  },status=status.HTTP_200_OK )
        


class IsMember(APIView):
    def get(self,request):
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'user':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)  
        except:
            return Response({'status': False, 'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        
        data = UserMemberships.objects.filter(user_id= usr.id,status="1")
        if len(data)>0:
            return Response({"status":True,"data":"1"},status=status.HTTP_200_OK)
        else:
            return Response({"status":True,"data":"0"},status=status.HTTP_200_OK)
        



class GetDevices(APIView):
    def get(self,request):
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'user':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)  
        except:
            return Response({'status': False, 'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        
        try:
            user_data = UserMemberships.objects.get(user_id = usr.id,status='1')
            meter_data= UserMeters.objects.filter(member_id = user_data.id,status='1')
            serial = UserMeterSerial(meter_data,many=True).data
        except:
            serial = []
        return  Response({"status":True,"Message":"Devices Data","data":serial},status=status.HTTP_200_OK)
    



class UserProfile(APIView):
    def get(self, request):
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'user':
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
    



class ChangeUserPassword(APIView):
    def post(self,request):
        token = request.META.get('HTTP_AUTHORIZATION')
        data = request.data
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'user':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
       
        except jwt.ExpiredSignatureError:
            return Response({"status": False, "message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"status": False, "message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        if data.get("password") == data.get('confirm_password'):
        
            usr.password = make_password(data.get('password')) # type: ignore
            usr.save()
            return  Response({'status':True,'message':'password updated successfully'},status=status.HTTP_200_OK)
        else:
            return Response({
                "status":False,'message':"password and confirm password mismatch"
            },
            status=status.HTTP_400_BAD_REQUEST)
        




class ChangeUserProfile(APIView):
    def post(self,request):
        token = request.META.get('HTTP_AUTHORIZATION')
        data = request.data
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'user':
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
        else:
            return Response({'status':False,'message':serial.errors},status=status.HTTP_400_BAD_REQUEST)




class AmpReadingsApi(APIView):
    def get(self,request):
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'user':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
       
        except jwt.ExpiredSignatureError:
            return Response({"status": False, "message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"status": False, "message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        members_id = [i.id for i in UserMemberships.objects.filter(user_id=usr.id)]
        meter_id = [i.id for i in UserMeters.objects.filter(member_id__in=members_id)]
        data = UserMeterReadings.objects.filter(meter_id__in= meter_id)
        data = UserMeterReadingsSerial(data,many=True).data
        return Response({"status":True,"message":"Amp and volt readings","data":data},status=status.HTTP_200_OK)
        


        
class MembershipStatus(APIView):
    def get(self,request):
        token = request.META.get('HTTP_AUTHORIZATION')
        try:
            d = jwt.decode(token, key=KEYS, algorithms=['HS256'])
            usr = User.objects.get(email=d.get("email"))
            if d.get('method') != "verified" or usr.role != 'user':
                return Response({"status": False, "message": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.ExpiredSignatureError:
            return Response({"status": False, "message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"status": False, "message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({"status": False, "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        try:
            data = UserMemberships.objects.get(user_id = usr.id,status='1')
            data = UserMembershipsSerial(data).data
            return Response({'status':True,'message':'user subscription data','data':data},status=status.HTTP_200_OK)
        except:
            return  Response({'Status':False,'message':'usermembership not found'},status=status.HTTP_400_BAD_REQUEST)



        