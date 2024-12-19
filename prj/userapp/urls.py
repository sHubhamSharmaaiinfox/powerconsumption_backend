from django.contrib import admin
from django.urls import path
from .import views


urlpatterns = [
    path('meters-data',views.MetersData.as_view()),
    path('meter-readings',views.AmpereReading.as_view()),
    path('kwh-data',views.KwhData.as_view()),
    path('alerts',views.AltersAPI.as_view()),
    path('kwh',views.KwhAPI.as_view()),
    path('meter-list',views.MeterList.as_view()),
    path('meter-chart',views.MeterChart.as_view()),
    path('meter-chart-daily',views.MeterChartDaily.as_view()),
    path('meter-consumption-logs',views.MeterConsumptionLogs.as_view()),
    path('membershipplan',views.Membershipplans.as_view()),
    path('paymentreceived',views.Paymentreceived.as_view()),
    path('getMembership',views.getMembership.as_view()),
    path('metercreate',views.metercreate.as_view()),
    path('createqrcode',views.craeteqrcode.as_view())
 
]