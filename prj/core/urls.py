from django.contrib import admin
from django.urls import path
from .import views


urlpatterns = [
    path("login",views.LoginAPIView.as_view()),
    path('forgot',views.ForgotPasswordApi.as_view()),
    path('reset-password',views.ResetPassword.as_view()),
    path('save-data',views.UserMeterDataCreation.as_view())
    # path('fix-time',views.FixTimeAPI.as_view())
]