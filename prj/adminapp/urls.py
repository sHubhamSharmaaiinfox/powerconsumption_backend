from django.contrib import admin
from django.urls import path
from .import views


urlpatterns = [
   path("create-user",views.CreateUser.as_view()),
   path("verify-account",views.VerifyAccount.as_view()),
   path("verify-account/<str:pk>",views.VerifyAccount.as_view()),
   path("get-user",views.GetAllUser.as_view()),
   path("get-user-id", views.GetUserID.as_view()),
   path("update-user",views.UpdateUser.as_view()),
   path("active-users", views.VerifiedUsers.as_view()),
   path("inactive-users", views.UnverifiedUsers.as_view()),             
   path("user-status", views.DisableUser.as_view()),
   path("create-email", views.CreateEmailSender.as_view()),
   path("update-email", views.UpdateEmailSender.as_view()),
   path("get-mail",views.GetAllEmails.as_view()),
   path("get-mail-id", views.GetEmailId.as_view()),
   path("disable-mail", views.UpdateEmailStatus.as_view()),
   path("create-membership", views.CreateMembership.as_view()),
   path("update-membership", views.UpdateMembership.as_view()),
   path("get-membership", views.GetAllMemberships.as_view()),
   path("get-membership-id", views.GetMembershipById.as_view()),
   path("membership-status", views.UpdateMembershipStatus.as_view()),
   path('create-payment', views.CreatePayment.as_view()),
   path('get-payment', views.GetPayment.as_view()),
   path('get-payment-id', views.GetPaymentsID.as_view()),
   path('update-payment', views.UpdatePaymentStatus.as_view()),
   path('create-datareading', views.meterreading.as_view()),
   path('get-readings', views.getmeterreading.as_view()),
   path('get-pending-payments',views.GetPendingPayment.as_view()),
   path("get-meters",views.MetersData.as_view()),
   path("meter-status",views.MeterStatus.as_view()),
   path("user-detail",views.Detailuser.as_view()),
   path('get-usercount',views.GetUserCount.as_view()),
   path('subscription-chart',views.TotalSubscriptionChart.as_view()),
   path('createupiid',views.createqrupi.as_view()),
   path('Updatepassword',views.Updatepassword.as_view()),
 
]