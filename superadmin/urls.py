from django.contrib import admin
from django.urls import path
from .import views
urlpatterns = [
   path('profile',views.ProfileApi.as_view()),
   path('profile-update',views.ChangeProfile.as_view()),
   path('change-password',views.ChangePassword.as_view()),
   path('get-admin',views.GetAllAdmins.as_view()),
   path("active-admin",views.ActiveAdmins.as_view()),
   path('create-admin',views.CreateAdmin.as_view()),
   path('update-admin',views.UpdateAdmin.as_view()),
   path('admin-status',views.AdminStatus.as_view()),
   path("get-user",views.GetUserDetails.as_view()),
   path("inactive-admin",views.InactiveAdmin.as_view()),
   path('active-users',views.ActiveUser.as_view()),
   path("inactive-users",views.InactiveUsers.as_view()),
   path("create-membership", views.CreateMembership.as_view()),
   path("update-membership", views.UpdateMembership.as_view()),
   path("get-membership", views.GetAllMemberships.as_view()),
   path("membership-status",views.UpdateMembershipStatus.as_view()),
   path('dash-cards',views.DashCards.as_view()),
   path('admin-package',views.AdminPackagesApi.as_view()),
   path('user-count-by-month',views.UserCountByMonth.as_view()),
   path('admin-count-by-month',views.AdminCountByMonth.as_view()),
   path('subscription-amount-by-month',views.SubscribersCountByMonth.as_view()),
   path('devices-by-month',views.DevicesByMonth.as_view()),
   path('admindetail',views.AdminDetail.as_view()),
   path('get-users-data',views.GetUsersData.as_view()),
   path("get-pending-payments",views.GetPendingPayment.as_view()),
   path("update-payment",views.UpdatePaymentStatus.as_view()),
   path('get-payment',views.GetPayment.as_view()),
   path("get-qr-detail",views.GetQrUpi.as_view()),
   path("createupiid",views.createqrupi.as_view())
]