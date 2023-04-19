from django.urls import path, include
from .import views
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register(r'userview', views.RsmUser,basename='userview'),

urlpatterns = [
    #path('', include(router.urls)),
    path('userall/', views.Usergetall.as_view(),name='userall'),

    path('userregister/', views.UserRegister.as_view(),name='userregister'),

    path('userlogin/', views.UserLogin.as_view(),name='userlogin'),
    path('userlogout/', views.UserLogout.as_view(),name='userlogout'),

    path('forgotpass/', views.ForgotPass.as_view(), name='forgotpass'),
    path('change/', views.ResetPassword.as_view(), name='change'),

    path('userget/<str:pk>/', views.UserGet.as_view() ,name='getu'),
    path('userupdate/<str:pk>/', views.UserUpdate.as_view() ,name='updateu'),
    path('userdelete/<str:pk>/', views.UserDelete.as_view() ,name='deleteu'),

]