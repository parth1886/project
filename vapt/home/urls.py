from django.contrib import admin
from django.urls import path
from home import views
from .views import  port_scan_result
urlpatterns = [
    path("", views.index, name='home'),
    path("tool", views.tool, name='tool'),
    path("tool2", views.tool2, name='tool2'),
    path("tool3", views.tool3, name='tool3'),
    path("tool4", views.tool4, name='tool4'),
    path("tool5", views.tool5, name='tool5'),
    path("tool6", views.tool6, name='tool6'),
    path("tool7", views.tool7, name='tool7'),
    path("tool8", views.tool8, name='tool8'),
    path("about", views.about, name='about'),
    path("services", views.services, name='services'),
    path("team", views.team, name='team'),
    path("contact", views.contact, name='contact'),
    # path("profile", views.profile, name='profile'),
    path("signup", views.handleSignup, name='handleSignup'),
    path("signin", views.handleSignin, name='handleSignin'),
    path("logout", views.handleLogout, name='handleLogout'),
     path('portscanresult/', port_scan_result, name='port_scan_result'),
   

]