from django.contrib import admin
from django.urls import path
from scanner import views

urlpatterns = [
    path('admin/', admin.site.urls),

    # authentification
    path('signup/', views.signup_view, name='signup'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),

    # dashboard (page principale après login)
    path('', views.dashboard, name='dashboard'),
    path('dashboard/', views.dashboard, name='dashboard'),

    # scanners
    path('scan-url/', views.home, name='scan_url'),
    path('scan-ip/', views.scan_ip, name='scan_ip'),
    path('scan-url/', views.home, name='url_scan'),  # home = ton scan URLù
    path('scan-ip/', views.scan_ip, name='nmap_scan'),
]