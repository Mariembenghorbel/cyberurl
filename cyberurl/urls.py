from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from scanner.views.auth import redirection_dashboard
from django.conf import settings

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # Authentification native et sécurisée de Django
    path('login/', auth_views.LoginView.as_view(template_name='registration/login.html'), name='login'),
    # La déconnexion en méthode POST requise pour casser la session proprement
    path('logout/', auth_views.LogoutView.as_view(next_page='login'), name='logout'),
    
    # Point d'entrée central de ton app (aiguillage automatique)
    path('', redirection_dashboard, name='redirection_dashboard'),
    
    # Inclusion de toutes les sous-routes de l'application scanner
    path('security/', include('scanner.urls')),
  

]
