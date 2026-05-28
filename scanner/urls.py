from django import views
from django.urls import path
from .views.auth import signup_view
from .views.employee import url_scan_view
from .views.soc import  check_new_incidents, export_scan_pdf, nmap_audit_view, respond_incident
from django.urls import path
# Importe la vue manquante ici :
from .views.soc import dashboard_soc_view,delete_incident


urlpatterns = [
    path('signup/', signup_view, name='signup'),
    path('workspace/employee/', url_scan_view, name='url_scan'),
    path('workspace/soc/', dashboard_soc_view, name='dashboard_soc'),
    path('workspace/soc/audit/', nmap_audit_view, name='nmap_scan'),
    path('audit/', nmap_audit_view, name='nmap_audit'),
    path('audit/pdf/', export_scan_pdf, name='export_scan_pdf'),
    path('dashboard/', dashboard_soc_view, name='dashboard_soc'),
   
    path( 'analyst/respond/<int:incident_id>/', respond_incident, name='respond_incident' ),
  


    path("workspace/soc/alerts/check/", check_new_incidents, name="check_new_incidents"),
    path('incident/delete/<int:incident_id>/', delete_incident, name='delete_incident'),

]