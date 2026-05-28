from django.contrib import admin

# Register your models here.
from django.contrib import admin
from .models import Incident, Asset

admin.site.register(Incident)
admin.site.register(Asset)