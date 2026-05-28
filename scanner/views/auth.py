from django.shortcuts import render, redirect
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm

def signup_view(request):
    """Register a new operator profile"""
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)  # Automatically authorize user after registration
            return redirect('redirection_dashboard')
    else:
        form = UserCreationForm()
    return render(request, 'signup.html', {'form': form})

@login_required
def redirection_dashboard(request):
    """Automatic pipeline redirection after authentication"""
    if request.user.is_staff or request.user.is_superuser:
        return redirect('dashboard_soc')  # Route to master SOC dashboard if Analyst/Admin
    return redirect('url_scan')  # Route to normal utilities page if default Operator