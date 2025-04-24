from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.decorators import login_required, user_passes_test
from .models import CustomUser, SenderDetails
from .utils import logger
from .forms import SenderDetailsForm
from django.http import JsonResponse


def admin_check(user):
    return user.is_superuser

def login_view(request):
    if request.user.is_authenticated:
        logger.info(f"User logged in successfully {request.user}")
        return redirect('dashboard')
        
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        try:
            user = CustomUser.objects.get(username=username)
            
            # Check if account is locked
            if user.locked_until and user.locked_until > timezone.now():
                remaining_time = user.locked_until - timezone.now()
                if remaining_time > timedelta(minutes=25):
                    # 30 minute lockout
                    minutes = int(remaining_time.total_seconds() // 60)
                    messages.error(request, f'Account locked. Try again after {minutes} minutes.')
                else:
                    # 1 minute lockout
                    seconds = int(remaining_time.total_seconds())
                    messages.error(request, f'Account locked. Try again after {seconds} seconds.')
                return render(request, 'login.html')
            
            # Try to authenticate
            user_auth = authenticate(request, username=username, password=password)
            
            if user_auth is not None:
                # Reset failed attempts on successful login
                user.failed_login_attempts = 0
                user.last_failed_attempt = None
                user.locked_until = None
                user.save()
                
                login(request, user_auth)
                return redirect('dashboard')
            else:
                # Increment failed attempts
                user.failed_login_attempts += 1
                user.last_failed_attempt = timezone.now()
                
                # Check for lockout conditions
                if user.failed_login_attempts >= 3:
                    if user.failed_login_attempts >= 6:
                        # Lock for 30 minutes after 6 attempts (3 + 3)
                        user.locked_until = timezone.now() + timedelta(minutes=30)
                        user.failed_login_attempts = 0
                        messages.error(request, 'Too many failed attempts. Account locked for 30 minutes.')
                    else:
                        # Lock for 1 minute after 3 attempts
                        user.locked_until = timezone.now() + timedelta(minutes=1)
                        messages.error(request, 'Too many failed attempts. Account locked for 1 minute.')
                else:
                    messages.error(request, 'Invalid username or password.')
                
                user.save()
                
        except CustomUser.DoesNotExist:
            messages.error(request, 'Invalid username or password.')
        
    return render(request, 'login.html')

@login_required
def dashboard_view(request):
    return render(request, 'dashboard.html')

@login_required
def logout_view(request):
    logout(request)
    return redirect('login')

@user_passes_test(admin_check, login_url='/login/')
@login_required
def sender_details_list(request):
    """View to display all sender details"""
    sender_details = SenderDetails.objects.all()
    return render(request, 'sender_details_list.html', {'sender_details': sender_details})

@login_required
def create_sender_details(request):
    """View to create new sender details"""
    if request.method == 'POST':
        form = SenderDetailsForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Sender details created successfully!')
            return redirect('sender_details_list')
    else:
        form = SenderDetailsForm()
    
    return render(request, 'sender_details_form.html', {
        'form': form,
        'title': 'Register New Sender Details',
        'button_text': 'Register'
    })

@login_required
def edit_sender_details(request, pk):
    """View to edit existing sender details"""
    sender_details = get_object_or_404(SenderDetails, pk=pk)
    
    if request.method == 'POST':
        form = SenderDetailsForm(request.POST, instance=sender_details)
        if form.is_valid():
            form.save()
            messages.success(request, 'Sender details updated successfully!')
            return redirect('sender_details_list')
    else:
        form = SenderDetailsForm(instance=sender_details)
    
    return render(request, 'sender_details_form.html', {
        'form': form,
        'title': 'Edit Sender Details',
        'button_text': 'Update'
    })

@login_required
def delete_sender_details(request, pk):
    """View to delete sender details"""
    sender_details = get_object_or_404(SenderDetails, pk=pk)
    
    if request.method == 'POST':
        sender_details.delete()
        messages.success(request, 'Sender details deleted successfully!')
        return redirect('sender_details_list')
    
    return render(request, 'sender_details_confirm_delete.html', {
        'sender_details': sender_details
    })

def get_webhook(request, sender_id):
    try:
        webhook = SenderDetails.objects.get(sender_id=sender_id)
        return JsonResponse({"webhook_url": webhook.webhook_url})
    except SenderDetails.DoesNotExist:
        return JsonResponse({"webhook_url": None}, status=404)