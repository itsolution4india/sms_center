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
from django.core.paginator import Paginator
import requests
from requests.auth import HTTPBasicAuth
from django.views.decorators.csrf import csrf_exempt

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
    
FASTAPI_LOGS_URL = "https://smscapi.wtsmessage.xyz/logs"
USERNAME = "admin"
PASSWORD = "supersecret"

def view_logs(request):
    try:
        # You can pass lines as query param (e.g., ?lines=300)
        lines_to_fetch = request.GET.get('lines', 300)
        response = requests.get(
            FASTAPI_LOGS_URL,
            params={"lines": lines_to_fetch},
            auth=HTTPBasicAuth(USERNAME, PASSWORD),
            timeout=10
        )

        if response.status_code == 200:
            log_lines = response.json().get("log_lines", [])
            log_lines.reverse()  # Show latest logs first
        else:
            messages.error(request, "Failed to fetch logs.")
            log_lines = []

    except Exception as e:
        messages.error(request, f"Error: {str(e)}")
        log_lines = []

    # Paginate
    paginator = Paginator(log_lines, 20)  # 20 logs per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, "view_logs.html", {"page_obj": page_obj})


import telnetlib
import re
import time
from django.shortcuts import render, redirect
from django.contrib import messages

JCLI_HOST = "46.202.130.143"
JCLI_PORT = 8990
TIMEOUT = 5

def fetch_jasmin_users():
    try:
        tn = telnetlib.Telnet(JCLI_HOST, JCLI_PORT, TIMEOUT)

        tn.read_until(b"jcli : ", timeout=TIMEOUT)
        tn.write(b"user -l\n")
        output = tn.read_until(b"jcli : ", timeout=TIMEOUT).decode('utf-8')
        tn.write(b"quit\n")

        lines = output.strip().splitlines()
        users_data = []

        # Get only lines starting with '#' (header + user data)
        data_lines = [line[1:].strip() for line in lines if line.startswith('#')]

        if len(data_lines) < 2:
            print("No user data found")
            return []

        for line in data_lines[1:]:
            # First split out uid, gid, username
            initial_parts = re.split(r'\s{2,}', line, maxsplit=3)
            if len(initial_parts) < 4:
                continue

            uid, gid, username, rest = initial_parts

            # Now split the rest into balance, mt_sms, throughput
            last_parts = re.split(r'\s{2,}', rest)
            balance = last_parts[0] if len(last_parts) > 0 else "ND"
            mt_sms = last_parts[1] if len(last_parts) > 1 else "ND"
            throughput = last_parts[2] if len(last_parts) > 2 else "ND"

            users_data.append({
                'uid': uid,
                'gid': gid,
                'username': username,
                'balance': balance,
                'mt_sms': mt_sms,
                'throughput': throughput,
            })

        return users_data

    except Exception as e:
        print(f"Error fetching Jasmin users: {e}")
        return []


def list_users(request):
    users = fetch_jasmin_users()
    return render(request, 'users/list_users.html', {'users': users})


@csrf_exempt
def add_user(request):
    if request.method == 'POST':
        uid = request.POST.get("uid")
        username = request.POST.get("username")
        password = request.POST.get("password")
        gid = request.POST.get("gid")

        tn = telnetlib.Telnet("46.202.130.143", 8990, 5)
        tn.read_until(b"jcli : ", timeout=5)
        tn.write(b"user -a\n")
        time.sleep(1)

        tn.write(f"username {username}\n".encode())
        tn.write(f"password {password}\n".encode())
        tn.write(f"gid {gid}\n".encode())
        tn.write(f"uid {uid}\n".encode())

        # Optional fields
        for key, value in request.POST.items():
            if key not in ['uid', 'username', 'password', 'gid'] and value:
                tn.write(f"{key} {value}\n".encode())

        tn.write(b"ok\n")
        time.sleep(1)
        tn.read_very_eager()
        tn.write(b"quit\n")
        tn.close()

        return redirect('list_users')

    context = {
        'auth_fields': [
            'http_send', 'http_balance', 'http_rate', 'http_bulk',
            'smpps_send', 'http_long_content', 'dlr_level', 'http_dlr_method',
            'src_addr', 'priority', 'validity_period', 'schedule_delivery_time', 'hex_content'
        ],
        'valuefilters': ['dst_addr', 'src_addr', 'priority', 'validity_period', 'content'],
        'quotas': ['balance', 'early_percent', 'sms_count', 'http_throughput', 'smpps_throughput'],
    }
    return render(request, 'users/add_user.html', context)


def delete_user(request, uid):
    try:
        tn = telnetlib.Telnet(JCLI_HOST, JCLI_PORT, TIMEOUT)
        tn.read_until(b"jcli : ")
        tn.write(f"user -r {uid}\n".encode())
        time.sleep(0.5)
        tn.read_very_eager()
        tn.write(b"quit\n")
        tn.close()
        messages.success(request, f"User {uid} deleted.")
    except Exception as e:
        messages.error(request, f"Error deleting user: {e}")

    return redirect('list_users')

# views.py
import mysql.connector
from django.shortcuts import render
from django.http import JsonResponse
from datetime import datetime, timedelta
import json

def get_db_connection():
    """Establish database connection"""
    try:
        conn = mysql.connector.connect(
            host='localhost',
            port=3306,
            user='prashanth@itsolution4india.com',
            password='Solution@97',
            database='smsc_table'
        )
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        return None

def user_list(request):
    """View to display all usernames"""
    conn = get_db_connection()
    if not conn:
        return render(request, 'error.html', {'error': 'Database connection failed'})
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT DISTINCT username FROM smsc_responses WHERE username IS NOT NULL ORDER BY username")
        users = cursor.fetchall()
        return render(request, 'user_list.html', {'users': users})
    except Exception as e:
        print(f"Error fetching users: {e}")
        return render(request, 'error.html', {'error': str(e)})
    finally:
        if conn:
            conn.close()

def user_analytics(request, username):
    """View to display analytics for a specific user"""
    context = {
        'username': username,
        'default_date': datetime.now().strftime('%Y-%m-%d')
    }
    return render(request, 'user_analytics.html', context)

def get_analytics_data(request):
    """API endpoint to fetch analytics data for Chart.js"""
    username = request.GET.get('username')
    date_str = request.GET.get('date', datetime.now().strftime('%Y-%m-%d'))
    
    try:
        selected_date = datetime.strptime(date_str, '%Y-%m-%d')
        next_day = selected_date + timedelta(days=1)
    except ValueError:
        selected_date = datetime.now()
        next_day = selected_date + timedelta(days=1)
    
    conn = get_db_connection()
    if not conn:
        return JsonResponse({'error': 'Database connection failed'}, status=500)
    
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Query for status counts
        status_query = """
            SELECT status, COUNT(*) as count 
            FROM smsc_responses 
            WHERE username = %s AND created_at >= %s AND created_at < %s
            GROUP BY status
        """
        cursor.execute(status_query, (username, selected_date, next_day))
        status_data = cursor.fetchall()
        
        # Query for hourly distribution
        hourly_query = """
            SELECT EXTRACT(HOUR FROM created_at) as hour, COUNT(*) as count
            FROM smsc_responses
            WHERE username = %s AND created_at >= %s AND created_at < %s
            GROUP BY EXTRACT(HOUR FROM created_at)
            ORDER BY hour
        """
        cursor.execute(hourly_query, (username, selected_date, next_day))
        hourly_data = cursor.fetchall()
        
        # Query for error distribution (if any)
        error_query = """
            SELECT error_code, error_message, COUNT(*) as count
            FROM smsc_responses
            WHERE username = %s AND created_at >= %s AND created_at < %s AND error_code IS NOT NULL
            GROUP BY error_code, error_message
            ORDER BY count DESC
            LIMIT 5
        """
        cursor.execute(error_query, (username, selected_date, next_day))
        error_data = cursor.fetchall()
        
        # Prepare data for charts
        result = {
            'status_labels': [item['status'] for item in status_data],
            'status_counts': [item['count'] for item in status_data],
            'hourly_labels': [f"{int(item['hour'])}:00" for item in hourly_data],
            'hourly_counts': [item['count'] for item in hourly_data],
            'error_data': error_data,
            'total_messages': sum([item['count'] for item in hourly_data]),
            'selected_date': selected_date.strftime('%Y-%m-%d')
        }
        
        return JsonResponse(result)
    except Exception as e:
        print(f"Error fetching analytics data: {e}")
        return JsonResponse({'error': str(e)}, status=500)
    finally:
        if conn:
            conn.close()
            
import mysql.connector
from django.shortcuts import render, redirect
from django.http import HttpResponse

DB_CONFIG = {
    'host': 'localhost',
    'user': 'prashanth@itsolution4india.com',
    'password': 'Solution@97',
    'database': 'smsc_table'
}

def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)

def list_users(request):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM whatsapp_services")
    users = cursor.fetchall()
    cursor.close()
    conn.close()
    return render(request, 'users/list.html', {'users': users})

def create_user(request):
    if request.method == 'POST':
        data = (
            request.POST['SenderID'],
            request.POST['username'],
            request.POST['account_id'],
            request.POST['balance'],
            request.POST['tps'],
            request.POST['Service'],
            request.POST['number'],
            request.POST['app_name'],
            request.POST['phone_id'],
            request.POST['waba_id'],
            request.POST['token'],
            request.POST['template_name'],
            request.POST['language'],
        )

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO whatsapp_services 
            (SenderID, username, account_id, balance, tps, Service, number, app_name, phone_id, waba_id, token, template_name, language)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, data)
        conn.commit()
        cursor.close()
        conn.close()
        return redirect('list_users')
    return render(request, 'users/create.html')

def edit_user(request, username):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM whatsapp_services WHERE username = %s", (username,))
    user = cursor.fetchone()

    if request.method == 'POST':
        data = (
            request.POST['SenderID'],
            request.POST['account_id'],
            request.POST['balance'],
            request.POST['tps'],
            request.POST['Service'],
            request.POST['number'],
            request.POST['app_name'],
            request.POST['phone_id'],
            request.POST['waba_id'],
            request.POST['token'],
            request.POST['template_name'],
            request.POST['language'],
            username,
        )

        cursor.execute("""
            UPDATE whatsapp_services SET
            SenderID=%s, account_id=%s, balance=%s, tps=%s, Service=%s, number=%s,
            app_name=%s, phone_id=%s, waba_id=%s, token=%s, template_name=%s, language=%s
            WHERE username=%s
        """, data)
        conn.commit()
        return redirect('list_users')

    cursor.close()
    conn.close()
    return render(request, 'users/edit.html', {'user': user})

def delete_user(request, username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM whatsapp_services WHERE username = %s", (username,))
    conn.commit()
    cursor.close()
    conn.close()
    return redirect('list_users')
