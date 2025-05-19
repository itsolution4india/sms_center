from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.decorators import login_required, user_passes_test
from .models import CustomUser, SenderDetails
from .utils import logger
from .forms import SenderDetailsForm
from django.http import JsonResponse, HttpResponse
from django.core.paginator import Paginator
import requests
from requests.auth import HTTPBasicAuth
from django.views.decorators.csrf import csrf_exempt
from django.db import connection
import random
import telnetlib
import re
import time
import mysql.connector
from datetime import datetime, timedelta
import csv
import openpyxl


FASTAPI_LOGS_URL = "https://smppapi.wtsmessage.xyz/logs"
USERNAME = "admin"
PASSWORD = "supersecret"

JCLI_HOST = "46.202.130.143"
JCLI_PORT = 8990
TIMEOUT = 5

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


def list_jasmin_users(request):
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

def delete_jasmin_user(request, uid):
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
        
        # Query for dlr_status counts (new)
        dlr_status_query = """
            SELECT dlr_status, COUNT(*) as count 
            FROM smsc_responses 
            WHERE username = %s AND created_at >= %s AND created_at < %s
            GROUP BY dlr_status
        """
        cursor.execute(dlr_status_query, (username, selected_date, next_day))
        dlr_status_data = cursor.fetchall()
        
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
        
        # Query for hourly distribution per dlr_status (new)
        hourly_dlr_query = """
            SELECT EXTRACT(HOUR FROM created_at) as hour, 
                   dlr_status,
                   COUNT(*) as count
            FROM smsc_responses
            WHERE username = %s AND created_at >= %s AND created_at < %s
            GROUP BY EXTRACT(HOUR FROM created_at), dlr_status
            ORDER BY hour, dlr_status
        """
        cursor.execute(hourly_dlr_query, (username, selected_date, next_day))
        hourly_dlr_data = cursor.fetchall()
        
        # Process hourly DLR data to format needed for Chart.js
        hourly_sent = []
        hourly_pending = []
        hourly_failed = []
        hours = sorted(set([int(item['hour']) for item in hourly_dlr_data]))
        
        # Initialize arrays with zeros
        for _ in range(24):
            hourly_sent.append(0)
            hourly_pending.append(0)
            hourly_failed.append(0)
        
        # Fill with actual data
        for item in hourly_dlr_data:
            hour = int(item['hour'])
            status = item['dlr_status']
            count = item['count']
            
            if status == 'sent':
                hourly_sent[hour] = count
            elif status == 'pending':
                hourly_pending[hour] = count
            elif status == 'failed':
                hourly_failed[hour] = count
        
        # Prepare data for charts
        result = {
            'status_labels': [item['status'] for item in status_data],
            'status_counts': [item['count'] for item in status_data],
            'dlr_status_labels': [item['dlr_status'] if item['dlr_status'] else 'unknown' for item in dlr_status_data],
            'dlr_status_counts': [item['count'] for item in dlr_status_data],
            'hourly_labels': [f"{hour}:00" for hour in range(24)],
            'hourly_counts': [item['count'] for item in hourly_data],
            'hourly_dlr_data': {
                'sent': hourly_sent,
                'pending': hourly_pending,
                'failed': hourly_failed
            },
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
            
DB_CONFIG = {
    'host': 'localhost',
    'user': 'prashanth@itsolution4india.com',
    'password': 'Solution@97',
    'database': 'smsc_table'
}

def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)

def generate_transaction_id():
    return f"ITS{random.randint(100000, 999999)}"

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
            (sender_id, username, account_id, balance, tps, Service, number, app_name, phone_id, waba_id, token, template_name, language)
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
            sender_id=%s, account_id=%s, balance=%s, tps=%s, Service=%s, number=%s,
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

def get_all_usernames():
    with connection.cursor() as cursor:
        cursor.execute("SELECT username FROM whatsapp_services")
        return [row[0] for row in cursor.fetchall()]
    
def generate_transaction_id():
    return f"ITS{random.randint(100000, 999999)}"

def credit_debit_coins(request):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch all usernames
    cursor.execute("SELECT username FROM whatsapp_services")
    usernames = [row['username'] for row in cursor.fetchall()]

    # Fetch coin history
    cursor.execute("SELECT * FROM coins_history ORDER BY created_at DESC LIMIT 50")
    history = cursor.fetchall()

    if request.method == 'POST':
        username = request.POST['username']
        coins = int(request.POST['coins'])
        action_type = request.POST['action_type']
        transaction_id = generate_transaction_id()

        # Get current balance
        cursor.execute("SELECT balance FROM whatsapp_services WHERE username = %s", (username,))
        result = cursor.fetchone()

        if not result:
            cursor.close()
            conn.close()
            return HttpResponse("User not found.")

        current_balance = int(result['balance'])

        if action_type == 'credit':
            new_balance = current_balance + coins
            reason = f"{coins} coins have been credited to your account, your current balance is {new_balance}"
        else:
            new_balance = current_balance - coins
            reason = f"{coins} coins have been deducted from your account, your current balance is {new_balance}"

        # Update balance
        cursor.execute("UPDATE whatsapp_services SET balance = %s WHERE username = %s", (new_balance, username))

        # Insert into coins_history
        cursor.execute("""
            INSERT INTO coins_history (username, coins, reason, created_at, type, transaction_id)
            VALUES (%s, %s, %s, NOW(), %s, %s)
        """, (username, coins, reason, action_type, transaction_id))

        conn.commit()
        cursor.close()
        conn.close()
        return redirect('coin_transaction')

    cursor.close()
    conn.close()
    return render(request, 'users/coin_transaction.html', {'usernames': usernames, 'history': history})


def smsc_responses_view(request):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Filters from GET params
    filters = {
        'username': request.GET.get('username', ''),
        'source_addr': request.GET.get('source_addr', ''),
        'destination_addr': request.GET.get('destination_addr', ''),
        'status': request.GET.get('status', ''),
        'dlr_status': request.GET.get('dlr_status', ''),
        'search': request.GET.get('search', ''),
    }

    base_query = "SELECT * FROM smsc_responses WHERE 1=1"
    params = []

    for key in ['username', 'source_addr', 'destination_addr', 'status', 'dlr_status']:
        if filters[key]:
            base_query += f" AND {key} LIKE %s"
            params.append(f"%{filters[key]}%")

    if filters['search']:
        base_query += " AND (short_message LIKE %s OR message_body LIKE %s OR contact_name LIKE %s)"
        q = f"%{filters['search']}%"
        params += [q, q, q]

    base_query += " ORDER BY created_at DESC"

    cursor.execute(base_query, params)
    all_records = cursor.fetchall()

    # Export
    export = request.GET.get('export')
    if export == 'csv':
        return export_to_csv(all_records)
    elif export == 'excel':
        return export_to_excel(all_records)

    # Pagination
    paginator = Paginator(all_records, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'smsc_responses.html', {
        'page_obj': page_obj,
        'filters': filters
    })


# def export_to_csv(records):
#     response = HttpResponse(content_type='text/csv')
#     response['Content-Disposition'] = 'attachment; filename="smsc_responses.csv"'
#     writer = csv.writer(response)
    
#     if records:
#         writer.writerow(records[0].keys())  # headers
#         for row in records:
#             writer.writerow(row.values())
#     return response


# def export_to_excel(records):
#     response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
#     response['Content-Disposition'] = 'attachment; filename="smsc_responses.xlsx"'

#     wb = openpyxl.Workbook()
#     ws = wb.active
#     if records:
#         ws.append(list(records[0].keys()))
#         for row in records:
#             ws.append(list(row.values()))
#     wb.save(response)
#     return response

from urllib.parse import urlencode
import csv
import xlwt
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger

def smsc_responses_list(request):
    """View to display SMSC responses with filtering and pagination"""
    # Get filter parameters from request
    username = request.GET.get('username', '')
    source_addr = request.GET.get('source_addr', '')
    destination_addr = request.GET.get('destination_addr', '')
    status = request.GET.get('status', '')
    dlr_status = request.GET.get('dlr_status', '')
    search = request.GET.get('search', '')
    error_code = request.GET.get('error_code', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    
    # Database connection
    conn = get_db_connection()
    if not conn:
        return render(request, 'smsc_responses/list.html', 
                     {'error': 'Database connection failed'})
    
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Build the SQL query with filters
        sql_query = "SELECT * FROM smsc_responses WHERE 1=1"
        params = []
        
        if username:
            sql_query += " AND username LIKE %s"
            params.append(f"%{username}%")
        
        if source_addr:
            sql_query += " AND source_addr LIKE %s"
            params.append(f"%{source_addr}%")
        
        if destination_addr:
            sql_query += " AND destination_addr LIKE %s"
            params.append(f"%{destination_addr}%")
        
        if status:
            sql_query += " AND status = %s"
            params.append(status)
        
        if dlr_status:
            sql_query += " AND dlr_status = %s"
            params.append(dlr_status)
        
        if error_code:
            sql_query += " AND error_code = %s"
            params.append(int(error_code))
        
        if date_from:
            sql_query += " AND created_at >= %s"
            params.append(date_from)
        
        if date_to:
            sql_query += " AND created_at <= %s"
            params.append(date_to)
        
        # Global search across multiple fields
        if search:
            sql_query += """ AND (
                username LIKE %s OR
                source_addr LIKE %s OR
                destination_addr LIKE %s OR
                short_message LIKE %s OR
                message_id LIKE %s OR
                status LIKE %s OR
                contact_name LIKE %s OR
                message_body LIKE %s
            )"""
            search_param = f"%{search}%"
            params.extend([search_param] * 8)  # Add search parameter 8 times for the 8 OR conditions
        
        # Add order by
        sql_query += " ORDER BY created_at DESC"
        
        # Get total count for pagination
        count_query = f"SELECT COUNT(*) as count FROM ({sql_query}) as filtered_data"
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()['count']
        
        # Get paginated results
        page = request.GET.get('page', 1)
        per_page = 20  # Items per page
        
        # Add limit and offset for pagination
        offset = (int(page) - 1) * per_page
        sql_query += f" LIMIT {per_page} OFFSET {offset}"
        
        # Execute the query with all filters
        cursor.execute(sql_query, params)
        results = cursor.fetchall()
        
        # Get unique values for filter dropdowns
        cursor.execute("SELECT DISTINCT username FROM smsc_responses ORDER BY username")
        usernames = [row['username'] for row in cursor.fetchall() if row['username']]
        
        cursor.execute("SELECT DISTINCT status FROM smsc_responses ORDER BY status")
        statuses = [row['status'] for row in cursor.fetchall() if row['status']]
        
        cursor.execute("SELECT DISTINCT dlr_status FROM smsc_responses ORDER BY dlr_status")
        dlr_statuses = [row['dlr_status'] for row in cursor.fetchall() if row['dlr_status']]
        
        cursor.execute("SELECT DISTINCT error_code FROM smsc_responses WHERE error_code IS NOT NULL ORDER BY error_code")
        error_codes = [row['error_code'] for row in cursor.fetchall()]
        
        # Create paginator
        paginator = Paginator(range(total_count), per_page)
        try:
            page_obj = paginator.page(page)
        except PageNotAnInteger:
            page_obj = paginator.page(1)
        except EmptyPage:
            page_obj = paginator.page(paginator.num_pages)
        
        # Save current GET parameters for pagination links
        get_params = request.GET.copy()
        if 'page' in get_params:
            del get_params['page']
        query_string = urlencode(get_params)
        
        # Prepare context for template
        context = {
            'results': results,
            'page_obj': page_obj,
            'total_count': total_count,
            'usernames': usernames,
            'statuses': statuses,
            'dlr_statuses': dlr_statuses,
            'error_codes': error_codes,
            'filters': {
                'username': username,
                'source_addr': source_addr,
                'destination_addr': destination_addr,
                'status': status,
                'dlr_status': dlr_status,
                'search': search,
                'error_code': error_code,
                'date_from': date_from,
                'date_to': date_to,
            },
            'query_string': query_string
        }
        
        # Check if export was requested
        if 'export' in request.GET:
            export_format = request.GET.get('export')
            if export_format == 'csv':
                return export_to_csv(results)
            elif export_format == 'excel':
                return export_to_excel(results)
        
        return render(request, 'smsc_responses_list.html', context)
    
    except Exception as e:
        return render(request, 'smsc_responses_list.html', {'error': str(e)})
    finally:
        if conn:
            conn.close()

def export_to_csv(data):
    """Export data to CSV file"""
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="smsc_responses_export.csv"'
    
    writer = csv.writer(response)
    # Write header
    if data:
        writer.writerow(data[0].keys())
        # Write data rows
        for row in data:
            writer.writerow(row.values())
    
    return response

def export_to_excel(data):
    """Export data to Excel file"""
    response = HttpResponse(content_type='application/ms-excel')
    response['Content-Disposition'] = 'attachment; filename="smsc_responses_export.xls"'
    
    wb = xlwt.Workbook(encoding='utf-8')
    ws = wb.add_sheet('SMSC Responses')
    
    # Write header row
    row_num = 0
    if data:
        columns = list(data[0].keys())
        for col_num, column_title in enumerate(columns):
            ws.write(row_num, col_num, column_title)
        
        # Write data rows
        for item in data:
            row_num += 1
            for col_num, column_name in enumerate(columns):
                value = item[column_name]
                ws.write(row_num, col_num, str(value) if value is not None else '')
    
    wb.save(response)
    return response