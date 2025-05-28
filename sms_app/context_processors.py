from .utils import logger
import mysql.connector

def global_context(request):
    context = {
        'users': None
    }

    try:
        users = user_list()
        context['users'] = users
    except Exception as e:
        logger.error(f"UserAccess not found for user {e}")

    return context

def get_db_connection():
    """Establish database connection"""
    try:
        conn = mysql.connector.connect(
            host='localhost',
            port=3306,
            user='prashanth@itsolution4india.com',
            password='Solution@97',
            database='smsc_db'
        )
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        return None

def user_list():
    """View to display all usernames"""
    conn = get_db_connection()
    if not conn:
        logger.info('error Database connection failed')
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT DISTINCT username FROM smsc_responses WHERE username IS NOT NULL ORDER BY username")
        users = cursor.fetchall()
        return users
    except Exception as e:
        logger.error(f"Error fetching users: {e}")
    finally:
        if conn:
            conn.close()