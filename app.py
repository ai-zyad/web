"""
منصة تعليمية متكاملة - Flask Application
======================================
كود كامل في ملف واحد
المميزات:
- نظام تسجيل دخول قوي مع حماية
- تخزين JSON بدون قاعدة بيانات
- نظام جلسات متقدم
- حماية الفيديوهات
- لوحة تحكم أدمن كاملة
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort, make_response
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import json
import os
import uuid
import hashlib
import time
import re
import requests
from datetime import datetime, timedelta
from user_agents import parse 

app = Flask(__name__)

# ==================== إعدادات التطبيق ====================
try:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
except NameError:
    BASE_DIR = os.getcwd()
JSON_DIR = os.path.join(BASE_DIR, 'json_data')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
ALLOWED_EXTENSIONS = {'mp4', 'webm', 'ogg', 'mov'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max

# ==================== دوال المساعدة ====================
def load_json(filename):
    """تحميل ملف JSON"""
    filepath = os.path.join(JSON_DIR, filename)
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_json(filename, data):
    """حفظ ملف JSON"""
    filepath = os.path.join(JSON_DIR, filename)
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def get_config():
    """الحصول على الإعدادات"""
    return load_json('config.json')

def update_config(config):
    """تحديث الإعدادات"""
    save_json('config.json', config)

def get_users_data():
    """الحصول على بيانات المستخدمين"""
    return load_json('users.json')

def save_users_data(data):
    """حفظ بيانات المستخدمين"""
    save_json('users.json', data)

def get_courses_data():
    """الحصول على بيانات الكورسات"""
    return load_json('courses.json')

def save_courses_data(data):
    """حفظ بيانات الكورسات"""
    save_json('courses.json', data)

def allowed_file(filename):
    """التحقق من امتداد الملف المسموح"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_client_ip():
    """الحصول على IP العميل"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr

def get_country_from_ip(ip):
    """الحصول على الدولة من IP"""
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}?fields=status,country,countryCode', timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return {
                    'country': data.get('country', 'Unknown'),
                    'country_code': data.get('countryCode', 'XX')
                }
    except:
        pass
    return {'country': 'Unknown', 'country_code': 'XX'}

def get_device_info():
    """الحصول على معلومات الجهاز"""
    user_agent = request.headers.get('User-Agent', '')
    parsed = parse(user_agent)
    
    return {
        'browser': f"{parsed.browser.family} {parsed.browser.version_string}",
        'os': f"{parsed.os.family} {parsed.os.version_string}",
        'device': parsed.device.family,
        'is_mobile': parsed.is_mobile,
        'is_tablet': parsed.is_tablet,
        'is_pc': parsed.is_pc,
        'user_agent': user_agent
    }

def generate_session_token():
    """توليد توكن جلسة فريد"""
    return hashlib.sha256(f"{uuid.uuid4()}{time.time()}".encode()).hexdigest()

def hash_password(password):
    """تشفير كلمة المرور"""
    return generate_password_hash(password, method='scrypt')

def verify_password(password_hash, password):
    """التحقق من كلمة المرور"""
    return check_password_hash(password_hash, password)

def get_session_id():
    """الحصول على معرف الجلسة"""
    return session.get('session_token')

def is_valid_session():
    """التحقق من صلاحية الجلسة"""
    session_token = get_session_id()
    if not session_token:
        return False
    
    users_data = get_users_data()
    sessions = users_data.get('sessions', [])
    
    for s in sessions:
        if s['token'] == session_token and s['is_active']:
            # التحقق من انتهاء الصلاحية
            config = get_config()
            timeout = config.get('security', {}).get('session_timeout', 3600)
            last_activity = datetime.fromisoformat(s['last_activity'])
            if datetime.now() - last_activity > timedelta(seconds=timeout):
                s['is_active'] = False
                save_users_data(users_data)
                return False
            return True
    return False

def update_session_activity():
    """تحديث نشاط الجلسة"""
    session_token = get_session_id()
    if session_token:
        users_data = get_users_data()
        sessions = users_data.get('sessions', [])
        for s in sessions:
            if s['token'] == session_token:
                s['last_activity'] = datetime.now().isoformat()
                save_users_data(users_data)
                break

def get_current_user():
    """الحصول على المستخدم الحالي"""
    session_token = get_session_id()
    if not session_token:
        return None
    
    users_data = get_users_data()
    sessions = users_data.get('sessions', [])
    
    for s in sessions:
        if s['token'] == session_token and s['is_active']:
            users = users_data.get('users', [])
            for user in users:
                if user['id'] == s['user_id']:
                    return user
    return None

def is_admin():
    """التحقق إذا كان المستخدم أدمن"""
    user = get_current_user()
    return user and user.get('is_admin', False)

def is_enrolled(user_id, course_id):
    """التحقق من اشتراك المستخدم في الكورس"""
    courses_data = get_courses_data()
    enrollments = courses_data.get('enrollments', [])
    
    for e in enrollments:
        if e['user_id'] == user_id and e['course_id'] == course_id and e['is_active']:
            return True
    return False

def get_enrolled_courses(user_id):
    """الحصول على كورسات المشترك فيها المستخدم"""
    courses_data = get_courses_data()
    enrollments = courses_data.get('enrollments', [])
    courses = courses_data.get('courses', [])
    
    enrolled_course_ids = [e['course_id'] for e in enrollments if e['user_id'] == user_id and e['is_active']]
    return [c for c in courses if c['id'] in enrolled_course_ids]

def get_course_by_id(course_id):
    """الحصول على كورس بواسطة المعرف"""
    courses_data = get_courses_data()
    courses = courses_data.get('courses', [])
    
    for c in courses:
        if c['id'] == course_id:
            return c
    return None

def get_video_by_id(course_id, video_id):
    """الحصول على فيديو بواسطة المعرف"""
    course = get_course_by_id(course_id)
    if course:
        for section in course.get('sections', []):
            for video in section.get('videos', []):
                if video['id'] == video_id:
                    return video
    return None

def get_total_videos(course):
    """الحصول على عدد الفيديوهات في الكورس"""
    total = 0
    for section in course.get('sections', []):
        total += len(section.get('videos', []))
    return total

def get_total_duration(course):
    """الحصول على مدة الكورس الكلية"""
    total_minutes = 0
    for section in course.get('sections', []):
        for video in section.get('videos', []):
            duration = video.get('duration', '0:00')
            parts = duration.split(':')
            if len(parts) == 2:
                total_minutes += int(parts[0]) + int(parts[1]) / 60
    return f"{int(total_minutes)} ساعة {int((total_minutes % 1) * 60)} دقيقة"

def add_notification(user_id, title, message, notification_type='info'):
    """إضافة إشعار"""
    courses_data = get_courses_data()
    notifications = courses_data.get('notifications', [])
    
    notifications.append({
        'id': len(notifications) + 1,
        'user_id': user_id,
        'title': title,
        'message': message,
        'type': notification_type,
        'is_read': False,
        'created_at': datetime.now().isoformat()
    })
    
    courses_data['notifications'] = notifications
    save_courses_data(courses_data)

def get_notifications(user_id):
    """الحصول على إشعارات المستخدم"""
    courses_data = get_courses_data()
    notifications = courses_data.get('notifications', [])
    return [n for n in notifications if n['user_id'] == user_id]

def get_unread_notifications_count(user_id):
    """الحصول على عدد الإشعارات غير المقروءة"""
    notifications = get_notifications(user_id)
    return len([n for n in notifications if not n['is_read']])

def log_user_activity(user_id, action, details=None):
    """تسجيل نشاط المستخدم"""
    users_data = get_users_data()
    
    if 'activity_logs' not in users_data:
        users_data['activity_logs'] = []
    
    ip = get_client_ip()
    country_info = get_country_from_ip(ip)
    device_info = get_device_info()
    
    users_data['activity_logs'].append({
        'id': len(users_data['activity_logs']) + 1,
        'user_id': user_id,
        'action': action,
        'details': details or {},
        'ip': ip,
        'country': country_info['country'],
        'country_code': country_info['country_code'],
        'device_info': device_info,
        'timestamp': datetime.now().isoformat()
    })
    
    save_users_data(users_data)

def check_new_device_login(user_id):
    """التحقق من تسجيل دخول من جهاز جديد"""
    users_data = get_users_data()
    sessions = users_data.get('sessions', [])
    device_info = get_device_info()
    ip = get_client_ip()
    
    # البحث عن جلسات سابقة للمستخدم
    user_sessions = [s for s in sessions if s['user_id'] == user_id and s['is_active']]
    
    if user_sessions:
        # التحقق إذا كان الجهاز أو IP مختلف
        last_session = user_sessions[-1]
        if (last_session.get('device_info', {}).get('user_agent') != device_info['user_agent'] or
            last_session.get('ip') != ip):
            return True
    
    return False

def create_pending_session(user_id):
    """إنشاء جلسة معلقة للموافقة"""
    users_data = get_users_data()
    pending = users_data.get('pending_sessions', [])
    
    ip = get_client_ip()
    country_info = get_country_from_ip(ip)
    device_info = get_device_info()
    
    pending_session = {
        'id': len(pending) + 1,
        'user_id': user_id,
        'token': generate_session_token(),
        'ip': ip,
        'country': country_info['country'],
        'country_code': country_info['country_code'],
        'device_info': device_info,
        'status': 'pending',
        'created_at': datetime.now().isoformat()
    }
    
    pending.append(pending_session)
    users_data['pending_sessions'] = pending
    save_users_data(users_data)
    
    # إضافة إشعار للأدمن
    user = None
    for u in users_data.get('users', []):
        if u['id'] == user_id:
            user = u
            break
    
    if user:
        add_notification(
            1,  # Admin ID
            'طلب تسجيل دخول جديد',
            f"المستخدم {user['full_name']} ({user['username']}) يحاول تسجيل الدخول من جهاز/موقع جديد",
            'warning'
        )
    
    return pending_session

def approve_session(session_id, approved=True):
    """الموافقة أو رفض الجلسة"""
    users_data = get_users_data()
    pending = users_data.get('pending_sessions', [])
    
    for p in pending:
        if p['id'] == session_id:
            if approved:
                p['status'] = 'approved'
                # إنشاء جلسة نشطة
                sessions = users_data.get('sessions', [])
                sessions.append({
                    'id': len(sessions) + 1,
                    'user_id': p['user_id'],
                    'token': p['token'],
                    'ip': p['ip'],
                    'country': p['country'],
                    'country_code': p['country_code'],
                    'device_info': p['device_info'],
                    'is_active': True,
                    'created_at': datetime.now().isoformat(),
                    'last_activity': datetime.now().isoformat()
                })
                users_data['sessions'] = sessions
                
                # إضافة إشعار للمستخدم
                add_notification(
                    p['user_id'],
                    'تمت الموافقة على تسجيل الدخول',
                    'تمت الموافقة على طلب تسجيل الدخول من الجهاز الجديد',
                    'success'
                )
            else:
                p['status'] = 'rejected'
                # إضافة إشعار للمستخدم
                add_notification(
                    p['user_id'],
                    'تم رفض تسجيل الدخول',
                    'تم رفض طلب تسجيل الدخول من الجهاز الجديد. يرجى التواصل مع الدعم.',
                    'error'
                )
            
            save_users_data(users_data)
            return True
    
    return False

# ==================== Decorators ====================
def login_required(f):
    """تأكد من تسجيل الدخول"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_valid_session():
            flash('يرجى تسجيل الدخول أولاً', 'warning')
            return redirect(url_for('login'))
        update_session_activity()
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """تأكد من أن المستخدم أدمن"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_valid_session():
            flash('يرجى تسجيل الدخول أولاً', 'warning')
            return redirect(url_for('login'))
        if not is_admin():
            flash('غير مصرح لك بالوصول', 'error')
            return redirect(url_for('index'))
        update_session_activity()
        return f(*args, **kwargs)
    return decorated_function

# ==================== Routes ====================
@app.route('/')
def index():
    """الصفحة الرئيسية"""
    config = get_config()
    user = get_current_user()
    courses_data = get_courses_data()
    courses = courses_data.get('courses', [])
    
    enrolled_courses = []
    if user:
        enrolled_courses = get_enrolled_courses(user['id'])
    
    return render_template('index.html', 
                         config=config, 
                         user=user, 
                         courses=courses,
                         enrolled_courses=enrolled_courses,
                         is_enrolled=lambda c_id: is_enrolled(user['id'], c_id) if user else False)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """صفحة تسجيل الدخول"""
    if is_valid_session():
        return redirect(url_for('index'))
    
    config = get_config()
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('يرجى إدخال اسم المستخدم وكلمة المرور', 'error')
            return render_template('login.html', config=config)
        
        users_data = get_users_data()
        
        # التحقق من محاولات تسجيل الدخول
        ip = get_client_ip()
        attempts = users_data.get('login_attempts', {})
        
        if ip in attempts:
            last_attempt = attempts[ip]
            config_security = config.get('security', {})
            max_attempts = config_security.get('max_login_attempts', 5)
            lockout = config_security.get('lockout_duration', 900)
            
            if last_attempt['count'] >= max_attempts:
                last_time = datetime.fromisoformat(last_attempt['last_time'])
                if datetime.now() - last_time < timedelta(seconds=lockout):
                    remaining = lockout - (datetime.now() - last_time).seconds
                    flash(f'تم حظر تسجيل الدخول مؤقتاً. يرجى المحاولة بعد {remaining // 60} دقيقة', 'error')
                    return render_template('login.html', config=config)
                else:
                    attempts[ip] = {'count': 0, 'last_time': datetime.now().isoformat()}
        
        # البحث عن المستخدم
        users = users_data.get('users', [])
        user = None
        
        for u in users:
            if u['username'] == username:
                user = u
                break
        
        if not user:
            # التحقق من الأدمن الافتراضي
            if username == config.get('admin_username'):
                if verify_password(config.get('admin_password_hash'), password):
                    # إنشاء مستخدم أدمن إذا لم يكن موجوداً
                    user = {
                        'id': 1,
                        'username': config['admin_username'],
                        'full_name': 'المسؤول',
                        'email': config.get('admin_email', 'admin@platform.com'),
                        'password_hash': config['admin_password_hash'],
                        'is_admin': True,
                        'is_active': True,
                        'created_at': datetime.now().isoformat()
                    }
                    users.append(user)
                    users_data['users'] = users
                    save_users_data(users_data)
                else:
                    flash('اسم المستخدم أو كلمة المرور غير صحيحة', 'error')
                    return render_template('login.html', config=config)
            else:
                flash('اسم المستخدم أو كلمة المرور غير صحيحة', 'error')
                return render_template('login.html', config=config)
        
        # التحقق من كلمة المرور
        if not verify_password(user['password_hash'], password):
            # تسجيل المحاولة الفاشلة
            if ip not in attempts:
                attempts[ip] = {'count': 0, 'last_time': datetime.now().isoformat()}
            attempts[ip]['count'] += 1
            attempts[ip]['last_time'] = datetime.now().isoformat()
            users_data['login_attempts'] = attempts
            save_users_data(users_data)
            
            flash('اسم المستخدم أو كلمة المرور غير صحيحة', 'error')
            return render_template('login.html', config=config)
        
        # التحقق من تفعيل الحساب
        if not user.get('is_active', True):
            flash('الحساب غير مفعل. يرجى التواصل مع الدعم.', 'error')
            return render_template('login.html', config=config)
        
        # التحقق من الجهاز الجديد
        if check_new_device_login(user['id']):
            pending = create_pending_session(user['id'])
            flash('تم اكتشاف تسجيل دخول من جهاز/موقع جديد. في انتظار موافقة المسؤول.', 'info')
            return render_template('pending_approval.html', config=config, pending_id=pending['id'])
        
        # إنشاء جلسة جديدة
        session_token = generate_session_token()
        sessions = users_data.get('sessions', [])
        
        ip = get_client_ip()
        country_info = get_country_from_ip(ip)
        device_info = get_device_info()
        
        sessions.append({
            'id': len(sessions) + 1,
            'user_id': user['id'],
            'token': session_token,
            'ip': ip,
            'country': country_info['country'],
            'country_code': country_info['country_code'],
            'device_info': device_info,
            'is_active': True,
            'created_at': datetime.now().isoformat(),
            'last_activity': datetime.now().isoformat()
        })
        
        users_data['sessions'] = sessions
        save_users_data(users_data)
        
        # تعيين الجلسة
        session['session_token'] = session_token
        session.permanent = True
        
        # تسجيل النشاط
        log_user_activity(user['id'], 'login', {'method': 'password'})
        
        # إعادة تعيين محاولات تسجيل الدخول
        if ip in attempts:
            attempts[ip]['count'] = 0
            users_data['login_attempts'] = attempts
            save_users_data(users_data)
        
        flash(f'مرحباً {user["full_name"]}!', 'success')
        
        if user.get('is_admin'):
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('index'))
    
    return render_template('login.html', config=config)

@app.route('/logout')
def logout():
    """تسجيل الخروج"""
    session_token = get_session_id()
    if session_token:
        users_data = get_users_data()
        sessions = users_data.get('sessions', [])
        
        for s in sessions:
            if s['token'] == session_token:
                s['is_active'] = False
                log_user_activity(s['user_id'], 'logout')
                break
        
        save_users_data(users_data)
    
    session.clear()
    flash('تم تسجيل الخروج بنجاح', 'success')
    return redirect(url_for('login'))

@app.route('/course/<int:course_id>')
@login_required
def course_detail(course_id):
    """صفحة تفاصيل الكورس"""
    user = get_current_user()
    course = get_course_by_id(course_id)
    
    if not course:
        flash('الكورس غير موجود', 'error')
        return redirect(url_for('index'))
    
    enrolled = is_enrolled(user['id'], course_id)
    
    if enrolled or course.get('is_public', False):
        # عرض صفحة المشاهدة
        return render_template('course_player.html', 
                             course=course, 
                             user=user,
                             config=get_config())
    else:
        # عرض صفحة الشراء
        total_videos = get_total_videos(course)
        return render_template('course_purchase.html',
                             course=course,
                             user=user,
                             config=get_config(),
                             total_videos=total_videos,
                             telegram_link=get_config().get('telegram_link', '#'))

@app.route('/course/<int:course_id>/watch/<int:video_id>')
@login_required
def watch_video(course_id, video_id):
    """صفحة مشاهدة الفيديو"""
    user = get_current_user()
    course = get_course_by_id(course_id)
    video = get_video_by_id(course_id, video_id)
    
    if not course or not video:
        flash('الفيديو غير موجود', 'error')
        return redirect(url_for('index'))
    
    enrolled = is_enrolled(user['id'], course_id)
    
    if not enrolled and not video.get('is_public', False) and not course.get('is_public', False):
        flash('يجب شراء الكورس أولاً', 'warning')
        return redirect(url_for('course_detail', course_id=course_id))
    
    return render_template('video_player.html',
                         course=course,
                         video=video,
                         user=user,
                         config=get_config())

@app.route('/notifications')
@login_required
def notifications():
    """صفحة الإشعارات"""
    user = get_current_user()
    user_notifications = get_notifications(user['id'])
    
    # تحديث حالة القراءة
    courses_data = get_courses_data()
    all_notifications = courses_data.get('notifications', [])
    
    for n in all_notifications:
        if n['user_id'] == user['id'] and not n['is_read']:
            n['is_read'] = True
    
    save_courses_data(courses_data)
    
    return render_template('notifications.html',
                         notifications=user_notifications,
                         user=user,
                         config=get_config())

# ==================== Admin Routes ====================
@app.route('/admin')
@admin_required
def admin_dashboard():
    """لوحة تحكم الأدمن"""
    user = get_current_user()
    users_data = get_users_data()
    courses_data = get_courses_data()
    
    # إحصائيات
    total_users = len(users_data.get('users', []))
    total_courses = len(courses_data.get('courses', []))
    total_enrollments = len(courses_data.get('enrollments', []))
    
    # إحصائيات الكورسات
    course_stats = []
    for course in courses_data.get('courses', []):
        enrolled_count = len([e for e in courses_data.get('enrollments', []) 
                             if e['course_id'] == course['id'] and e['is_active']])
        course_stats.append({
            'course': course,
            'enrolled_count': enrolled_count
        })
    
    # النشاطات الأخيرة
    activity_logs = users_data.get('activity_logs', [])[-20:]
    activity_logs.reverse()
    
    # الجلسات المعلقة
    pending_sessions = users_data.get('pending_sessions', [])
    pending_sessions = [p for p in pending_sessions if p['status'] == 'pending']
    
    # إشعارات الأدمن
    admin_notifications = get_notifications(1)
    
    return render_template('admin/dashboard.html',
                         user=user,
                         config=get_config(),
                         stats={
                             'total_users': total_users,
                             'total_courses': total_courses,
                             'total_enrollments': total_enrollments
                         },
                         course_stats=course_stats,
                         activity_logs=activity_logs,
                         pending_sessions=pending_sessions,
                         notifications=admin_notifications,
                         unread_count=get_unread_notifications_count(1))

@app.route('/admin/users')
@admin_required
def admin_users():
    """إدارة المستخدمين"""
    user = get_current_user()
    users_data = get_users_data()
    users = users_data.get('users', [])
    
    return render_template('admin/users.html',
                         user=user,
                         config=get_config(),
                         users=users)

@app.route('/admin/users/create', methods=['POST'])
@admin_required
def admin_create_user():
    """إنشاء مستخدم جديد"""
    username = request.form.get('username', '').strip()
    full_name = request.form.get('full_name', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '')
    is_admin = request.form.get('is_admin') == 'on'
    
    if not all([username, full_name, email, password]):
        flash('جميع الحقول مطلوبة', 'error')
        return redirect(url_for('admin_users'))
    
    users_data = get_users_data()
    users = users_data.get('users', [])
    
    # التحقق من عدم التكرار
    for u in users:
        if u['username'] == username:
            flash('اسم المستخدم موجود مسبقاً', 'error')
            return redirect(url_for('admin_users'))
        if u['email'] == email:
            flash('البريد الإلكتروني موجود مسبقاً', 'error')
            return redirect(url_for('admin_users'))
    
    new_user = {
        'id': len(users) + 1,
        'username': username,
        'full_name': full_name,
        'email': email,
        'password_hash': hash_password(password),
        'is_admin': is_admin,
        'is_active': True,
        'created_at': datetime.now().isoformat()
    }
    
    users.append(new_user)
    users_data['users'] = users
    save_users_data(users_data)
    
    flash('تم إنشاء المستخدم بنجاح', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/toggle/<int:user_id>')
@admin_required
def admin_toggle_user(user_id):
    """تفعيل/تعطيل مستخدم"""
    users_data = get_users_data()
    users = users_data.get('users', [])
    
    for u in users:
        if u['id'] == user_id:
            u['is_active'] = not u.get('is_active', True)
            status = 'تفعيل' if u['is_active'] else 'تعطيل'
            flash(f'تم {status} المستخدم بنجاح', 'success')
            break
    
    users_data['users'] = users
    save_users_data(users_data)
    return redirect(url_for('admin_users'))

@app.route('/admin/courses')
@admin_required
def admin_courses():
    """إدارة الكورسات"""
    user = get_current_user()
    courses_data = get_courses_data()
    courses = courses_data.get('courses', [])
    
    return render_template('admin/courses.html',
                         user=user,
                         config=get_config(),
                         courses=courses)

@app.route('/admin/courses/create', methods=['POST'])
@admin_required
def admin_create_course():
    """إنشاء كورس جديد"""
    title = request.form.get('title', '').strip()
    description = request.form.get('description', '').strip()
    price = float(request.form.get('price', 0))
    is_public = request.form.get('is_public') == 'on'
    
    if not title:
        flash('عنوان الكورس مطلوب', 'error')
        return redirect(url_for('admin_courses'))
    
    courses_data = get_courses_data()
    courses = courses_data.get('courses', [])
    
    # معالجة الصورة
    image_url = request.form.get('image_url', '').strip()
    if not image_url:
        image_url = 'https://images.unsplash.com/photo-1516321318423-f06f85e504b3?w=600'
    
    new_course = {
        'id': len(courses) + 1,
        'title': title,
        'description': description,
        'image': image_url,
        'price': price,
        'currency': 'USD',
        'is_public': is_public,
        'created_at': datetime.now().isoformat(),
        'sections': []
    }
    
    courses.append(new_course)
    courses_data['courses'] = courses
    save_courses_data(courses_data)
    
    flash('تم إنشاء الكورس بنجاح', 'success')
    return redirect(url_for('admin_courses'))

@app.route('/admin/courses/edit/<int:course_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_course(course_id):
    """تعديل كورس"""
    user = get_current_user()
    courses_data = get_courses_data()
    course = get_course_by_id(course_id)
    
    if not course:
        flash('الكورس غير موجود', 'error')
        return redirect(url_for('admin_courses'))
    
    if request.method == 'POST':
        course['title'] = request.form.get('title', '').strip()
        course['description'] = request.form.get('description', '').strip()
        course['price'] = float(request.form.get('price', 0))
        course['is_public'] = request.form.get('is_public') == 'on'
        
        image_url = request.form.get('image_url', '').strip()
        if image_url:
            course['image'] = image_url
        
        save_courses_data(courses_data)
        flash('تم تحديث الكورس بنجاح', 'success')
        return redirect(url_for('admin_courses'))
    
    return render_template('admin/edit_course.html',
                         user=user,
                         config=get_config(),
                         course=course)

@app.route('/admin/courses/<int:course_id>/sections/add', methods=['POST'])
@admin_required
def admin_add_section(course_id):
    """إضافة قسم للكورس"""
    title = request.form.get('title', '').strip()
    
    if not title:
        flash('عنوان القسم مطلوب', 'error')
        return redirect(url_for('admin_edit_course', course_id=course_id))
    
    courses_data = get_courses_data()
    course = get_course_by_id(course_id)
    
    if course:
        sections = course.get('sections', [])
        sections.append({
            'id': len(sections) + 1,
            'title': title,
            'videos': []
        })
        course['sections'] = sections
        save_courses_data(courses_data)
        flash('تم إضافة القسم بنجاح', 'success')
    
    return redirect(url_for('admin_edit_course', course_id=course_id))

@app.route('/admin/courses/<int:course_id>/sections/<int:section_id>/videos/add', methods=['POST'])
@admin_required
def admin_add_video(course_id, section_id):
    """إضافة فيديو للقسم"""
    title = request.form.get('title', '').strip()
    duration = request.form.get('duration', '').strip()
    video_url = request.form.get('video_url', '').strip()
    is_public = request.form.get('is_public') == 'on'
    
    if not title:
        flash('عنوان الفيديو مطلوب', 'error')
        return redirect(url_for('admin_edit_course', course_id=course_id))
    
    courses_data = get_courses_data()
    course = get_course_by_id(course_id)
    
    if course:
        for section in course.get('sections', []):
            if section['id'] == section_id:
                videos = section.get('videos', [])
                videos.append({
                    'id': len(videos) + 1,
                    'title': title,
                    'duration': duration or '0:00',
                    'video_url': video_url,
                    'is_public': is_public
                })
                section['videos'] = videos
                save_courses_data(courses_data)
                flash('تم إضافة الفيديو بنجاح', 'success')
                break
    
    return redirect(url_for('admin_edit_course', course_id=course_id))

@app.route('/admin/enrollments')
@admin_required
def admin_enrollments():
    """إدارة الاشتراكات"""
    user = get_current_user()
    courses_data = get_courses_data()
    users_data = get_users_data()
    
    enrollments = courses_data.get('enrollments', [])
    users = {u['id']: u for u in users_data.get('users', [])}
    courses = {c['id']: c for c in courses_data.get('courses', [])}
    
    return render_template('admin/enrollments.html',
                         user=user,
                         config=get_config(),
                         enrollments=enrollments,
                         users=users,
                         courses=courses)

@app.route('/admin/enrollments/add', methods=['POST'])
@admin_required
def admin_add_enrollment():
    """إضافة اشتراك"""
    user_id = int(request.form.get('user_id', 0))
    course_id = int(request.form.get('course_id', 0))
    
    courses_data = get_courses_data()
    enrollments = courses_data.get('enrollments', [])
    
    # التحقق من عدم وجود الاشتراك مسبقاً
    for e in enrollments:
        if e['user_id'] == user_id and e['course_id'] == course_id:
            flash('المستخدم مشترك في هذا الكورس مسبقاً', 'warning')
            return redirect(url_for('admin_enrollments'))
    
    enrollments.append({
        'id': len(enrollments) + 1,
        'user_id': user_id,
        'course_id': course_id,
        'is_active': True,
        'created_at': datetime.now().isoformat()
    })
    
    courses_data['enrollments'] = enrollments
    save_courses_data(courses_data)
    
    # إضافة إشعار للمستخدم
    add_notification(
        user_id,
        'تم تفعيل الكورس',
        'تم تفعيل اشتراكك في الكورس بنجاح',
        'success'
    )
    
    flash('تم إضافة الاشتراك بنجاح', 'success')
    return redirect(url_for('admin_enrollments'))

@app.route('/admin/sessions/approve/<int:session_id>')
@admin_required
def admin_approve_session(session_id):
    """الموافقة على جلسة"""
    if approve_session(session_id, True):
        flash('تمت الموافقة على الجلسة بنجاح', 'success')
    else:
        flash('الجلسة غير موجودة', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/sessions/reject/<int:session_id>')
@admin_required
def admin_reject_session(session_id):
    """رفض جلسة"""
    if approve_session(session_id, False):
        flash('تم رفض الجلسة بنجاح', 'success')
    else:
        flash('الجلسة غير موجودة', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/send-notification', methods=['POST'])
@admin_required
def admin_send_notification():
    """إرسال إشعار"""
    user_id = request.form.get('user_id')
    title = request.form.get('title', '').strip()
    message = request.form.get('message', '').strip()
    notification_type = request.form.get('type', 'info')
    
    if not title or not message:
        flash('العنوان والرسالة مطلوبان', 'error')
        return redirect(url_for('admin_dashboard'))
    
    if user_id == 'all':
        # إرسال للجميع
        users_data = get_users_data()
        for u in users_data.get('users', []):
            add_notification(u['id'], title, message, notification_type)
        flash('تم إرسال الإشعار للجميع بنجاح', 'success')
    else:
        add_notification(int(user_id), title, message, notification_type)
        flash('تم إرسال الإشعار بنجاح', 'success')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/video/make-public/<int:course_id>/<int:video_id>')
@admin_required
def admin_make_video_public(course_id, video_id):
    """جعل الفيديو عاماً"""
    courses_data = get_courses_data()
    video = get_video_by_id(course_id, video_id)
    
    if video:
        video['is_public'] = not video.get('is_public', False)
        save_courses_data(courses_data)
        status = 'عام' if video['is_public'] else 'خاص'
        flash(f'تم جعل الفيديو {status} بنجاح', 'success')
    
    return redirect(url_for('admin_edit_course', course_id=course_id))

# ==================== API Routes ====================
@app.route('/api/check-session-status/<int:pending_id>')
def check_session_status(pending_id):
    """التحقق من حالة الجلسة المعلقة"""
    users_data = get_users_data()
    pending = users_data.get('pending_sessions', [])
    
    for p in pending:
        if p['id'] == pending_id:
            return jsonify({'status': p['status'], 'token': p.get('token') if p['status'] == 'approved' else None})
    
    return jsonify({'status': 'not_found'})

@app.route('/api/notifications/unread-count')
@login_required
def api_unread_count():
    """الحصول على عدد الإشعارات غير المقروءة"""
    user = get_current_user()
    count = get_unread_notifications_count(user['id'])
    return jsonify({'count': count})

@app.route('/api/video/protect', methods=['POST'])
@login_required
def protect_video():
    """حماية الفيديو - التحقق من الصلاحية"""
    video_url = request.json.get('video_url', '')
    course_id = request.json.get('course_id', 0)
    
    user = get_current_user()
    
    if is_admin() or is_enrolled(user['id'], course_id):
        return jsonify({'allowed': True, 'url': video_url})
    
    return jsonify({'allowed': False, 'message': 'غير مصرح بالوصول'}), 403

# ==================== Error Handlers ====================
@app.errorhandler(404)
def not_found(e):
    return render_template('errors/404.html', config=get_config()), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('errors/500.html', config=get_config()), 500

# ==================== Initialize ====================
def init_app():
    """تهيئة التطبيق"""
    config = get_config()
    app.secret_key = config.get('security', {}).get('secret_key', 'dev_key_change_in_production')
    
    # إنشاء المجلدات
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(JSON_DIR, exist_ok=True)
    
    # التأكد من وجود ملفات JSON
    if not os.path.exists(os.path.join(JSON_DIR, 'config.json')):
        default_config = {
            "site_name": "منصتي التعليمية",
            "site_logo": "",
            "admin_username": "admin",
            "admin_password_hash": generate_password_hash("admin123", method='scrypt'),
            "admin_email": "admin@platform.com",
            "telegram_link": "https://t.me/your_channel",
            "colors": {
                "primary": "#10b981",
                "secondary": "#0ea5e9",
                "accent": "#06b6d4"
            },
            "security": {
                "secret_key": "super_secret_key_change_this_in_production_2024",
                "session_timeout": 3600,
                "max_login_attempts": 5,
                "lockout_duration": 900
            }
        }
        save_json('config.json', default_config)
    
    if not os.path.exists(os.path.join(JSON_DIR, 'users.json')):
        save_json('users.json', {"users": [], "sessions": [], "login_attempts": {}, "pending_sessions": [], "activity_logs": []})
    
    if not os.path.exists(os.path.join(JSON_DIR, 'courses.json')):
        save_json('courses.json', {"courses": [], "enrollments": [], "notifications": []})

# ==================== Main ====================
if __name__ == '__main__':
    init_app()
    app.run(debug=True, host='0.0.0.0', port=5000)
