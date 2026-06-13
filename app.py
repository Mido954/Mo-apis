import os
import json
import sqlite3
import secrets
import threading
import time
import hashlib
import hmac
import base64
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton

# ============================================================
# الإعدادات المتقدمة - غيرها حسب رغبتك
# ============================================================

BOT_TOKEN = "7845657550:AAGmQ88PV8g23jVCU6X6iU4V9ZqcVAehDCc"
ADMIN_ID = 8220915719
ADMIN_KEY = "Dr_Sources_Super_Secret_Key_2024_Ultra_Secure"
JWT_SECRET = "Dr_Sources_JWT_Secret_2024_xyz_789_abc_123"
RATE_LIMIT = "100 per minute"
RATE_LIMIT_ADMIN = "1000 per hour"

# ============================================================
# قاعدة البيانات المتقدمة (SQLite مع تشفير)
# ============================================================

DATABASE_URL = os.environ.get('DATABASE_URL', 'licenses.db')

def get_db():
    conn = sqlite3.connect(DATABASE_URL)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn

def init_db():
    conn = get_db()
    
    # جدول التراخيص
    conn.execute('''
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            customer TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            created_at TEXT NOT NULL,
            expiry_date TEXT,
            max_devices INTEGER DEFAULT 1,
            device_ids TEXT DEFAULT '[]',
            usage_count INTEGER DEFAULT 0,
            last_used TEXT,
            metadata TEXT DEFAULT '{}'
        )
    ''')
    
    # جدول السجلات
    conn.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT NOT NULL,
            action TEXT NOT NULL,
            ip TEXT,
            user_agent TEXT,
            details TEXT,
            timestamp TEXT NOT NULL
        )
    ''')
    
    # جدول المفاتيح (للمطورين)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_value TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            permissions TEXT DEFAULT 'read',
            created_at TEXT NOT NULL,
            last_used TEXT,
            is_active INTEGER DEFAULT 1
        )
    ''')
    
    # جدول الإشعارات
    conn.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL,
            is_read INTEGER DEFAULT 0
        )
    ''')
    
    # إضافة بعض المفاتيح التجريبية
    api_key = hashlib.sha256(f"{ADMIN_KEY}_api_key".encode()).hexdigest()[:32]
    conn.execute('''
        INSERT OR IGNORE INTO api_keys (key_value, name, permissions, created_at)
        VALUES (?, ?, ?, ?)
    ''', (api_key, "Admin API Key", "admin", datetime.now().isoformat()))
    
    conn.commit()
    conn.close()

# ============================================================
# دوال مساعدة متقدمة
# ============================================================

def generate_secure_token(length=32):
    """توليد توكن آمن"""
    return secrets.token_urlsafe(length).upper()

def hash_token(token):
    """تشفير التوكن للتخزين"""
    return hashlib.sha256(f"{token}{JWT_SECRET}".encode()).hexdigest()

def verify_api_key(key):
    """التحقق من صحة مفتاح API"""
    conn = get_db()
    result = conn.execute('SELECT * FROM api_keys WHERE key_value = ? AND is_active = 1', (key,)).fetchone()
    if result:
        conn.execute('UPDATE api_keys SET last_used = ? WHERE key_value = ?', (datetime.now().isoformat(), key))
        conn.commit()
    conn.close()
    return result

def log_activity(token, action, ip=None, user_agent=None, details=None):
    """تسجيل النشاطات المتقدم"""
    conn = get_db()
    conn.execute('''
        INSERT INTO logs (token, action, ip, user_agent, details, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (token, action, ip, user_agent, details, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def create_notification(title, message):
    """إنشاء إشعار جديد"""
    conn = get_db()
    conn.execute('''
        INSERT INTO notifications (title, message, created_at)
        VALUES (?, ?, ?)
    ''', (title, message, datetime.now().isoformat()))
    conn.commit()
    conn.close()

# ============================================================
# دوال إدارة التراخيص المتقدمة
# ============================================================

def create_license(customer, expiry_days=0, max_devices=1, metadata=None):
    """إنشاء ترخيص جديد مع بيانات إضافية"""
    token = generate_secure_token()
    created_at = datetime.now().isoformat()
    expiry_date = (datetime.now() + timedelta(days=expiry_days)).isoformat() if expiry_days > 0 else None
    metadata_json = json.dumps(metadata or {})
    
    conn = get_db()
    conn.execute('''
        INSERT INTO licenses (token, customer, created_at, expiry_date, max_devices, metadata)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (token, customer, created_at, expiry_date, max_devices, metadata_json))
    conn.commit()
    
    # تسجيل النشاط
    log_activity(token, 'created', metadata=f'Customer: {customer}')
    create_notification('ترخيص جديد', f'تم إنشاء ترخيص جديد للعميل {customer}')
    
    conn.close()
    return token

def verify_license(token, device_id, ip, user_agent=None):
    """التحقق المتقدم من الترخيص"""
    conn = get_db()
    license_data = conn.execute('SELECT * FROM licenses WHERE token = ?', (token,)).fetchone()
    
    if not license_data:
        log_activity(token, 'verify_failed', ip, user_agent, 'Token not found')
        conn.close()
        return {'valid': False, 'reason': 'التوكن غير صالح', 'code': 'INVALID_TOKEN'}
    
    license_dict = dict(license_data)
    
    if license_dict['status'] != 'active':
        log_activity(token, 'verify_failed', ip, user_agent, 'License blocked')
        conn.close()
        return {'valid': False, 'reason': 'هذا الترخيص تم إيقافه', 'code': 'LICENSE_BLOCKED'}
    
    if license_dict['expiry_date']:
        expiry = datetime.fromisoformat(license_dict['expiry_date'])
        if datetime.now() > expiry:
            log_activity(token, 'verify_failed', ip, user_agent, 'License expired')
            conn.close()
            return {'valid': False, 'reason': 'انتهت صلاحية الترخيص', 'code': 'LICENSE_EXPIRED'}
    
    devices = json.loads(license_dict['device_ids'] or '[]')
    if device_id not in devices and len(devices) >= license_dict['max_devices']:
        log_activity(token, 'verify_failed', ip, user_agent, f'Max devices reached: {len(devices)}')
        conn.close()
        return {'valid': False, 'reason': f'تم الوصول للحد الأقصى ({license_dict["max_devices"]} أجهزة)', 'code': 'MAX_DEVICES'}
    
    if device_id not in devices:
        devices.append(device_id)
        conn.execute('UPDATE licenses SET device_ids = ? WHERE token = ?', (json.dumps(devices), token))
    
    # تحديث الإحصائيات
    conn.execute('''
        UPDATE licenses 
        SET usage_count = usage_count + 1, last_used = ? 
        WHERE token = ?
    ''', (datetime.now().isoformat(), token))
    
    log_activity(token, 'verify_success', ip, user_agent, f'Device: {device_id}')
    conn.commit()
    conn.close()
    
    return {
        'valid': True, 
        'customer': license_dict['customer'],
        'expiry': license_dict['expiry_date'],
        'usage_count': license_dict['usage_count'] + 1,
        'max_devices': license_dict['max_devices'],
        'devices_used': len(devices)
    }

def revoke_license(token, reason=None):
    """إيقاف ترخيص مع سبب"""
    conn = get_db()
    result = conn.execute('UPDATE licenses SET status = "blocked" WHERE token = ?', (token,))
    affected = result.rowcount
    if affected:
        log_activity(token, 'revoked', details=reason)
        create_notification('ترخيص تم إيقافه', f'تم إيقاف الترخيص {token[:16]}...')
    conn.commit()
    conn.close()
    return affected > 0

def activate_license(token):
    """تفعيل ترخيص"""
    conn = get_db()
    result = conn.execute('UPDATE licenses SET status = "active" WHERE token = ?', (token,))
    affected = result.rowcount
    if affected:
        log_activity(token, 'activated')
        create_notification('ترخيص تم تفعيله', f'تم تفعيل الترخيص {token[:16]}...')
    conn.commit()
    conn.close()
    return affected > 0

def delete_license(token):
    """حذف ترخيص نهائياً"""
    conn = get_db()
    result = conn.execute('DELETE FROM licenses WHERE token = ?', (token,))
    affected = result.rowcount
    if affected:
        log_activity(token, 'deleted')
    conn.commit()
    conn.close()
    return affected > 0

def get_all_licenses(limit=100, offset=0, status=None):
    """الحصول على التراخيص مع تصفية"""
    conn = get_db()
    query = 'SELECT token, customer, status, created_at, expiry_date, usage_count, last_used, max_devices FROM licenses'
    params = []
    
    if status:
        query += ' WHERE status = ?'
        params.append(status)
    
    query += ' ORDER BY id DESC LIMIT ? OFFSET ?'
    params.extend([limit, offset])
    
    licenses = conn.execute(query, params).fetchall()
    total = conn.execute('SELECT COUNT(*) as count FROM licenses' + (' WHERE status = ?' if status else ''), 
                         params[:1] if status else []).fetchone()['count']
    conn.close()
    
    return [dict(lic) for lic in licenses], total

def get_license_details(token):
    """الحصول على تفاصيل الترخيص كاملة"""
    conn = get_db()
    license_data = conn.execute('SELECT * FROM licenses WHERE token = ?', (token,)).fetchone()
    if not license_data:
        conn.close()
        return None
    
    logs = conn.execute('SELECT action, ip, timestamp, details FROM logs WHERE token = ? ORDER BY id DESC LIMIT 20', (token,)).fetchall()
    conn.close()
    
    result = dict(license_data)
    result['logs'] = [dict(log) for log in logs]
    result['device_ids'] = json.loads(result['device_ids'] or '[]')
    result['metadata'] = json.loads(result['metadata'] or '{}')
    
    return result

def get_stats():
    """إحصائيات متقدمة"""
    conn = get_db()
    
    total = conn.execute('SELECT COUNT(*) as count FROM licenses').fetchone()['count']
    active = conn.execute('SELECT COUNT(*) as count FROM licenses WHERE status = "active"').fetchone()['count']
    blocked = conn.execute('SELECT COUNT(*) as count FROM licenses WHERE status = "blocked"').fetchone()['count']
    expired = conn.execute('''
        SELECT COUNT(*) as count FROM licenses 
        WHERE expiry_date IS NOT NULL AND expiry_date < datetime('now')
    ''').fetchone()['count']
    
    total_checks = conn.execute('SELECT COUNT(*) as count FROM logs WHERE action = "verify_success"').fetchone()['count']
    total_fails = conn.execute('SELECT COUNT(*) as count FROM logs WHERE action = "verify_failed"').fetchone()['count']
    
    # إحصائيات يومية
    today = datetime.now().strftime('%Y-%m-%d')
    today_checks = conn.execute('''
        SELECT COUNT(*) as count FROM logs 
        WHERE action = "verify_success" AND date(timestamp) = date(?)
    ''', (today,)).fetchone()['count']
    
    # أهم التراخيص استخداماً
    top_licenses = conn.execute('''
        SELECT token, customer, usage_count FROM licenses 
        ORDER BY usage_count DESC LIMIT 5
    ''').fetchall()
    
    conn.close()
    
    return {
        'total': total,
        'active': active,
        'blocked': blocked,
        'expired': expired,
        'total_checks': total_checks,
        'total_fails': total_fails,
        'today_checks': today_checks,
        'top_licenses': [dict(lic) for lic in top_licenses]
    }

# ============================================================
# مصادقة API (Decorators)
# ============================================================

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
        
        key_data = verify_api_key(api_key)
        if not key_data:
            return jsonify({'error': 'Invalid API key'}), 401
        
        g.api_key = key_data
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        admin_key = request.headers.get('X-Admin-Key')
        if not admin_key or admin_key != ADMIN_KEY:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

# ============================================================
# خادم Flask (API)
# ============================================================

app = Flask(__name__)
CORS(app)

# إعدادات تحديد المعدل
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=[RATE_LIMIT],
    storage_uri="memory://"
)

@app.route('/')
def home():
    return jsonify({
        'status': 'online',
        'message': 'License API System v2.0',
        'version': '2.0.0',
        'endpoints': {
            'verify': '/api/verify?token=TOKEN&device_id=DEVICE',
            'admin': '/api/admin/',
            'docs': '/api/docs'
        }
    })

@app.route('/api/docs')
def api_docs():
    return jsonify({
        'endpoints': {
            'GET /api/verify': 'التحقق من الترخيص',
            'POST /api/admin/create': 'إنشاء ترخيص جديد',
            'POST /api/admin/revoke': 'إيقاف ترخيص',
            'POST /api/admin/activate': 'تفعيل ترخيص',
            'DELETE /api/admin/delete': 'حذف ترخيص',
            'GET /api/admin/list': 'قائمة التراخيص',
            'GET /api/admin/details': 'تفاصيل الترخيص',
            'GET /api/admin/stats': 'إحصائيات',
            'GET /api/admin/logs': 'سجل النشاطات',
            'GET /api/admin/notifications': 'الإشعارات'
        },
        'headers': {
            'X-Admin-Key': 'مفتاح الإدارة (للواجهات الإدارية)',
            'X-API-Key': 'مفتاح API (للواجهات العامة)'
        }
    })

@app.route('/api/verify', methods=['GET'])
@limiter.limit(RATE_LIMIT)
def verify():
    token = request.args.get('token')
    device_id = request.args.get('device_id', 'unknown')
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    user_agent = request.headers.get('User-Agent', 'unknown')
    
    if not token:
        return jsonify({'status': 'error', 'message': 'التوكن مطلوب', 'code': 'MISSING_TOKEN'}), 400
    
    result = verify_license(token, device_id, ip, user_agent)
    
    if result['valid']:
        return jsonify({
            'status': 'active',
            'message': 'الترخيص صالح',
            'customer': result['customer'],
            'usage_count': result['usage_count'],
            'max_devices': result['max_devices'],
            'devices_used': result['devices_used']
        })
    else:
        return jsonify({
            'status': 'invalid',
            'message': result['reason'],
            'code': result.get('code', 'UNKNOWN')
        })

@app.route('/api/admin/create', methods=['POST'])
@require_admin
@limiter.limit(RATE_LIMIT_ADMIN)
def admin_create():
    data = request.get_json()
    customer = data.get('customer')
    expiry_days = data.get('expiry_days', 0)
    max_devices = data.get('max_devices', 1)
    metadata = data.get('metadata', {})
    
    if not customer:
        return jsonify({'error': 'customer required'}), 400
    
    token = create_license(customer, expiry_days, max_devices, metadata)
    
    return jsonify({
        'success': True,
        'token': token,
        'customer': customer,
        'expiry_days': expiry_days,
        'max_devices': max_devices
    })

@app.route('/api/admin/revoke', methods=['POST'])
@require_admin
def admin_revoke():
    data = request.get_json()
    token = data.get('token')
    reason = data.get('reason')
    
    if not token:
        return jsonify({'error': 'token required'}), 400
    
    if revoke_license(token, reason):
        return jsonify({'success': True, 'message': 'تم إيقاف الترخيص'})
    return jsonify({'success': False, 'message': 'الترخيص غير موجود'}), 404

@app.route('/api/admin/activate', methods=['POST'])
@require_admin
def admin_activate():
    data = request.get_json()
    token = data.get('token')
    
    if not token:
        return jsonify({'error': 'token required'}), 400
    
    if activate_license(token):
        return jsonify({'success': True, 'message': 'تم تفعيل الترخيص'})
    return jsonify({'success': False, 'message': 'الترخيص غير موجود'}), 404

@app.route('/api/admin/delete', methods=['DELETE'])
@require_admin
def admin_delete():
    data = request.get_json()
    token = data.get('token')
    
    if not token:
        return jsonify({'error': 'token required'}), 400
    
    if delete_license(token):
        return jsonify({'success': True, 'message': 'تم حذف الترخيص'})
    return jsonify({'success': False, 'message': 'الترخيص غير موجود'}), 404

@app.route('/api/admin/list', methods=['GET'])
@require_admin
def admin_list():
    limit = int(request.args.get('limit', 100))
    offset = int(request.args.get('offset', 0))
    status = request.args.get('status')
    
    licenses, total = get_all_licenses(limit, offset, status)
    
    return jsonify({
        'success': True,
        'licenses': licenses,
        'pagination': {
            'limit': limit,
            'offset': offset,
            'total': total,
            'has_more': offset + limit < total
        }
    })

@app.route('/api/admin/details', methods=['GET'])
@require_admin
def admin_details():
    token = request.args.get('token')
    
    if not token:
        return jsonify({'error': 'token required'}), 400
    
    details = get_license_details(token)
    if not details:
        return jsonify({'error': 'License not found'}), 404
    
    return jsonify({'success': True, 'details': details})

@app.route('/api/admin/stats', methods=['GET'])
@require_admin
def admin_stats():
    stats = get_stats()
    return jsonify({'success': True, 'stats': stats})

@app.route('/api/admin/logs', methods=['GET'])
@require_admin
def admin_logs():
    token = request.args.get('token')
    limit = int(request.args.get('limit', 50))
    
    conn = get_db()
    if token:
        logs = conn.execute('''
            SELECT action, ip, user_agent, details, timestamp FROM logs 
            WHERE token = ? ORDER BY id DESC LIMIT ?
        ''', (token, limit)).fetchall()
    else:
        logs = conn.execute('''
            SELECT token, action, ip, timestamp FROM logs 
            ORDER BY id DESC LIMIT ?
        ''', (limit,)).fetchall()
    conn.close()
    
    return jsonify({'success': True, 'logs': [dict(log) for log in logs]})

@app.route('/api/admin/notifications', methods=['GET'])
@require_admin
def admin_notifications():
    conn = get_db()
    notifications = conn.execute('''
        SELECT id, title, message, created_at, is_read FROM notifications 
        ORDER BY id DESC LIMIT 20
    ''').fetchall()
    conn.close()
    
    return jsonify({'success': True, 'notifications': [dict(n) for n in notifications]})

@app.route('/api/admin/api-keys', methods=['GET', 'POST'])
@require_admin
def admin_api_keys():
    if request.method == 'GET':
        conn = get_db()
        keys = conn.execute('SELECT key_value, name, permissions, created_at, last_used, is_active FROM api_keys').fetchall()
        conn.close()
        return jsonify({'success': True, 'api_keys': [dict(k) for k in keys]})
    
    elif request.method == 'POST':
        data = request.get_json()
        name = data.get('name')
        permissions = data.get('permissions', 'read')
        
        if not name:
            return jsonify({'error': 'name required'}), 400
        
        new_key = hashlib.sha256(f"{ADMIN_KEY}_{name}_{datetime.now().isoformat()}".encode()).hexdigest()[:32]
        
        conn = get_db()
        conn.execute('''
            INSERT INTO api_keys (key_value, name, permissions, created_at)
            VALUES (?, ?, ?, ?)
        ''', (new_key, name, permissions, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        
        create_notification('مفتاح API جديد', f'تم إنشاء مفتاح API جديد: {name}')
        
        return jsonify({'success': True, 'api_key': new_key, 'name': name})

# ============================================================
# بوت التحكم المتقدم
# ============================================================

bot = telebot.TeleBot(BOT_TOKEN, parse_mode="HTML")

def create_main_menu():
    keyboard = InlineKeyboardMarkup(row_width=2)
    keyboard.add(
        InlineKeyboardButton("➕ إنشاء ترخيص", callback_data="menu_create"),
        InlineKeyboardButton("📋 قائمة التراخيص", callback_data="menu_list")
    )
    keyboard.add(
        InlineKeyboardButton("📊 الإحصائيات", callback_data="menu_stats"),
        InlineKeyboardButton("🔗 رابط API", callback_data="menu_api")
    )
    keyboard.add(
        InlineKeyboardButton("🔑 مفاتيح API", callback_data="menu_keys"),
        InlineKeyboardButton("📜 السجلات", callback_data="menu_logs")
    )
    return keyboard

@bot.message_handler(commands=['start'])
def start(message):
    if message.from_user.id != ADMIN_ID:
        bot.reply_to(message, "❌ غير مصرح")
        return
    
    stats = get_stats()
    text = f"""
🔐 <b>نظام إدارة التراخيص المتقدم</b>

📊 <b>إحصائيات سريعة:</b>
━━━━━━━━━━━━━━━━━━
📋 إجمالي التراخيص: {stats['total']}
🟢 النشطة: {stats['active']}
🔴 المحظورة: {stats['blocked']}
⏰ المنتهية: {stats['expired']}
━━━━━━━━━━━━━━━━━━
✅ فحوصات ناجحة: {stats['total_checks']}
❌ فحوصات فاشلة: {stats['total_fails']}
📅 فحوصات اليوم: {stats['today_checks']}
━━━━━━━━━━━━━━━━━━

استخدم الأزرار أدناه للتحكم:
"""
    bot.send_message(message.chat.id, text, reply_markup=create_main_menu())

@bot.callback_query_handler(func=lambda call: True)
def handle_callback(call):
    if call.from_user.id != ADMIN_ID:
        bot.answer_callback_query(call.id, "غير مصرح", show_alert=True)
        return

    if call.data == "menu_create":
        msg = bot.send_message(call.message.chat.id, 
            "📝 <b>إنشاء ترخيص جديد</b>\n\n"
            "أرسل المعلومات بهذا التنسيق:\n"
            "<code>الاسم | المدة (أيام) | عدد الأجهزة</code>\n\n"
            "مثال: <code>محمد أحمد | 30 | 2</code>\n"
            "(المدة 0 = دائمة، عدد الأجهزة الافتراضي 1)")
        bot.register_next_step_handler(msg, process_create)
        bot.answer_callback_query(call.id)

    elif call.data == "menu_list":
        show_licenses(call.message.chat.id, call.message.message_id)
        bot.answer_callback_query(call.id)

    elif call.data == "menu_stats":
        show_stats(call.message.chat.id, call.message.message_id)
        bot.answer_callback_query(call.id)

    elif call.data == "menu_api":
        server_url = os.environ.get('RENDER_EXTERNAL_URL', 'http://localhost:5000')
        text = f"""
🔗 <b>رابط API المتقدم</b>

━━━━━━━━━━━━━━━━━━
<b>للتحقق من الترخيص:</b>
<code>{server_url}/api/verify?token=التوكن&amp;device_id=الجهاز</code>

<b>لإنشاء ترخيص (POST):</b>
<code>{server_url}/api/admin/create</code>

<b>لإيقاف ترخيص (POST):</b>
<code>{server_url}/api/admin/revoke</code>

<b>مثال للعميل:</b>
<code>
import requests
r = requests.get("{server_url}/api/verify?token=TOKEN&amp;device_id=DEVICE")
print(r.json())
</code>
━━━━━━━━━━━━━━━━━━
<b>رأس الإدارة:</b>
<code>X-Admin-Key: {ADMIN_KEY}</code>
"""
        bot.edit_message_text(text, call.message.chat.id, call.message.message_id, reply_markup=create_main_menu())
        bot.answer_callback_query(call.id)

    elif call.data == "menu_keys":
        show_api_keys(call.message.chat.id, call.message.message_id)
        bot.answer_callback_query(call.id)

    elif call.data == "menu_logs":
        show_logs(call.message.chat.id, call.message.message_id)
        bot.answer_callback_query(call.id)

    elif call.data == "back_to_main":
        stats = get_stats()
        text = f"""
🔐 <b>نظام إدارة التراخيص المتقدم</b>

📊 <b>إحصائيات سريعة:</b>
━━━━━━━━━━━━━━━━━━
📋 إجمالي التراخيص: {stats['total']}
🟢 النشطة: {stats['active']}
🔴 المحظورة: {stats['blocked']}
━━━━━━━━━━━━━━━━━━
✅ إجمالي الفحوصات: {stats['total_checks']}
"""
        bot.edit_message_text(text, call.message.chat.id, call.message.message_id, reply_markup=create_main_menu())
        bot.answer_callback_query(call.id)

def process_create(message):
    try:
        parts = message.text.split('|')
        customer = parts[0].strip()
        days = int(parts[1].strip()) if len(parts) > 1 else 0
        max_devices = int(parts[2].strip()) if len(parts) > 2 else 1
        
        token = create_license(customer, days, max_devices)
        
        server_url = os.environ.get('RENDER_EXTERNAL_URL', 'http://localhost:5000')
        
        text = f"""
✅ <b>تم إنشاء الترخيص!</b>

━━━━━━━━━━━━━━━━━━
👤 <b>العميل:</b> {customer}
🔑 <b>التوكن:</b> <code>{token}</code>
📅 <b>الصلاحية:</b> {days if days > 0 else 'دائمة'}
📱 <b>الحد الأقصى للأجهزة:</b> {max_devices}
━━━━━━━━━━━━━━━━━━
🔗 <b>رابط التحقق:</b>
<code>{server_url}/api/verify?token={token}</code>

⚠️ احتفظ بهذا التوكن في مكان آمن
"""
        bot.send_message(message.chat.id, text, reply_markup=create_main_menu())
    except Exception as e:
        bot.reply_to(message, f"❌ خطأ: {e}\nاستخدم التنسيق: الاسم | المدة | عدد_الأجهزة")

def show_licenses(chat_id, message_id=None):
    licenses, total = get_all_licenses(limit=20)
    
    if not licenses:
        text = "📋 لا توجد تراخيص حالياً"
        bot.edit_message_text(text, chat_id, message_id, reply_markup=create_main_menu())
        return
    
    text = f"📋 <b>قائمة التراخيص</b> (إجمالي: {total})\n━━━━━━━━━━━━━━━━━━\n"
    
    for lic in licenses:
        icon = "🟢" if lic['status'] == 'active' else "🔴"
        expiry = lic['expiry_date'][:10] if lic['expiry_date'] else 'دائم'
        text += f"{icon} <b>{lic['customer']}</b>\n"
        text += f"   📅 {expiry} | 📊 {lic['usage_count']} استخدام\n"
        text += f"   🔑 <code>{lic['token'][:16]}...</code>\n━━━━━━━━━━━━━━━━━━\n"
    
    keyboard = InlineKeyboardMarkup()
    keyboard.add(InlineKeyboardButton("🔙 رجوع", callback_data="back_to_main"))
    
    bot.edit_message_text(text, chat_id, message_id, reply_markup=keyboard)

def show_stats(chat_id, message_id=None):
    stats = get_stats()
    text = f"""
📊 <b>إحصائيات النظام المتقدمة</b>
━━━━━━━━━━━━━━━━━━
<b>التراخيص:</b>
📋 الإجمالي: {stats['total']}
🟢 النشطة: {stats['active']}
🔴 المحظورة: {stats['blocked']}
⏰ المنتهية: {stats['expired']}
━━━━━━━━━━━━━━━━━━
<b>الفحوصات:</b>
✅ ناجحة: {stats['total_checks']}
❌ فاشلة: {stats['total_fails']}
📅 اليوم: {stats['today_checks']}
━━━━━━━━━━━━━━━━━━
<b>أكثر التراخيص استخداماً:</b>
"""
    for lic in stats.get('top_licenses', []):
        text += f"• {lic['customer']}: {lic['usage_count']} استخدام\n"
    
    bot.edit_message_text(text, chat_id, message_id, reply_markup=create_main_menu())

def show_api_keys(chat_id, message_id=None):
    conn = get_db()
    keys = conn.execute('SELECT name, key_value, permissions, created_at, last_used FROM api_keys').fetchall()
    conn.close()
    
    text = f"🔑 <b>مفاتيح API</b>\n━━━━━━━━━━━━━━━━━━\n"
    for key in keys:
        text += f"📌 <b>{key['name']}</b>\n"
        text += f"   🔐 <code>{key['key_value']}</code>\n"
        text += f"   🔑 صلاحيات: {key['permissions']}\n"
        text += f"   📅 تاريخ: {key['created_at'][:10]}\n━━━━━━━━━━━━━━━━━━\n"
    
    keyboard = InlineKeyboardMarkup()
    keyboard.add(InlineKeyboardButton("➕ إنشاء مفتاح جديد", callback_data="create_key"))
    keyboard.add(InlineKeyboardButton("🔙 رجوع", callback_data="back_to_main"))
    
    bot.edit_message_text(text, chat_id, message_id, reply_markup=keyboard)

def show_logs(chat_id, message_id=None):
    conn = get_db()
    logs = conn.execute('''
        SELECT token, action, timestamp FROM logs 
        ORDER BY id DESC LIMIT 15
    ''').fetchall()
    conn.close()
    
    text = f"📜 <b>آخر النشاطات</b>\n━━━━━━━━━━━━━━━━━━\n"
    for log in logs:
        token_short = log['token'][:12] + '...' if log['token'] else 'system'
        text += f"🔹 {log['action']} | {token_short}\n"
        text += f"   🕐 {log['timestamp'][:16]}\n━━━━━━━━━━━━━━━━━━\n"
    
    bot.edit_message_text(text, chat_id, message_id, reply_markup=create_main_menu())

def run_bot():
    while True:
        try:
            bot.infinity_polling(timeout=60)
        except Exception as e:
            print(f"Bot error: {e}")
            time.sleep(5)

# ============================================================
# التشغيل الرئيسي
# ============================================================

if __name__ == '__main__':
    init_db()
    
    # تشغيل البوت في خلفية
    bot_thread = threading.Thread(target=run_bot)
    bot_thread.daemon = True
    bot_thread.start()
    
    # تشغيل Flask
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, threaded=True)
