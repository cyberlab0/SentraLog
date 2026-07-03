import os
import sqlite3
import random
import string
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, g
from werkzeug.security import generate_password_hash, check_password_hash
import requests

app = Flask(__name__)

# Security Hardening
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

def load_env():
    env_path = os.path.join(os.path.dirname(__file__), 'sensitive-SentraLog.env')
    if os.path.exists(env_path):
        with open(env_path, 'r') as f:
            for line in f:
                if line.strip() and not line.startswith('#'):
                    key, value = line.strip().split('=', 1)
                    os.environ[key] = value

load_env()

app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'xdr_secure_key_9912')
MASTER_USER = os.environ.get('MASTER_USERNAME', 'admin')
MASTER_PASS = os.environ.get('MASTER_PASSWORD', 'admin')
VT_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
URLSCAN_API_KEY = os.environ.get('URLSCAN_API_KEY', '')

DATABASE = 'sentralog_xdr.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None: db.close()

def generate_emergency_key():
    return "EMG-" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))

def get_live_time():
    return datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

def init_db():
    with app.app_context():
        db = get_db()
        db.execute('''CREATE TABLE IF NOT EXISTS tenants (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, server_ip TEXT, log_source TEXT, status TEXT DEFAULT 'Active', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        db.execute('''CREATE TABLE IF NOT EXISTS blocklist (ip TEXT PRIMARY KEY, reason TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        db.execute('''CREATE TABLE IF NOT EXISTS emergency_keys (org_name TEXT PRIMARY KEY, current_key TEXT, requested_at TIMESTAMP)''')
        db.execute('''CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, user TEXT, action TEXT, ip_address TEXT, location TEXT, timestamp TIMESTAMP)''')
        
        # New Users Table for Registration
        db.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            username TEXT UNIQUE, 
            password_hash TEXT, 
            role TEXT, 
            status TEXT DEFAULT 'pending', 
            ip_address TEXT, 
            location TEXT, 
            created_at TIMESTAMP)''')
        
        cur = db.execute("SELECT * FROM emergency_keys")
        if not cur.fetchone():
            db.execute("INSERT INTO emergency_keys (org_name, current_key, requested_at) VALUES (?, ?, ?)", ('Global_Org', generate_emergency_key(), get_live_time()))
        db.commit()

init_db()

def log_audit(user, action, ip, location="Unknown"):
    db = get_db()
    db.execute('INSERT INTO audit_logs (user, action, ip_address, location, timestamp) VALUES (?, ?, ?, ?, ?)', (user, action, ip, location, get_live_time()))
    db.commit()

# --- Authentication & Registration ---

@app.route('/')
def index():
    if 'logged_in' in session: return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json
    username, password, role = data.get('username'), data.get('password'), data.get('role')
    ip = request.remote_addr
    location = "Lagos, NG (ISP: MainOne)" if random.random() > 0.5 else "New York, US (ISP: Verizon)" # Mock Geolocation
    
    if not username or not password or not role: return jsonify({'error': 'Missing fields'}), 400
    if username == MASTER_USER: return jsonify({'error': 'Reserved username'}), 400

    db = get_db()
    try:
        db.execute('INSERT INTO users (username, password_hash, role, status, ip_address, location, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)', 
                   (username, generate_password_hash(password), role, 'pending', ip, location, get_live_time()))
        db.commit()
        log_audit(username, "New Registration Submitted - Awaiting Admin Approval", ip, location)
        return jsonify({'status': 'success'})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 400

@app.route('/api/auth/login', methods=['POST'])
def auth_login():
    data = request.json
    username, password = data.get('username'), data.get('password')
    ip = request.remote_addr
    location = "Lagos, NG" if random.random() > 0.5 else "London, UK"
    
    # Super Admin Check
    if username == MASTER_USER and password == MASTER_PASS:
        session['logged_in'] = True
        session['role'] = 'Super Admin'
        session['username'] = username
        log_audit(username, "Super Admin Login Success", ip, location)
        return jsonify({'status': 'success'})
    
    # Regular User Check
    db = get_db()
    cur = db.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    
    if user and check_password_hash(user['password_hash'], password):
        if user['status'] != 'approved':
            log_audit(username, "Login Blocked - Account Pending Admin Approval", ip, location)
            return jsonify({'error': 'Account pending Super Admin approval. Access Denied.'}), 403
            
        session['logged_in'] = True
        session['role'] = user['role']
        session['username'] = username
        log_audit(username, f"{user['role']} Login Success", ip, location)
        return jsonify({'status': 'success'})
        
    return jsonify({'error': 'Invalid Credentials'}), 401

@app.route('/api/auth/emergency', methods=['POST'])
def emergency_login():
    code = request.json.get('code')
    ip = request.remote_addr
    db = get_db()
    
    cur = db.execute("SELECT * FROM emergency_keys WHERE current_key = ?", (code,))
    emg = cur.fetchone()
    if emg:
        new_key = generate_emergency_key()
        db.execute("UPDATE emergency_keys SET current_key = ?, requested_at = ? WHERE org_name = ?", (new_key, get_live_time(), emg['org_name']))
        db.commit()
        
        session['logged_in'] = True
        session['role'] = 'Emergency Responder'
        session['username'] = 'EMERGENCY_OVERRIDE'
        log_audit('EMERGENCY_OVERRIDE', f"CRITICAL: One-Time Bypass Key Used. Key invalidated.", ip, "Emergency Access")
        return jsonify({'status': 'success'})
        
    return jsonify({'error': 'Invalid Emergency Key'}), 401

@app.route('/logout')
def logout():
    if 'username' in session:
        log_audit(session['username'], "User Logout", request.remote_addr)
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'logged_in' not in session: return redirect(url_for('login'))
    return render_template('dashboard.html', username=session.get('username'), role=session.get('role'))

# --- Gatekeeper & Approvals (Super Admin Only) ---
@app.route('/api/admin/gatekeeper', methods=['GET'])
def get_gatekeeper_data():
    if session.get('role') != 'Super Admin': return jsonify({'error': 'Unauthorized'}), 403
    db = get_db()
    
    cur = db.execute("SELECT * FROM users WHERE status = 'pending' ORDER BY created_at DESC")
    pending = [dict(row) for row in cur.fetchall()]
    
    cur = db.execute("SELECT * FROM emergency_keys")
    keys = [dict(row) for row in cur.fetchall()]
    
    cur = db.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 50")
    audits = [dict(row) for row in cur.fetchall()]
    
    return jsonify({'pending': pending, 'keys': keys, 'audits': audits})

@app.route('/api/admin/approve_user', methods=['POST'])
def approve_user():
    if session.get('role') != 'Super Admin': return jsonify({'error': 'Unauthorized'}), 403
    username = request.json.get('username')
    db = get_db()
    db.execute("UPDATE users SET status = 'approved' WHERE username = ?", (username,))
    db.commit()
    log_audit(session.get('username'), f"Approved User Registration: {username}", request.remote_addr)
    return jsonify({'status': 'success'})

# --- Escalation & Playbooks ---
@app.route('/api/escalate', methods=['POST'])
def escalate_incident():
    threat = request.json.get('threat')
    level = request.json.get('level') # e.g. SOC2, Manager
    log_audit(session.get('username'), f"Escalated threat '{threat}' to {level}", request.remote_addr)
    return jsonify({'status': 'success'})

# --- Cloud Sandbox Detonator (URLScan / VT) ---
@app.route('/api/sandbox/detonate', methods=['POST'])
def sandbox_detonate():
    url = request.json.get('url')
    # Simulated connection to URLScan.io and VirusTotal using provided API keys
    # In a real environment, this makes HTTP requests to urlscan.io/api/v1/scan and virustotal.com/api/v3/urls
    log_audit(session.get('username', 'System'), f"Detonated Payload in Cloud VM: {url}", request.remote_addr)
    
    return jsonify({
        'status': 'success',
        'url_scanned': url,
        'threat_level': 'CRITICAL MALWARE',
        'vt_score': '58/72 Engines Detected',
        'verdict': 'Phishing / Credential Harvester',
        'sandbox_ip': '104.21.44.1'
    })

# --- Legacy Endpoints (Map, Timeline, UEBA, SOAR) preserved ---
@app.route('/api/analytics/map_data', methods=['GET'])
def map_data():
    vectors = [
        {"lat": 55.75, "lng": 37.61, "source": "RU", "target_lat": 38.90, "target_lng": -77.03, "type": "Brute Force", "severity": "critical"},
        {"lat": 39.90, "lng": 116.40, "source": "CN", "target_lat": 37.77, "target_lng": -122.41, "type": "DDoS", "severity": "medium"}
    ]
    return jsonify(random.sample(vectors, k=1))

@app.route('/api/analytics/timeline', methods=['GET'])
def incident_timeline():
    return jsonify([{"time": get_live_time(), "type": "recon", "title": "Unauthorized Access Attempt", "desc": "IP scan matched blocked signature.", "eli5": "An attacker is checking our doors."}])

@app.route('/api/analytics/ueba', methods=['GET'])
def ueba_data():
    return jsonify([{"user": "j.smith", "risk_score": 92, "event": "Impossible Travel", "details": "Login from Lagos -> Moscow", "action": "Account Suspended"}])

if __name__ == '__main__':
    app.run(debug=False, port=5000, threaded=True)
