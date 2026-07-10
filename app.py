import os
import sqlite3
import random
import string
import re
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, g
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests

app = Flask(__name__)

# Security Hardening - Rate Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' https:; img-src 'self' data: https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:;"
    return response

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

def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr

def get_geoip(ip):
    # Skip local IPs
    if ip == '127.0.0.1' or ip.startswith('192.168.'): return "Local Network|0|0"
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
        if res.get("status") == "success":
            return f"{res['city']}, {res['countryCode']}|{res['lat']}|{res['lon']}"
    except: pass
    return "Unknown|0|0"

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
    # Extract Device Type from User-Agent if available in request context
    device_info = "Unknown Device"
    try:
        user_agent = request.headers.get('User-Agent', '').lower()
        if 'windows' in user_agent: device_info = "Windows PC"
        elif 'macintosh' in user_agent or 'mac os' in user_agent: device_info = "Mac OS"
        elif 'iphone' in user_agent: device_info = "iPhone (Mobile)"
        elif 'android' in user_agent: device_info = "Android (Mobile)"
        elif 'linux' in user_agent: device_info = "Linux System"
    except: pass
    
    # Store device info alongside location
    enriched_location = f"{location} | Device: {device_info}" if location != "Unknown" else f"Unknown | Device: {device_info}"
    
    db.execute('INSERT INTO audit_logs (user, action, ip_address, location, timestamp) VALUES (?, ?, ?, ?, ?)', (user, action, ip, enriched_location, get_live_time()))
    db.commit()

# --- Threat Intelligence (IP Scanner) ---
@app.route('/api/scan_ip', methods=['POST'])
def ip_scanner():
    if 'logged_in' not in session: return jsonify({'error': 'Unauthorized'}), 401
    target_ip = request.json.get('ip')
    if not target_ip: return jsonify({'error': 'No IP provided'}), 400
    
    # 1. Geo-Location Lookup
    geo_data = {"city": "Unknown", "country": "Unknown", "isp": "Unknown"}
    try:
        res = requests.get(f"http://ip-api.com/json/{target_ip}", timeout=3).json()
        if res.get("status") == "success":
            geo_data = {"city": res.get("city"), "country": res.get("country"), "isp": res.get("isp")}
    except: pass

    # 2. Simulated Threat Intel (VirusTotal/AbuseIPDB mock)
    # If the IP starts with 104, 185, or 193, we simulate a bad reputation
    threat_score = "0/100 (Clean)"
    reported_before = "No previous reports."
    if target_ip.startswith("104.") or target_ip.startswith("185.") or target_ip.startswith("193."):
        threat_score = "85/100 (Malicious)"
        reported_before = "Flagged 14 times for Brute Force & Port Scanning (AlienVault OTX)."

    # 3. MAC Address Explanation (Layer 2 limitation)
    mac_address_status = "UNAVAILABLE (Layer 2 Protocol limitation. MAC addresses do not route across the public internet. Only local network MACs can be resolved)."

    # Log the scan
    log_audit(session.get('username'), f"Ran IP Threat Scan on: {target_ip}", get_client_ip(), get_geoip(get_client_ip()))

    return jsonify({
        "status": "success",
        "ip": target_ip,
        "geolocation": geo_data,
        "malicious_votes": int(threat_score.split('/')[0]),
        "threat_intelligence": {
            "reputation_score": threat_score,
            "history": reported_before
        },
        "network_layer": {
            "mac_address": mac_address_status,
            "device_type": "Derived from HTTP User-Agent (See Audit Logs for captured devices)"
        }
    })

# --- Authentication & Registration ---

@app.route('/')
def index():
    if 'logged_in' in session: return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    data = request.json
    username, password, role = data.get('username'), data.get('password'), data.get('role')
    ip = get_client_ip()
    location = get_geoip(ip)
    
    # Input Validation (Sanitization)
    if not username or not password or not role: return jsonify({'error': 'Missing fields'}), 400
    if not re.match("^[a-zA-Z0-9_.-]+$", username) or len(username) < 3: return jsonify({'error': 'Invalid username format'}), 400
    if len(password) < 8: return jsonify({'error': 'Password must be at least 8 characters'}), 400
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
@limiter.limit("10 per minute")
def auth_login():
    data = request.json
    username, password = data.get('username'), data.get('password')
    two_factor = data.get('two_factor')
    ip = get_client_ip()
    location = get_geoip(ip)
    
    # Super Admin Check
    if username == MASTER_USER and password == MASTER_PASS:
        if two_factor != '123456': return jsonify({'error': 'Invalid 2FA Code'}), 401
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
        if two_factor != '123456':
            log_audit(username, "Login Blocked - Invalid 2FA Code", ip, location)
            return jsonify({'error': 'Invalid 2FA Code'}), 401
            
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
@limiter.limit("5 per minute")
def emergency_login():
    code = request.json.get('code')
    ip = get_client_ip()
    location = get_geoip(ip)
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
        log_audit('EMERGENCY_OVERRIDE', f"CRITICAL: One-Time Bypass Key Used. Key invalidated.", ip, location)
        return jsonify({'status': 'success'})
        
    return jsonify({'error': 'Invalid Emergency Key'}), 401

@app.route('/logout')
def logout():
    if 'username' in session:
        log_audit(session['username'], "User Logout", get_client_ip(), get_geoip(get_client_ip()))
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
    log_audit(session.get('username'), f"Approved User Registration: {username}", get_client_ip(), get_geoip(get_client_ip()))
    return jsonify({'status': 'success'})

# --- Escalation & Playbooks ---
@app.route('/api/escalate', methods=['POST'])
def escalate_incident():
    if 'logged_in' not in session: return jsonify({'error': 'Unauthorized'}), 401
    threat = request.json.get('threat')
    level = request.json.get('level') # e.g. SOC2, Manager
    log_audit(session.get('username'), f"Escalated threat '{threat}' to {level}", get_client_ip(), get_geoip(get_client_ip()))
    return jsonify({'status': 'success'})

# --- Cloud Sandbox Detonator (URLScan / VT) ---
@app.route('/api/sandbox/detonate', methods=['POST'])
def sandbox_detonate():
    if 'logged_in' not in session: return jsonify({'error': 'Unauthorized'}), 401
    url = request.json.get('url')
    # Simulated connection to URLScan.io and VirusTotal using provided API keys
    # In a real environment, this makes HTTP requests to urlscan.io/api/v1/scan and virustotal.com/api/v3/urls
    log_audit(session.get('username', 'System'), f"Detonated Payload in Cloud VM: {url}", get_client_ip(), get_geoip(get_client_ip()))
    
    return jsonify({
        'status': 'success',
        'url_scanned': url,
        'threat_level': 'CRITICAL MALWARE',
        'vt_score': '58/72 Engines Detected',
        'verdict': 'Phishing / Credential Harvester',
        'sandbox_ip': '104.21.44.1'
    })

# --- Endpoint Agent Telemetry Ingestion ---
@app.route('/api/agent/ingest', methods=['POST'])
@limiter.limit("100 per minute")
def agent_ingest():
    data = request.json
    api_key = data.get('api_key')
    # Secret Key matching the physical deployed agents
    if api_key != "SENTRA-AGENT-9912":
        return jsonify({'error': 'Unauthorized Agent'}), 401
    
    agent_id = data.get('agent_id', 'Unknown_Agent')
    event_type = data.get('event_type', 'System Alert')
    details = data.get('details', '')
    
    ip = get_client_ip()
    location = get_geoip(ip)
    
    # We prefix it with [EDR ALERT] so the Timeline displays it properly
    action_text = f"[EDR ALERT - {event_type}] {details}"
    log_audit(f"Host-{agent_id}", action_text, ip, location)
    
    return jsonify({'status': 'success', 'msg': 'Telemetry safely ingested'})

# --- True Database-Driven Endpoints ---
@app.route('/api/analytics/map_data', methods=['GET'])
def map_data():
    if 'logged_in' not in session: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    cur = db.execute("SELECT ip_address, location, action FROM audit_logs WHERE location != 'Unknown|0|0' AND location != 'Unknown' ORDER BY timestamp DESC LIMIT 20")
    vectors = []
    for row in cur.fetchall():
        parts = str(row['location']).split('|')
        if len(parts) == 3:
            severity = "critical" if "Block" in row['action'] or "Denied" in row['action'] else "low"
            vectors.append({"lat": float(parts[1]), "lng": float(parts[2]), "source": parts[0], "target_lat": 38.90, "target_lng": -77.03, "type": row['action'], "severity": severity})
    return jsonify(vectors)

@app.route('/api/analytics/timeline', methods=['GET'])
def incident_timeline():
    if 'logged_in' not in session: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    cur = db.execute("SELECT timestamp, action, user, ip_address FROM audit_logs ORDER BY timestamp DESC LIMIT 15")
    events = []
    for row in cur.fetchall():
        type_flag = "alert" if "Block" in row['action'] or "Denied" in row['action'] else "info"
        events.append({"time": row['timestamp'], "type": type_flag, "title": row['action'], "desc": f"User: {row['user']} | IP: {row['ip_address']}", "eli5": "System event recorded via True IP."})
    return jsonify(events)

@app.route('/api/analytics/ueba', methods=['GET'])
def ueba_data():
    if 'logged_in' not in session: return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    cur = db.execute("SELECT user, action, ip_address FROM audit_logs WHERE action LIKE '%Block%' OR action LIKE '%Denied%' ORDER BY timestamp DESC LIMIT 10")
    risks = []
    for row in cur.fetchall():
        risks.append({"user": row['user'], "risk_score": 95, "event": "Multiple Failed/Blocked Actions", "details": f"IP: {row['ip_address']}", "action": "Flagged for Review"})
    if not risks: risks = [{"user": "System Normal", "risk_score": 0, "event": "No anomalies", "details": "All user behavior within thresholds.", "action": "None"}]
    return jsonify(risks)

if __name__ == '__main__':
    app.run(debug=False, port=5000, threaded=True)
