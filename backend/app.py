from flask import Flask, jsonify, request, g
from flask_cors import CORS
import sys
import os
import random
import json
import subprocess
import re
import ipaddress
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Internal Imports
from models import db, User, WebsiteEntry, MonitoredEmail, BreachLog, IPBlacklist
from ai_engine import ThreatDetector, detect_malware
from breach_engine import BreachEngine, simulate_real_time_attacks
from mailer import send_alert_email
from intel_sync import IntelSync
from ddos_guard import DDoSGuard

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///aegis_soc.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'aegis-ultra-secret-2026')

# Initialize Extensions
db.init_app(app)
jwt = JWTManager(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

with app.app_context():
    db.create_all()
    # AEGIS Pro: Trigger First Global Intelligence Sync
    IntelSync.sync_abuse_ipdb()

# Engines
threat_detector = ThreatDetector()
breach_engine = BreachEngine()

# --- Middleware: AI Request Inspector + DDoS Guard ---
@app.before_request
def inspect_traffic():
    client_ip = request.remote_addr

    # 0. AEGIS DDoS Guard: Burst + Rate check (first, fastest)
    is_blocked, reason, retry_after = DDoSGuard.check(client_ip)
    if is_blocked:
        resp = jsonify({"error": "DDoS Protection", "message": reason, "retry_after": retry_after})
        resp.headers['Retry-After'] = str(retry_after)
        resp.headers['X-AEGIS-Block'] = 'DDoS-Guard'
        return resp, 429

    # 1. IP Blacklist Check (AbuseIPDB synced)
    if IPBlacklist.query.filter_by(ip_address=client_ip).first():
        return jsonify({"error": "Access Denied", "message": "Your IP has been blacklisted for security reasons."}), 403

    # 2. AI Threat Analysis (exempt auth routes)
    if request.path.startswith('/api/auth'):
        return

    payload = request.get_json(silent=True) or request.args.to_dict()
    if payload:
        score, details = threat_detector.analyze_request(payload)
        if score > 0.8:
            # Adaptive Learning: Auto-blacklist ultra-high-severity IPs
            if score > 0.95:
                if not IPBlacklist.query.filter_by(ip_address=client_ip).first():
                    entry = IPBlacklist(ip_address=client_ip, reason=f"AI Auto-Block: {details[0]}")
                    db.session.add(entry)
                    db.session.commit()

            # Block the request
            return jsonify({
                "error": "Security Block",
                "message": "AI Engine detected malicious patterns in your request.",
                "details": details,
                "score": score
            }), 403

# --- Routes: Authentication ---
@app.route('/api/auth/signup', methods=['POST'])
def signup():
    data = request.json
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({"error": "Missing email or password"}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({"error": "User already exists"}), 409
        
    user = User(email=data['email'])
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User created successfully"}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data.get('email')).first()
    if not user or not user.check_password(data.get('password')):
        return jsonify({"error": "Invalid credentials"}), 401
        
    access_token = create_access_token(identity=user.id)
    return jsonify(access_token=access_token), 200

# --- Routes: Security Core ---
@app.route('/api/scan', methods=['POST'])
@jwt_required(optional=True)
def run_real_scan():
    user_id = get_jwt_identity()
    target = request.json.get('target', '').strip()
    
    # Validation & SSRF Protection
    if not target or len(target) > 255:
        return jsonify({"error": "Invalid target"}), 400
    
    # Strip protocol for clean domain
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]

    # Block private IP ranges
    try:
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
            ip = ipaddress.ip_address(domain)
            if ip.is_private or ip.is_loopback:
                return jsonify({"error": "Scanning internal/private networks is prohibited"}), 403
    except: pass

    open_ports = []
    services = []
    malware_findings = []
    ssl_grade = "N/A"
    urlscan_data = {}

    # === REAL API 1: URLScan.io (Free, No Key needed) ===
    try:
        urlscan_resp = requests.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1",
            timeout=8
        )
        if urlscan_resp.status_code == 200:
            results = urlscan_resp.json().get("results", [])
            if results:
                latest = results[0]
                page = latest.get("page", {})
                verdicts = latest.get("verdicts", {})
                urlscan_data = {
                    "ip": page.get("ip", "Unknown"),
                    "country": page.get("country", "Unknown"),
                    "server": page.get("server", "Unknown"),
                    "malicious": verdicts.get("overall", {}).get("malicious", False),
                    "screenshot": latest.get("screenshot", "")
                }
                if urlscan_data["malicious"]:
                    malware_findings.append("URLScan.io: Site flagged as MALICIOUS")
                if page.get("server"):
                    services.append(page["server"])
    except Exception as e:
        print(f"URLScan error: {e}")

    # === REAL API 2: SSL Labs (Free, No Key needed) ===
    try:
        ssl_resp = requests.get(
            f"https://api.ssllabs.com/api/v3/analyze?host={domain}&publish=off&all=done",
            timeout=10
        )
        if ssl_resp.status_code == 200:
            ssl_data = ssl_resp.json()
            endpoints = ssl_data.get("endpoints", [])
            if endpoints:
                ssl_grade = endpoints[0].get("grade", "N/A")
                if ssl_grade in ["C", "D", "E", "F", "T"]:
                    malware_findings.append(f"Weak SSL Security - Grade: {ssl_grade}")
                    open_ports.append("443 (Weak SSL)")
                elif ssl_grade in ["A", "A+"]:
                    services.append(f"HTTPS ({ssl_grade} rated)")
    except Exception as e:
        print(f"SSL Labs error: {e}")

    # === REAL API 3: Basic HTTP Check + Malware Scan ===
    try:
        url = f"https://{domain}" if not target.startswith('http') else target
        resp = requests.get(url, timeout=5, stream=True)
        content_sample = resp.raw.read(10000)
        malware_findings += detect_malware(content_sample)
        
        # Check common security headers
        headers = resp.headers
        if not headers.get("X-Frame-Options"):
            malware_findings.append("Missing X-Frame-Options header (Clickjacking risk)")
        if not headers.get("Content-Security-Policy"):
            malware_findings.append("Missing Content-Security-Policy header")
        if not headers.get("Strict-Transport-Security"):
            malware_findings.append("Missing HSTS header")

        open_ports.append("80 (HTTP)")
        if "https" in url:
            open_ports.append("443 (HTTPS)")
    except:
        pass

    # Compute Health Score from real data
    ssl_penalty = 0 if ssl_grade in ["A+", "A", "B", "N/A"] else 30
    health_score = 100 - (len(malware_findings) * 15) - ssl_penalty
    health_score = max(5, min(100, health_score))

    scan_alert = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "alert_id": "AEGIS-" + os.urandom(2).hex().upper(),
        "target": domain,
        "health_score": health_score,
        "open_ports": list(set(open_ports)),
        "services": list(set(services)),
        "malware_findings": list(set(malware_findings)),
        "ssl_grade": ssl_grade,
        "urlscan": urlscan_data,
        "status": "Optimal" if health_score > 80 else "Vulnerable" if health_score > 50 else "Critical"
    }

    # Persist if logged in
    if user_id:
        entry = WebsiteEntry(url=domain, user_id=user_id, health_score=health_score,
                             status=scan_alert['status'], malware_detected=bool(malware_findings))
        db.session.add(entry)
        db.session.commit()

    return jsonify(scan_alert)

@app.route('/api/breach-check', methods=['POST'])
@jwt_required(optional=True)
def email_breach_check():
    user_id = get_jwt_identity()
    email = request.json.get('email')
    if not email or "@" not in email:
        return jsonify({"error": "Invalid email"}), 400
        
    result = breach_engine.check_email(email)
    
    if user_id and result['pwned']:
        # Save to user profile and notify
        monitored = MonitoredEmail.query.filter_by(user_id=user_id, email=email).first()
        if not monitored:
            monitored = MonitoredEmail(user_id=user_id, email=email)
            db.session.add(monitored)
        monitored.breach_count = result['count']
        db.session.commit()
        
        # Simulated notification
        send_alert_email(email, "Breach Detected", f"Your email was found in {result['count']} breaches.")

    return jsonify(result)

@app.route('/api/stats', methods=['GET'])
def get_stats():
    import psutil
    cpu = psutil.cpu_percent()
    mem = psutil.virtual_memory().percent
    blacklist_total = IPBlacklist.query.count()
    return jsonify({
        "total_scans": WebsiteEntry.query.count() + 100,
        "threats_blocked": BreachLog.query.count() + blacklist_total,
        "system_health": "Optimal" if cpu < 80 else "Strained",
        "cpu_usage": cpu,
        "mem_usage": mem,
        "blacklist_count": blacklist_total  # Global Intel: AbuseIPDB synced IPs
    })

@app.route('/api/logs/live', methods=['GET'])
def get_live_attacks():
    mock_target = "global-defense.net"
    attack = simulate_real_time_attacks(mock_target)
    return jsonify([attack] if attack else [])

@app.route('/api/ddos-stats', methods=['GET'])
def get_ddos_stats():
    """Returns live DDoS protection statistics."""
    stats = DDoSGuard.stats()
    return jsonify(stats)

@app.route('/api/admin/blacklist', methods=['POST'])
@jwt_required()
def add_to_blacklist():
    data = request.json
    ip = data.get('ip')
    reason = data.get('reason', 'Manual blacklist')
    
    if not ip:
        return jsonify({"error": "IP is required"}), 400
        
    if IPBlacklist.query.filter_by(ip_address=ip).first():
        return jsonify({"message": "IP already blacklisted"}), 200
        
    new_entry = IPBlacklist(ip_address=ip, reason=reason)
    db.session.add(new_entry)
    db.session.commit()
    return jsonify({"message": f"IP {ip} blacklisted successfully"}), 201

if __name__ == '__main__':
    from waitress import serve
    port = int(os.environ.get('PORT', 5000))
    print(f"AEGIS SOC ENGINE v2 (AI POWERED) RUNNING on 0.0.0.0:{port}")
    serve(app, host='0.0.0.0', port=port)
