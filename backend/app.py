from flask import Flask, jsonify, request
from flask_cors import CORS
import sys
import os
import random
import json
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Security Configuration
API_KEY = os.environ.get('AEGIS_API_KEY', 'AEGIS-MASTER-KEY-2026')

def require_api_key(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        provided_key = request.headers.get('X-API-Key')
        
        # Allow Guest Access for GET (Read-Only)
        if request.method == 'GET' and provided_key == 'GUEST_ACCESS':
            return f(*args, **kwargs)
            
        # Require Master Key for everything else (POST/Simulate)
        if provided_key != API_KEY:
            return jsonify({"error": "Unauthorized: Master Access Required"}), 401
        return f(*args, **kwargs)
    return decorated_function

# Fallback Data Generators
def generate_mock_alert(atype=None):
    types = ["PortScan", "BruteForce", "Anomaly", "SQL Injection", "DDoS Attack", "Credential Stuffing", "BENIGN"]
    severities = {
        "PortScan": "Medium", 
        "BruteForce": "High", 
        "Anomaly": "Critical", 
        "SQL Injection": "Critical",
        "DDoS Attack": "High",
        "Credential Stuffing": "Medium",
        "BENIGN": "Low"
    }
    techniques = {
        "PortScan": {"id": "T1046", "name": "Network Service Scanning", "desc": "Adversaries may attempt to get a listing of services running on remote hosts."},
        "BruteForce": {"id": "T1110", "name": "Brute Force", "desc": "Adversaries may use brute force techniques to gain access to accounts."},
        "Anomaly": {"id": "T1000", "name": "Unknown Anomaly", "desc": "The system detected behavior that deviates significantly from normal traffic patterns."},
        "SQL Injection": {"id": "T1190", "name": "SQL Injection", "desc": "Adversary inserts malicious SQL queries into input fields to manipulate the database."},
        "DDoS Attack": {"id": "T1498", "name": "Network Denial of Service", "desc": "Adversary floods the network with traffic to cause service unavailability."},
        "Credential Stuffing": {"id": "T1110.004", "name": "Credential Stuffing", "desc": "Adversary uses stolen credentials to gain unauthorized access to accounts."},
        "BENIGN": {"id": "N/A", "name": "Normal Traffic", "desc": "Normal network behavior."}
    }
    
    if not atype:
        atype = random.choices(types, weights=[15, 10, 5, 15, 15, 10, 30])[0]
        
    tech = techniques[atype]
    sites = ["clint-portfolio.com", "clint-shop.net", "clint-internal-api.dev", "clint-website.com"]
    
    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "alert_id": os.urandom(4).hex(),
        "type": atype,
        "severity": severities[atype],
        "confidence": random.randint(70, 99),
        "mitre_technique": tech["id"],
        "technique_name": tech["name"],
        "description": tech["desc"],
        "target_site": random.choice(sites)
    }

# Keep track of simulated threats for immediate retrieval
simulated_threat_queue = []

@app.route('/api/simulate', methods=['POST'])
@require_api_key
def simulate_threat():
    target_type = request.json.get('type', 'SQL Injection')
    alert = generate_mock_alert(target_type)
    simulated_threat_queue.append(alert)
    return jsonify({"status": "Simulation triggered", "alert": alert})

@app.route('/api/alerts/recent', methods=['GET'])
@require_api_key
def get_recent_alerts():
    global simulated_threat_queue
    # Return 3 random ones + all simulated ones from the queue
    alerts = simulated_threat_queue + [generate_mock_alert() for _ in range(3)]
    simulated_threat_queue = [] # Clear queue after fetch
    return jsonify(alerts)

@app.route('/api/stats', methods=['GET'])
@require_api_key
def get_stats():
    return jsonify({
        "total_analyzed": random.randint(100000, 500000),
        "threats_blocked": random.randint(1200, 5000),
        "active_anomalies": random.randint(0, 5),
        "system_health": "Optimal"
    })

@app.route('/api/logs', methods=['GET'])
@require_api_key
def get_logs():
    search = request.args.get('search', '').lower()
    logs = [generate_mock_alert() for _ in range(20)]
    if search:
        logs = [l for l in logs if search in l['type'].lower() or search in l['alert_id'].lower()]
    return jsonify(logs)

@app.route('/api/ml/metrics', methods=['GET'])
@require_api_key
def get_ml_metrics():
    # Features derived from CICIDS
    features = ["Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts", "Flow Byts/s", "Flow Pkts/s", "Fwd Pkt Len Max", "Bwd Pkt Len Max", "Init Win Fwd Byts"]
    importances = [0.25, 0.18, 0.15, 0.12, 0.10, 0.08, 0.07, 0.05]
    return jsonify({
        "features": features,
        "importances": importances
    })

if __name__ == '__main__':
    from waitress import serve
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '0.0.0.0')
    print(f"SOC ENGINE API RUNNING IN PRODUCTION (Waitress) on {host}:{port}")
    serve(app, host=host, port=port)
