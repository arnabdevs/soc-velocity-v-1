import requests
import os
from datetime import datetime
from models import db, IPBlacklist, BreachLog
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_KEY = os.getenv('ABUSEIPDB_API_KEY')
XPOSED_API_URL = "https://xposedornot.p.rapidapi.com/v1/check-email" # Example endpoint

class IntelSync:
    @staticmethod
    def sync_abuse_ipdb():
        """Fetches the latest malicious IPs from AbuseIPDB and updates the local blacklist."""
        if not ABUSEIPDB_KEY or ABUSEIPDB_KEY == "YOUR_KEY_HERE":
            print("⚠️ AbuseIPDB Key missing. Skipping sync.")
            return

        url = 'https://api.abuseipdb.com/api/v2/blacklist'
        headers = {
            'Accept': 'application/json',
            'Key': ABUSEIPDB_KEY
        }
        params = {
            'confidenceMinimum': 90,
            'limit': 1000
        }

        try:
            response = requests.get(url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()
                new_ips = 0
                for item in data.get('data', []):
                    ip = item.get('ipAddress')
                    if not IPBlacklist.query.filter_by(ip_address=ip).first():
                        entry = IPBlacklist(ip_address=ip, reason=f"AbuseIPDB Confidence: {item.get('abuseConfidenceScore')}%")
                        db.session.add(entry)
                        new_ips += 1
                
                db.session.commit()
                print(f"✅ Sync Complete: Added {new_ips} new malicious IPs from Global Intelligence.")
            else:
                print(f"❌ AbuseIPDB Sync Failed: {response.status_code}")
        except Exception as e:
            print(f"❌ Sync Error: {e}")

    @staticmethod
    def check_live_breach(email):
        """Checks a live open-source breach database (XposedOrNot)."""
        # Using the free XposedOrNot public API which doesn't always require a key for basic checks
        url = f"https://api.xposedornot.com/v1/check-email/{email}"
        
        try:
            resp = requests.get(url)
            if resp.status_code == 200:
                data = resp.json()
                breaches = data.get('breaches', [])
                return {
                    "pwned": True,
                    "count": len(breaches),
                    "breaches": [{"name": b, "year": "Unknown"} for b in breaches]
                }
            elif resp.status_code == 404:
                return {"pwned": False, "count": 0, "breaches": []}
        except:
            pass
        return None
