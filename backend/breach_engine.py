from intel_sync import IntelSync

class BreachEngine:
    def __init__(self):
        # Simulated high-profile breach datasets
        self.known_breaches = [
            {"name": "Adobe", "year": 2013, "data_leaked": ["Email", "Password Hints", "Usernames"]},
            {"name": "Canva", "year": 2019, "data_leaked": ["Email", "Name", "Passwords"]},
            {"name": "LinkedIn", "year": 2012, "data_leaked": ["Email", "Passwords"]},
            {"name": "MySpace", "year": 2008, "data_leaked": ["Email", "Passwords", "Usernames"]},
            {"name": "Dropbox", "year": 2012, "data_leaked": ["Email", "Passwords"]}
        ]

    def check_email(self, email):
        """
        Tries a live check first, then falls back to simulation.
        """
        live_result = IntelSync.check_live_breach(email)
        if live_result and live_result['pwned']:
            live_result['checked_at'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            return live_result

        email_hash = hashlib.md5(email.lower().encode()).hexdigest()
        # Seed random with hash for consistent results for same email
        random.seed(int(email_hash[:8], 16))
        
        is_pwned = random.random() > 0.4 # 60% chance of being found in a breach
        breaches_found = []
        
        if is_pwned:
            num_breaches = random.randint(1, 4)
            breaches_found = random.sample(self.known_breaches, num_breaches)
            
        return {
            "pwned": is_pwned,
            "count": len(breaches_found),
            "breaches": breaches_found,
            "checked_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        }

def simulate_real_time_attacks(target):
    """
    Simulates real-time attack attempts for a given target to show 
    active threat hunting in the dashboard.
    """
    attacks = [
        "Brute Force Attempt",
        "Credential Stuffing",
        "Directory Traversal",
        "Path Discovery",
        "DNS Tunneling Attempt"
    ]
    
    if random.random() > 0.7:
        return {
            "type": random.choice(attacks),
            "severity": "High" if random.random() > 0.5 else "Medium",
            "timestamp": datetime.utcnow().strftime("%H:%M:%S"),
            "origin": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        }
    return None
