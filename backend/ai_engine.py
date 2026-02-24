import re
import numpy as np

class ThreatDetector:
    def __init__(self):
        # Weighted patterns for common attacks
        self.sqli_patterns = [
            r"'.*--", r"'.*OR.*'1'='1'", r"UNION.*SELECT", r"DROP.*TABLE",
            r"SLEEP\(", r"BENCHMARK\(", r"INFORMATION_SCHEMA"
        ]
        self.xss_patterns = [
            r"<script>", r"onerror=", r"onload=", r"javascript:", r"alert\("
        ]
        
    def analyze_request(self, payload):
        """
        AI-inspired heuristic scoring engine.
        Returns a threat score and detection details.
        """
        score = 0.0
        details = []
        
        if not payload:
            return 0.0, []

        # Check for SQL Injection patterns
        for pattern in self.sqli_patterns:
            if re.search(pattern, str(payload), re.IGNORECASE):
                score += 0.4
                details.append("SQL Injection Pattern Detected")
        
        # Check for XSS patterns
        for pattern in self.xss_patterns:
            if re.search(pattern, str(payload), re.IGNORECASE):
                score += 0.3
                details.append("XSS Pattern Detected")
        
        # Multiplier for high-frequency special characters (typical of obfuscation)
        special_char_ratio = len(re.findall(r"[%'\"<>&;#]", str(payload))) / len(str(payload)) if payload else 0
        if special_char_ratio > 0.1:
            score += special_char_ratio * 0.5
            details.append(f"High Anomaly Score (Char Ratio: {special_char_ratio:.2f})")
            
        return min(1.0, score), list(set(details))

def detect_malware(content):
    """
    Scans content for common malware/virus indicators.
    """
    malware_sigs = [
        r"eval\(.*base64_decode", r"document\.write\(unescape",
        r"hidden.*iframe", r"powershell.*-ExecutionPolicy",
        r"system\(\"ping.*-n.*1"
    ]
    
    hits = []
    for sig in malware_sigs:
        if re.search(sig, str(content), re.IGNORECASE):
            hits.append(f"Malicious Signature: {sig}")
            
    return hits
