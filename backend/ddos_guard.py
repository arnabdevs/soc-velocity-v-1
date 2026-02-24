"""
AEGIS DDoS Guard - Maximum protection for a single-server deployment.
Handles: HTTP floods, slowloris-style attacks, burst requests, repeat offenders.
"""
import time
import threading
from collections import defaultdict, deque
from flask import jsonify

# --- In-memory per-IP tracking (fast, no DB overhead) ---
_lock = threading.Lock()
_request_log = defaultdict(deque)      # IP -> deque of timestamps
_strike_count = defaultdict(int)       # IP -> consecutive violation count
_tarpit_until = defaultdict(float)     # IP -> epoch time when unblocked

# Config
WINDOW_SECONDS = 10          # Sliding window
MAX_REQUESTS_PER_WINDOW = 30 # Max allowed before throttle
BURST_LIMIT = 15             # Max in 2 seconds (burst detection)
BURST_WINDOW = 2
TARPIT_BASE = 10             # Base tarpit seconds
MAX_TARPIT = 3600            # 1 hour max ban

class DDoSGuard:

    @staticmethod
    def check(client_ip):
        """
        Returns (is_blocked, reason, retry_after)
        Call this in before_request.
        """
        now = time.time()

        with _lock:
            # 1. Check if currently tarpitted
            if _tarpit_until[client_ip] > now:
                retry_after = int(_tarpit_until[client_ip] - now)
                return True, "Too many requests. You are temporarily blocked.", retry_after

            # 2. Update sliding window log
            log = _request_log[client_ip]
            log.append(now)

            # Remove old entries outside the window
            while log and log[0] < now - WINDOW_SECONDS:
                log.popleft()

            # 3. Check burst (many requests in 2s)
            burst_count = sum(1 for t in log if t >= now - BURST_WINDOW)
            if burst_count > BURST_LIMIT:
                _strike_count[client_ip] += 1
                tarpit_secs = min(TARPIT_BASE * (2 ** _strike_count[client_ip]), MAX_TARPIT)
                _tarpit_until[client_ip] = now + tarpit_secs
                return True, f"Burst detected. Tarpitted for {tarpit_secs}s.", int(tarpit_secs)

            # 4. Check sustained rate (many requests in window)
            if len(log) > MAX_REQUESTS_PER_WINDOW:
                _strike_count[client_ip] += 1
                tarpit_secs = min(TARPIT_BASE * _strike_count[client_ip], MAX_TARPIT)
                _tarpit_until[client_ip] = now + tarpit_secs
                return True, f"Rate limit exceeded. Blocked for {tarpit_secs}s.", int(tarpit_secs)

            # 5. All clear
            return False, None, 0

    @staticmethod
    def stats():
        """Returns live DDoS statistics."""
        now = time.time()
        with _lock:
            active_tarpits = {ip: int(until - now) for ip, until in _tarpit_until.items() if until > now}
            return {
                "active_blocks": len(active_tarpits),
                "top_blocked_ips": active_tarpits,
                "total_repeat_offenders": sum(1 for s in _strike_count.values() if s > 2)
            }
