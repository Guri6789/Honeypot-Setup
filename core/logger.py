"""
HoneyBank - Core Logger
Captures and stores all attack data as structured JSON logs
"""

import json
import os
import threading
from datetime import datetime
from config import LOG_DIR, PAYLOAD_DIR, LOG_FILE, BRUTE_LOG

# Thread-safe lock for log writing
_lock = threading.Lock()

# Ensure directories exist
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(PAYLOAD_DIR, exist_ok=True)


def _write_log(filepath: str, entry: dict):
    """Append a JSON log entry to a file (thread-safe)."""
    with _lock:
        with open(filepath, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")


def log_attack(
    ip: str,
    attack_type: str,
    endpoint: str,
    payload: str = "",
    method: str = "GET",
    user_agent: str = "",
    extra: dict = None,
    severity: str = "MEDIUM"
):
    """
    Log a detected attack attempt.

    Args:
        ip:          Attacker's IP address
        attack_type: Type of attack (SQLi, XSS, BruteForce, etc.)
        endpoint:    URL path that was targeted
        payload:     Raw payload sent by attacker
        method:      HTTP method (GET/POST)
        user_agent:  Browser/tool user-agent string
        extra:       Any additional metadata
        severity:    LOW / MEDIUM / HIGH / CRITICAL
    """
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "severity": severity,
        "attack_type": attack_type,
        "ip": ip,
        "endpoint": endpoint,
        "method": method,
        "user_agent": user_agent,
        "payload": payload[:2000],  # Cap payload size
        "extra": extra or {}
    }

    print(f"[{entry['timestamp']}] [{severity}] {attack_type} from {ip} → {endpoint}")
    _write_log(LOG_FILE, entry)

    # Save raw payload separately if it exists
    if payload:
        _save_payload(ip, attack_type, payload)

    return entry


def log_login_attempt(ip: str, username: str, password: str, success: bool, user_agent: str = ""):
    """Log an authentication attempt (brute force tracking)."""
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "ip": ip,
        "username": username,
        "password": password,   # Honeypot: capturing attempted credentials is the point
        "success": success,
        "user_agent": user_agent
    }
    status = "SUCCESS" if success else "FAILED"
    print(f"[AUTH] {status} login attempt — {username}:{password} from {ip}")
    _write_log(BRUTE_LOG, entry)
    return entry


def log_ssh_attempt(ip: str, username: str, password: str):
    """Log an SSH brute force attempt."""
    filepath = os.path.join(LOG_DIR, "ssh_attempts.json")
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "ip": ip,
        "username": username,
        "password": password
    }
    print(f"[SSH] Attempt — {username}:{password} from {ip}")
    _write_log(filepath, entry)
    return entry


def log_scan(ip: str, path: str, user_agent: str = ""):
    """Log a potential scanner/crawler activity."""
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "type": "SCAN",
        "ip": ip,
        "path": path,
        "user_agent": user_agent
    }
    _write_log(os.path.join(LOG_DIR, "scans.json"), entry)
    return entry


def _save_payload(ip: str, attack_type: str, payload: str):
    """Save raw attacker payload to a file for analysis."""
    filename = f"{attack_type}_{ip}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt"
    filepath = os.path.join(PAYLOAD_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(payload)


def get_all_logs() -> list:
    """Read and return all attack logs as a list of dicts."""
    if not os.path.exists(LOG_FILE):
        return []
    logs = []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    logs.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return logs


def get_brute_force_logs() -> list:
    """Read and return all brute force login attempt logs."""
    if not os.path.exists(BRUTE_LOG):
        return []
    logs = []
    with open(BRUTE_LOG, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    logs.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return logs


def get_stats() -> dict:
    """Return summary statistics for the dashboard."""
    logs = get_all_logs()
    brute_logs = get_brute_force_logs()

    attack_counts = {}
    ip_counts = {}

    for log in logs:
        atype = log.get("attack_type", "Unknown")
        ip = log.get("ip", "Unknown")
        attack_counts[atype] = attack_counts.get(atype, 0) + 1
        ip_counts[ip] = ip_counts.get(ip, 0) + 1

    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "total_attacks": len(logs),
        "total_auth_attempts": len(brute_logs),
        "attack_types": attack_counts,
        "top_attacker_ips": top_ips,
        "recent_attacks": logs[-20:][::-1]  # Last 20, newest first
    }
