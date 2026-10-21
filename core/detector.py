"""
HoneyBank - Attack Detector
Identifies attack patterns: SQLi, XSS, Path Traversal, Brute Force, Scanners
"""

import re
import time
from collections import defaultdict
from config import BRUTE_FORCE_THRESHOLD, SCAN_RATE_THRESHOLD

# ─── In-memory tracking (use Redis for production) ─────────────────────
_failed_logins = defaultdict(int)          # {ip: count}
_request_times = defaultdict(list)         # {ip: [timestamps]}
_blacklist = set()                         # Blocked IPs

# ─── Attack Signatures ─────────────────────────────────────────────────

SQLI_PATTERNS = [
    r"('|\")\s*(or|and)\s*('|\"|1|--|#)",     # Classic OR/AND injection
    r"union\s+select",                         # UNION SELECT
    r"(drop|delete|insert|update)\s+\w+",      # DML injection
    r"--\s*$",                                  # Comment injection
    r";\s*(drop|select|insert)",               # Stacked queries
    r"sleep\s*\(\d+\)",                        # Time-based blind SQLi
    r"benchmark\s*\(",                         # MySQL benchmark
    r"information_schema",                      # Schema enumeration
    r"xp_cmdshell",                            # MSSQL command exec
    r"load_file\s*\(",                         # File read via SQL
    r"0x[0-9a-fA-F]{4,}",                     # Hex encoding
]

XSS_PATTERNS = [
    r"<script.*?>",                            # Script tag
    r"javascript\s*:",                         # JS protocol
    r"on\w+\s*=\s*[\"']",                     # Event handlers (onerror=, onload=)
    r"<iframe.*?>",                            # iFrame injection
    r"<img.*?src.*?=",                         # Image tag XSS
    r"eval\s*\(",                              # eval()
    r"document\.(cookie|write|location)",      # DOM access
    r"alert\s*\(",                             # Classic alert() XSS test
    r"<svg.*?on\w+",                           # SVG-based XSS
]

PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",                                  # Directory traversal
    r"\.\.\\",                                 # Windows traversal
    r"%2e%2e%2f",                             # URL encoded ../
    r"%252e%252e",                             # Double URL encoded
    r"/etc/passwd",                            # Linux password file
    r"/etc/shadow",                            # Linux shadow file
    r"c:\\windows\\system32",                  # Windows system path
    r"boot\.ini",                             # Windows boot config
    r"win\.ini",                               # Windows config
]

SCANNER_USER_AGENTS = [
    r"sqlmap", r"nikto", r"nmap", r"masscan",
    r"hydra", r"metasploit", r"burpsuite", r"dirbuster",
    r"gobuster", r"nessus", r"openvas", r"acunetix",
    r"w3af", r"havij", r"pangolin", r"python-requests",
    r"curl/", r"wget/", r"scrapy", r"zgrab",
]

SENSITIVE_PATHS = [
    "/admin", "/admin/", "/wp-admin", "/phpmyadmin",
    "/.env", "/config.php", "/backup", "/db",
    "/shell", "/cmd", "/webshell", "/uploads",
    "/wp-login.php", "/xmlrpc.php", "/.git",
    "/api/admin", "/actuator", "/console",
]


def _match_patterns(text: str, patterns: list) -> str:
    """Return the first matching pattern or empty string."""
    text_lower = text.lower()
    for pattern in patterns:
        if re.search(pattern, text_lower, re.IGNORECASE):
            return pattern
    return ""


def detect_sqli(payload: str) -> dict:
    """Detect SQL injection attempts."""
    match = _match_patterns(payload, SQLI_PATTERNS)
    if match:
        return {"detected": True, "pattern": match, "attack_type": "SQL_INJECTION", "severity": "HIGH"}
    return {"detected": False}


def detect_xss(payload: str) -> dict:
    """Detect Cross-Site Scripting attempts."""
    match = _match_patterns(payload, XSS_PATTERNS)
    if match:
        return {"detected": True, "pattern": match, "attack_type": "XSS", "severity": "MEDIUM"}
    return {"detected": False}


def detect_path_traversal(path: str) -> dict:
    """Detect directory/path traversal attempts."""
    match = _match_patterns(path, PATH_TRAVERSAL_PATTERNS)
    if match:
        return {"detected": True, "pattern": match, "attack_type": "PATH_TRAVERSAL", "severity": "HIGH"}
    return {"detected": False}


def detect_scanner(user_agent: str) -> dict:
    """Detect known scanning/hacking tools from user-agent."""
    match = _match_patterns(user_agent, SCANNER_USER_AGENTS)
    if match:
        return {"detected": True, "tool": match, "attack_type": "SCANNER_DETECTED", "severity": "MEDIUM"}
    return {"detected": False}


def detect_sensitive_path(path: str) -> dict:
    """Detect probing of sensitive/hidden paths."""
    path_lower = path.lower().rstrip("/")
    for sensitive in SENSITIVE_PATHS:
        if path_lower == sensitive or path_lower.startswith(sensitive + "/"):
            return {"detected": True, "path": path, "attack_type": "SENSITIVE_PATH_PROBE", "severity": "MEDIUM"}
    return {"detected": False}


def track_brute_force(ip: str, success: bool) -> dict:
    """
    Track login attempts per IP.
    Returns brute force detection result.
    """
    if not success:
        _failed_logins[ip] += 1
    else:
        # Reset failed attempt count for IP on successful authentication
        _failed_logins[ip] = 0

    count = _failed_logins[ip]
    if count >= BRUTE_FORCE_THRESHOLD:
        severity = "CRITICAL" if count >= BRUTE_FORCE_THRESHOLD * 3 else "HIGH"
        return {
            "detected": True,
            "attack_type": "BRUTE_FORCE",
            "ip": ip,
            "failed_attempts": count,
            "severity": severity
        }
    return {"detected": False, "failed_attempts": count}


def track_scan_rate(ip: str) -> dict:
    """
    Track request rate per IP to detect port/path scanners.
    Returns scan detection result.
    """
    now = time.time()
    _request_times[ip].append(now)

    # Keep only last 60 seconds of requests
    _request_times[ip] = [t for t in _request_times[ip] if now - t < 60]
    rate = len(_request_times[ip])

    if rate >= SCAN_RATE_THRESHOLD:
        return {
            "detected": True,
            "attack_type": "PORT_SCAN",
            "ip": ip,
            "requests_per_minute": rate,
            "severity": "HIGH"
        }
    return {"detected": False, "requests_per_minute": rate}


def analyze_request(ip: str, path: str, method: str, params: dict, user_agent: str) -> list:
    """
    Run all detectors against an incoming request.
    Returns a list of detected threats (may be empty if clean).
    """
    threats = []
    all_params = " ".join(str(v) for v in params.values())

    # 1. Scanner user-agent check
    scanner = detect_scanner(user_agent)
    if scanner["detected"]:
        threats.append(scanner)

    # 2. Path traversal check
    traversal = detect_path_traversal(path)
    if traversal["detected"]:
        threats.append(traversal)

    # 3. Sensitive path probe
    sensitive = detect_sensitive_path(path)
    if sensitive["detected"]:
        threats.append(sensitive)

    # 4. SQLi check on all params
    sqli = detect_sqli(all_params)
    if sqli["detected"]:
        threats.append(sqli)

    # 5. XSS check on all params
    xss = detect_xss(all_params)
    if xss["detected"]:
        threats.append(xss)

    # 6. Scan rate check
    rate = track_scan_rate(ip)
    if rate["detected"]:
        threats.append(rate)

    return threats


def is_blacklisted(ip: str) -> bool:
    """Check if an IP is blacklisted."""
    return ip in _blacklist


def blacklist_ip(ip: str):
    """Add an IP to the blacklist."""
    _blacklist.add(ip)
    print(f"[BLACKLIST] IP {ip} has been blacklisted")


def get_failed_logins(ip: str) -> int:
    """Get number of failed login attempts for an IP."""
    return _failed_logins.get(ip, 0)


def reset_failed_logins(ip: str):
    """Reset failed login counter for an IP (on successful login)."""
    if ip in _failed_logins:
        del _failed_logins[ip]
