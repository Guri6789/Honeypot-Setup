"""
HoneyBank - Configuration
All settings for the honeypot system
"""

import os

# ─── Project Root (absolute) ───────────────────────────────────────────
_BASE = os.path.dirname(os.path.abspath(__file__))

# ─── Bank Portal Config ────────────────────────────────────────────────
BANK_NAME = "SecureBank"
BANK_PORT = 8080           # Fake banking web portal port
ADMIN_PATH = "/admin"      # Hidden admin panel path
API_BASE = "/api/v1"       # Fake API base path

# ─── SSH Trap Config ───────────────────────────────────────────────────
SSH_TRAP_PORT = 2222       # Fake SSH server port
SSH_HOST_KEY = os.path.join(_BASE, "data", "ssh_host_rsa.key")

# ─── Logging Config ────────────────────────────────────────────────────
LOG_DIR = os.path.join(_BASE, "data", "logs")
PAYLOAD_DIR = os.path.join(_BASE, "data", "payloads")
LOG_FILE = os.path.join(LOG_DIR, "attacks.json")
BRUTE_LOG = os.path.join(LOG_DIR, "bruteforce.json")

# ─── Detection Thresholds ──────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD = 5      # Failed logins before flagging
SCAN_RATE_THRESHOLD = 20       # Requests/min before flagging as scanner
BLOCK_REPEAT_OFFENDERS = True  # Auto-blacklist repeat attackers

# ─── Threat Intelligence ───────────────────────────────────────────────
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")   # Optional: AbuseIPDB API key
GEOIP_DB_PATH = os.path.join(_BASE, "data", "GeoLite2-City.mmdb")

# ─── Alerting Config ───────────────────────────────────────────────────
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")  # Optional: Discord webhook
ALERT_EMAIL = os.getenv("ALERT_EMAIL", "")                  # Optional: Email alerts
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = 587
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")

# ─── Monitoring Dashboard ──────────────────────────────────────────────
DASHBOARD_PORT = 5000
DASHBOARD_SECRET = os.getenv("DASHBOARD_SECRET", "changeme_dashboard_pass")

# Default credentials for the Threat Monitoring Dashboard (Port 5000)
DASHBOARD_USERS = {
    "admin": {
        "password": os.getenv("DASHBOARD_ADMIN_PASSWORD", "admin123"),
        "name": "Security Administrator",
        "role": "Administrator",
        "email": "sec-admin@honeynet.local"
    },
    "analyst": {
        "password": os.getenv("DASHBOARD_ANALYST_PASSWORD", "analyst123"),
        "name": "SOC Incident Analyst",
        "role": "SOC Analyst",
        "email": "soc-analyst@honeynet.local"
    },
    "auditor": {
        "password": os.getenv("DASHBOARD_AUDITOR_PASSWORD", "auditor123"),
        "name": "Security Compliance Auditor",
        "role": "Auditor",
        "email": "auditor@honeynet.local"
    }
}

# ─── Fake Bank Data (Decoy Users for Port 8080) ─────────────────────────
FAKE_ACCOUNTS = {
    "john.doe@securebank.com": {
        "username": "john.doe",
        "name": "John Doe",
        "password": "password123",
        "balance": "$24,890.50",
        "savings": "$12,500.00",
        "credit": "$8,250.00",
        "account": "****4521",
        "account_type": "Personal Checking",
        "transactions": [
            {"icon": "🛒", "name": "Amazon Purchase", "date": "Sep 20, 2026", "amount": "-$89.99", "type": "debit"},
            {"icon": "💼", "name": "Salary Deposit — TechCorp", "date": "Sep 15, 2026", "amount": "+$3,450.00", "type": "credit"},
            {"icon": "⚡", "name": "City Power & Light", "date": "Sep 12, 2026", "amount": "-$142.50", "type": "debit"},
            {"icon": "☕", "name": "Starbucks Coffee", "date": "Sep 10, 2026", "amount": "-$6.75", "type": "debit"},
            {"icon": "🏧", "name": "Downtown ATM Withdrawal", "date": "Sep 08, 2026", "amount": "-$200.00", "type": "debit"},
        ]
    },
    "sarah.smith@securebank.com": {
        "username": "sarah.smith",
        "name": "Sarah Smith",
        "password": "sarah2024",
        "balance": "$84,340.00",
        "savings": "$250,000.00",
        "credit": "$35,000.00",
        "account": "****7823",
        "account_type": "Premier Private Wealth",
        "transactions": [
            {"icon": "📈", "name": "Vanguard Dividend Payout", "date": "Sep 22, 2026", "amount": "+$2,840.00", "type": "credit"},
            {"icon": "✈️", "name": "Lufthansa Flight Booking", "date": "Sep 18, 2026", "amount": "-$1,250.00", "type": "debit"},
            {"icon": "🏨", "name": "Grand Hotel Lausanne", "date": "Sep 17, 2026", "amount": "-$680.00", "type": "debit"},
            {"icon": "💼", "name": "Consulting Retainer", "date": "Sep 05, 2026", "amount": "+$12,000.00", "type": "credit"},
        ]
    },
    "demo@securebank.com": {
        "username": "demo",
        "name": "Demo User",
        "password": "demo1234",
        "balance": "$5,250.75",
        "savings": "$1,500.00",
        "credit": "$3,000.00",
        "account": "****1102",
        "account_type": "Everyday Checking",
        "transactions": [
            {"icon": "🛒", "name": "Grocery Superstore", "date": "Sep 21, 2026", "amount": "-$64.30", "type": "debit"},
            {"icon": "🎬", "name": "Netflix Subscription", "date": "Sep 15, 2026", "amount": "-$15.99", "type": "debit"},
            {"icon": "💼", "name": "Direct Deposit", "date": "Sep 14, 2026", "amount": "+$1,850.00", "type": "credit"},
            {"icon": "📱", "name": "Mobile Carrier Bill", "date": "Sep 09, 2026", "amount": "-$45.00", "type": "debit"},
        ]
    },
    "alex.morgan@securebank.com": {
        "username": "alex.morgan",
        "name": "Alex Morgan",
        "password": "alex2024",
        "balance": "$1,820.40",
        "savings": "$450.00",
        "credit": "$1,500.00",
        "account": "****9941",
        "account_type": "Student Advantage",
        "transactions": [
            {"icon": "📚", "name": "Campus Bookstore", "date": "Sep 19, 2026", "amount": "-$135.20", "type": "debit"},
            {"icon": "🍕", "name": "Campus Pizza Cafe", "date": "Sep 16, 2026", "amount": "-$18.50", "type": "debit"},
            {"icon": "💼", "name": "Campus Work Study", "date": "Sep 12, 2026", "amount": "+$620.00", "type": "credit"},
        ]
    },
    "finance@acmecorp.com": {
        "username": "finance",
        "name": "Acme Corp Treasury",
        "password": "acme2024",
        "balance": "$154,200.00",
        "savings": "$500,000.00",
        "credit": "$100,000.00",
        "account": "****6300",
        "account_type": "Commercial Corporate Treasury",
        "transactions": [
            {"icon": "💰", "name": "Client Invoice Settlement #891", "date": "Sep 22, 2026", "amount": "+$48,500.00", "type": "credit"},
            {"icon": "👥", "name": "Bi-Weekly Payroll Processing", "date": "Sep 15, 2026", "amount": "-$62,400.00", "type": "debit"},
            {"icon": "🏢", "name": "Commercial Office Lease", "date": "Sep 01, 2026", "amount": "-$14,500.00", "type": "debit"},
        ]
    },
    "admin@securebank.com": {
        "username": "admin",
        "name": "System Administrator",
        "password": "admin",
        "balance": "$0.00",
        "savings": "$0.00",
        "credit": "$0.00",
        "account": "****0000",
        "account_type": "Decoy Admin Account",
        "transactions": []
    }
}
FAKE_DB_VERSION = "MySQL 5.7.32"
