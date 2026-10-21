"""
HoneyBank - Alerter
Sends real-time alerts via Discord webhook and/or Email
"""

import json
import smtplib
import threading
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from config import (
    DISCORD_WEBHOOK_URL, ALERT_EMAIL,
    SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASS
)

# Severity → Discord embed color
SEVERITY_COLORS = {
    "LOW":      0x95a5a6,   # Gray
    "MEDIUM":   0xf39c12,   # Orange
    "HIGH":     0xe74c3c,   # Red
    "CRITICAL": 0x8e44ad,   # Purple
}

SEVERITY_EMOJI = {
    "LOW":      "🟡",
    "MEDIUM":   "🟠",
    "HIGH":     "🔴",
    "CRITICAL": "🚨",
}


def send_discord_alert(attack_data: dict):
    """Send a rich embed alert to Discord webhook."""
    if not DISCORD_WEBHOOK_URL or not REQUESTS_AVAILABLE:
        return

    severity = attack_data.get("severity", "MEDIUM")
    attack_type = attack_data.get("attack_type", "Unknown")
    ip = attack_data.get("ip", "Unknown")
    endpoint = attack_data.get("endpoint", "/")
    payload = attack_data.get("payload", "")[:500]
    timestamp = attack_data.get("timestamp", datetime.utcnow().isoformat())

    emoji = SEVERITY_EMOJI.get(severity, "⚠️")
    color = SEVERITY_COLORS.get(severity, 0xf39c12)

    embed = {
        "title": f"{emoji} HoneyBank Alert — {attack_type}",
        "color": color,
        "fields": [
            {"name": "🌐 Attacker IP",   "value": f"`{ip}`",        "inline": True},
            {"name": "⚡ Severity",       "value": severity,          "inline": True},
            {"name": "🎯 Target",         "value": f"`{endpoint}`",  "inline": True},
            {"name": "💣 Payload",        "value": f"```{payload}```" if payload else "N/A", "inline": False},
        ],
        "footer": {"text": "HoneyBank Threat Detection System"},
        "timestamp": timestamp
    }

    payload_data = {"embeds": [embed]}

    def _send():
        try:
            requests.post(
                DISCORD_WEBHOOK_URL,
                data=json.dumps(payload_data),
                headers={"Content-Type": "application/json"},
                timeout=5
            )
        except Exception as e:
            print(f"[ALERTER] Discord webhook failed: {e}")

    threading.Thread(target=_send, daemon=True).start()


def send_email_alert(attack_data: dict):
    """Send an email alert for critical events."""
    if not ALERT_EMAIL or not SMTP_USER or not SMTP_PASS:
        return

    severity = attack_data.get("severity", "MEDIUM")
    if severity not in ("HIGH", "CRITICAL"):
        return  # Only email for high/critical

    attack_type = attack_data.get("attack_type", "Unknown")
    ip = attack_data.get("ip", "Unknown")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[HoneyBank] {severity} Alert — {attack_type} from {ip}"
    msg["From"] = SMTP_USER
    msg["To"] = ALERT_EMAIL

    body = f"""
    HoneyBank Threat Detection Alert
    ================================
    Time:        {attack_data.get('timestamp', 'N/A')}
    Severity:    {severity}
    Attack Type: {attack_type}
    IP Address:  {ip}
    Endpoint:    {attack_data.get('endpoint', 'N/A')}
    Method:      {attack_data.get('method', 'N/A')}
    User-Agent:  {attack_data.get('user_agent', 'N/A')}
    Payload:     {attack_data.get('payload', 'N/A')[:500]}
    """

    msg.attach(MIMEText(body, "plain"))

    def _send():
        try:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASS)
                server.sendmail(SMTP_USER, ALERT_EMAIL, msg.as_string())
                print(f"[ALERTER] Email sent to {ALERT_EMAIL}")
        except Exception as e:
            print(f"[ALERTER] Email failed: {e}")

    threading.Thread(target=_send, daemon=True).start()


def alert(attack_data: dict):
    """
    Main alert function — dispatches to all configured channels.
    Call this after logging an attack.
    """
    send_discord_alert(attack_data)
    send_email_alert(attack_data)
