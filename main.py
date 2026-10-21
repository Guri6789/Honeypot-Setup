"""
HoneyBank - Main Launcher
Starts all honeypot services in parallel threads
"""

import threading
import sys
import os
import time

# ─── Ensure project root is always in sys.path ─────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from config import BANK_NAME, BANK_PORT, SSH_TRAP_PORT, DASHBOARD_PORT


def start_web_honeypot():
    """Start the fake banking web portal."""
    from web.app import app
    print(f"[*] {BANK_NAME} Web Portal → http://0.0.0.0:{BANK_PORT}")
    app.run(host="0.0.0.0", port=BANK_PORT, debug=False, use_reloader=False)


def start_ssh_trap():
    """Start the fake SSH server."""
    from services.ssh_trap import start_ssh_trap as _start
    print(f"[*] SSH Trap → port {SSH_TRAP_PORT}")
    _start()


def start_dashboard():
    """Start the monitoring dashboard."""
    from dashboard.app import app as dash_app
    print(f"[*] Monitoring Dashboard → http://0.0.0.0:{DASHBOARD_PORT}")
    dash_app.run(host="0.0.0.0", port=DASHBOARD_PORT, debug=False, use_reloader=False)


if __name__ == "__main__":
    print("=" * 55)
    print(f"   🍯 HoneyBank Honeypot System Starting...")
    print("=" * 55)

    threads = [
        threading.Thread(target=start_web_honeypot, name="WebHoneypot", daemon=True),
        threading.Thread(target=start_ssh_trap,     name="SSHTrap",      daemon=True),
        threading.Thread(target=start_dashboard,    name="Dashboard",    daemon=True),
    ]

    for t in threads:
        t.start()
        time.sleep(0.8)  # Stagger startup to avoid import conflicts

    print("\n" + "=" * 65)
    print("  ✅ All services running!")
    print(f"  🏦 Banking Portal  → http://localhost:{BANK_PORT}")
    print("     Default users:  john.doe:password123 | sarah.smith:sarah2024")
    print("                     demo:demo1234        | finance:acme2024")
    print(f"  📊 Dashboard       → http://localhost:{DASHBOARD_PORT}")
    print("     Operators:      admin:admin123       | analyst:analyst123")
    print(f"  🔒 SSH Trap        → port {SSH_TRAP_PORT}")
    print("  📁 Logs            → data/logs/")
    print("=" * 65)
    print("  Press Ctrl+C to stop all services\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down HoneyBank...")
        sys.exit(0)
