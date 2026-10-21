#!/usr/bin/env python3
"""
HoneyBank Credential Verification Script
Tests authentication for all default users across both portals:
1. Fake Banking Web Portal (Port 8080)
2. Threat Monitoring Dashboard (Port 5000)

Usage:
    python3 verify_credentials.py
"""

import sys
import os
import requests

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from config import FAKE_ACCOUNTS, DASHBOARD_USERS, BANK_PORT, DASHBOARD_PORT

GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"


def is_live_server_running(port: int) -> bool:
    """Check if the service is running on the given port."""
    try:
        res = requests.get(f"http://127.0.0.1:{port}/login", timeout=1.5)
        return res.status_code == 200
    except Exception:
        return False


def test_via_http():
    """Test directly over live HTTP ports."""
    print(f"\n{BOLD}{CYAN}=== Testing via Live HTTP Sockets (127.0.0.1) ==={RESET}\n")

    # 1. Test Banking Portal (8080)
    print(f"{BOLD}1. 🏦 Testing Fake Banking Web Portal (http://localhost:{BANK_PORT}){RESET}")
    bank_passed = 0
    bank_total = 0

    test_logins = [
        ("john.doe@securebank.com", "password123", "John Doe"),
        ("john.doe",                "password123", "John Doe (alias)"),
        ("sarah.smith@securebank.com", "sarah2024", "Sarah Smith"),
        ("sarah.smith",             "sarah2024", "Sarah Smith (alias)"),
        ("demo@securebank.com",     "demo1234",  "Demo User"),
        ("demo",                    "demo1234",  "Demo User (alias)"),
        ("finance@acmecorp.com",    "acme2024",  "Corporate Treasury"),
        ("finance",                 "acme2024",  "Corporate Treasury (alias)"),
        ("alex.morgan@securebank.com", "alex2024", "Alex Morgan"),
        ("alex.morgan",             "alex2024",  "Alex Morgan (alias)"),
        ("admin@securebank.com",    "admin",     "Decoy Admin"),
    ]

    for username, password, label in test_logins:
        bank_total += 1
        session = requests.Session()
        try:
            res = session.post(
                f"http://127.0.0.1:{BANK_PORT}/login",
                data={"username": username, "password": password},
                allow_redirects=True,
                timeout=3
            )
            if res.status_code == 200 and ("Welcome," in res.text or "dashboard" in res.url):
                print(f"  {GREEN}[✓ PASS]{RESET} {label:<28} -> {username}:{password}")
                bank_passed += 1
            else:
                print(f"  {RED}[✗ FAIL]{RESET} {label:<28} -> {username}:{password}")
        except Exception as e:
            print(f"  {RED}[✗ ERR ]{RESET} {label:<28} -> {e}")

    # 2. Test Monitoring Dashboard (5000)
    print(f"\n{BOLD}2. 📊 Testing Threat Monitoring Dashboard (http://localhost:{DASHBOARD_PORT}){RESET}")
    dash_passed = 0
    dash_total = 0

    for username, data in DASHBOARD_USERS.items():
        dash_total += 1
        password = data["password"]
        role = data["role"]
        name = data["name"]

        session = requests.Session()
        try:
            res = session.post(
                f"http://127.0.0.1:{DASHBOARD_PORT}/login",
                data={"username": username, "password": password},
                allow_redirects=True,
                timeout=3
            )
            if res.status_code == 200 and ("Threat Monitor" in res.text or role in res.text):
                print(f"  {GREEN}[✓ PASS]{RESET} {name} ({role}) -> {username}:{password}")
                dash_passed += 1
            else:
                print(f"  {RED}[✗ FAIL]{RESET} {name} ({role}) -> {username}:{password}")
        except Exception as e:
            print(f"  {RED}[✗ ERR ]{RESET} {name} ({role}) -> {e}")

    return (bank_passed == bank_total) and (dash_passed == dash_total)


def test_via_flask_client():
    """Test directly in-memory via Flask Test Client."""
    print(f"\n{BOLD}{CYAN}=== Testing via In-Memory Flask Test Client ==={RESET}\n")

    from web.app import app as web_app
    from dashboard.app import app as dash_app
    from core.detector import _blacklist, _request_times, _failed_logins

    _blacklist.clear()
    _request_times.clear()
    _failed_logins.clear()

    print(f"{BOLD}1. 🏦 Testing Fake Banking Web Portal{RESET}")
    bank_passed = 0
    bank_total = 0

    test_logins = [
        ("john.doe@securebank.com", "password123", "John Doe"),
        ("john.doe",                "password123", "John Doe (alias)"),
        ("sarah.smith@securebank.com", "sarah2024", "Sarah Smith"),
        ("sarah.smith",             "sarah2024", "Sarah Smith (alias)"),
        ("demo@securebank.com",     "demo1234",  "Demo User"),
        ("demo",                    "demo1234",  "Demo User (alias)"),
        ("finance@acmecorp.com",    "acme2024",  "Corporate Treasury"),
        ("finance",                 "acme2024",  "Corporate Treasury (alias)"),
        ("alex.morgan@securebank.com", "alex2024", "Alex Morgan"),
        ("alex.morgan",             "alex2024",  "Alex Morgan (alias)"),
        ("admin@securebank.com",    "admin",     "Decoy Admin"),
    ]

    for username, password, label in test_logins:
        bank_total += 1
        with web_app.test_client() as client:
            res = client.post("/login", data={"username": username, "password": password}, follow_redirects=True)
            if res.status_code == 200 and "Welcome," in res.get_data(as_text=True):
                print(f"  {GREEN}[✓ PASS]{RESET} {label:<28} -> {username}:{password}")
                bank_passed += 1
            else:
                print(f"  {RED}[✗ FAIL]{RESET} {label:<28} -> {username}:{password}")

    print(f"\n{BOLD}2. 📊 Testing Threat Monitoring Dashboard{RESET}")
    dash_passed = 0
    dash_total = 0

    for username, data in DASHBOARD_USERS.items():
        dash_total += 1
        password = data["password"]
        role = data["role"]
        name = data["name"]

        with dash_app.test_client() as client:
            res = client.post("/login", data={"username": username, "password": password}, follow_redirects=True)
            body = res.get_data(as_text=True)
            if res.status_code == 200 and ("Threat Monitor" in body or role in body):
                print(f"  {GREEN}[✓ PASS]{RESET} {name} ({role}) -> {username}:{password}")
                dash_passed += 1
            else:
                print(f"  {RED}[✗ FAIL]{RESET} {name} ({role}) -> {username}:{password}")

    return (bank_passed == bank_total) and (dash_passed == dash_total)


def print_summary_table():
    print(f"\n{BOLD}{YELLOW}========================================================================{RESET}")
    print(f"{BOLD}                 HONEYBANK DEFAULT USER CREDENTIALS                      {RESET}")
    print(f"{BOLD}{YELLOW}========================================================================{RESET}")

    print(f"\n{BOLD}🏦 1. Fake Banking Web Portal (http://localhost:{BANK_PORT}){RESET}")
    print(f"{'Name':<22} | {'Username / Email':<28} | {'Password':<12} | {'Balance':<12}")
    print("-" * 80)
    for email, data in FAKE_ACCOUNTS.items():
        uname = f"{data.get('username')} / {email}"
        print(f"{data.get('name', 'User'):<22} | {uname:<28} | {data['password']:<12} | {data.get('balance', '$0.00'):<12}")

    print(f"\n{BOLD}📊 2. Threat Monitoring Dashboard (http://localhost:{DASHBOARD_PORT}){RESET}")
    print(f"{'Role':<18} | {'Username':<12} | {'Password':<14} | {'Operator Name':<24}")
    print("-" * 80)
    for username, data in DASHBOARD_USERS.items():
        print(f"{data['role']:<18} | {username:<12} | {data['password']:<14} | {data['name']:<24}")

    print(f"\n{BOLD}{YELLOW}========================================================================{RESET}\n")


if __name__ == "__main__":
    print_summary_table()

    # Check if servers are running on localhost
    if is_live_server_running(BANK_PORT) and is_live_server_running(DASHBOARD_PORT):
        success = test_via_http()
    else:
        print(f"{YELLOW}[!] Live servers are not running on ports {BANK_PORT}/{DASHBOARD_PORT}.{RESET}")
        print(f"    (To start them: run `./run.sh` or `python3 main.py` in another terminal)")
        success = test_via_flask_client()

    if success:
        print(f"\n{BOLD}{GREEN}🎉 All credential tests PASSED successfully!{RESET}\n")
        sys.exit(0)
    else:
        print(f"\n{BOLD}{RED}❌ Some credential tests failed.{RESET}\n")
        sys.exit(1)
