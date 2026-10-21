"""
Unit and integration tests for HoneyBank user authentication and sessions
across both the Banking Honeypot and Threat Monitoring Dashboard.
"""

import sys
import os
import unittest

# Ensure repo root is on sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from config import FAKE_ACCOUNTS, DASHBOARD_USERS
from web.app import app as web_app
from dashboard.app import app as dash_app
from core.detector import _blacklist, _request_times, _failed_logins


class TestMonitoringDashboardAuth(unittest.TestCase):
    def setUp(self):
        dash_app.testing = True
        self.client = dash_app.test_client()

    def test_unauthenticated_redirect(self):
        """Unauthenticated user accessing / should be redirected to /login"""
        response = self.client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertTrue("/login" in response.headers.get("Location", ""))

    def test_dashboard_users_login(self):
        """All default dashboard users should be able to log in successfully"""
        for username, data in DASHBOARD_USERS.items():
            with dash_app.test_client() as client:
                res = client.post(
                    "/login",
                    data={"username": username, "password": data["password"]},
                    follow_redirects=True
                )
                self.assertEqual(res.status_code, 200)
                body = res.get_data(as_text=True)
                self.assertIn("Threat Monitor", body)
                self.assertIn(data["name"], body)
                self.assertIn(data["role"], body)

    def test_invalid_dashboard_login(self):
        """Invalid credentials should show error message and deny access"""
        res = self.client.post(
            "/login",
            data={"username": "admin", "password": "wrong_password"},
            follow_redirects=True
        )
        self.assertEqual(res.status_code, 200)
        body = res.get_data(as_text=True)
        self.assertIn("Invalid username or password", body)

    def test_authenticated_api_access(self):
        """Authenticated session should be able to access api endpoints"""
        with dash_app.test_client() as client:
            client.post("/login", data={"username": "analyst", "password": "analyst123"})
            res = client.get("/api/stats")
            self.assertEqual(res.status_code, 200)
            json_data = res.get_json()
            self.assertIn("total_attacks", json_data)


class TestWebHoneypotAuth(unittest.TestCase):
    def setUp(self):
        web_app.testing = True
        self.client = web_app.test_client()
        _blacklist.clear()
        _request_times.clear()
        _failed_logins.clear()

    def tearDown(self):
        _blacklist.clear()
        _request_times.clear()
        _failed_logins.clear()

    def test_unauthenticated_redirect(self):
        """Unauthenticated access to /dashboard should redirect to /login"""
        res = self.client.get("/dashboard", follow_redirects=False)
        self.assertEqual(res.status_code, 302)
        self.assertTrue("/login" in res.headers.get("Location", ""))

    def test_login_with_full_email(self):
        """Test logging in with full email for all accounts"""
        for email, acc in FAKE_ACCOUNTS.items():
            with web_app.test_client() as client:
                res = client.post(
                    "/login",
                    data={"username": email, "password": acc["password"]},
                    follow_redirects=True
                )
                self.assertEqual(res.status_code, 200)
                body = res.get_data(as_text=True)
                self.assertIn("Welcome,", body)
                self.assertIn(acc["balance"], body)
                self.assertIn(acc["account"], body)

    def test_login_with_username_prefix(self):
        """Test logging in with username alias (e.g. 'john.doe' instead of 'john.doe@securebank.com')"""
        test_aliases = [
            ("john.doe", "password123", "$24,890.50"),
            ("sarah.smith", "sarah2024", "$84,340.00"),
            ("demo", "demo1234", "$5,250.75"),
            ("finance", "acme2024", "$154,200.00"),
            ("alex.morgan", "alex2024", "$1,820.40"),
        ]
        for uname, pwd, balance in test_aliases:
            with web_app.test_client() as client:
                res = client.post(
                    "/login",
                    data={"username": uname, "password": pwd},
                    follow_redirects=True
                )
                self.assertEqual(res.status_code, 200)
                body = res.get_data(as_text=True)
                self.assertIn(balance, body)

    def test_invalid_bank_login(self):
        """Invalid credentials should show error message"""
        res = self.client.post(
            "/login",
            data={"username": "john.doe@securebank.com", "password": "wrongpassword"},
            follow_redirects=True
        )
        self.assertEqual(res.status_code, 200)
        body = res.get_data(as_text=True)
        self.assertIn("Invalid username or password", body)


if __name__ == "__main__":
    unittest.main()
