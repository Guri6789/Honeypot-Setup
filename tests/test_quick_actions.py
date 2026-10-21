"""
Tests for HoneyBank Fake Banking Portal Quick Actions:
- Transfer Money (/transfer)
- Pay Bills (/pay-bills, /bills)
- Statements (/statements, /statements/download)
- Support (/support, /contact)
"""

import sys
import os
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from web.app import app as web_app
from core.logger import get_all_logs
from core.detector import _blacklist, _request_times, _failed_logins
from config import FAKE_ACCOUNTS


class TestQuickActions(unittest.TestCase):
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

    def _login_as(self, client, email="john.doe@securebank.com"):
        acc = FAKE_ACCOUNTS[email]
        res = client.post(
            "/login",
            data={"username": email, "password": acc["password"]},
            follow_redirects=True
        )
        self.assertEqual(res.status_code, 200)
        return acc

    # ─── 1. Unauthenticated Redirection Tests ──────────────────────────────

    def test_unauthenticated_quick_actions_redirect(self):
        """All quick action routes should require authentication."""
        protected_routes = [
            "/transfer",
            "/pay-bills",
            "/bills",
            "/statements",
            "/statements/download",
            "/support",
            "/contact",
        ]
        for route in protected_routes:
            res = self.client.get(route, follow_redirects=False)
            self.assertEqual(res.status_code, 302, f"Expected redirect for {route}")
            self.assertIn("/login", res.headers.get("Location", ""))

    # ─── 2. Dashboard Quick Action Links ───────────────────────────────────

    def test_dashboard_contains_all_quick_actions(self):
        """Dashboard page should contain working links to all 4 quick action routes."""
        with web_app.test_client() as client:
            self._login_as(client)
            res = client.get("/dashboard")
            self.assertEqual(res.status_code, 200)
            body = res.get_data(as_text=True)

            self.assertIn('href="/transfer"', body)
            self.assertIn('href="/pay-bills"', body)
            self.assertIn('href="/statements"', body)
            self.assertIn('href="/support"', body)

    # ─── 3. Transfer Money ─────────────────────────────────────────────────

    def test_transfer_get_authenticated(self):
        """GET /transfer displays transfer form with user account info."""
        with web_app.test_client() as client:
            acc = self._login_as(client)
            res = client.get("/transfer")
            self.assertEqual(res.status_code, 200)
            body = res.get_data(as_text=True)

            self.assertIn("Electronic Funds Transfer", body)
            self.assertIn(acc["account"], body)
            self.assertIn(acc["balance"], body)
            self.assertIn('id="recipient-input"', body)
            self.assertIn('id="amount-input"', body)

    def test_transfer_post_logs_attack_and_confirms(self):
        """POST /transfer records attempt in attack logs and returns confirmation."""
        initial_log_count = len(get_all_logs())

        with web_app.test_client() as client:
            self._login_as(client)
            res = client.post(
                "/transfer",
                data={
                    "from_account": "checking",
                    "recipient": "984210948",
                    "recipient_name": "Offshore Merchant Corp",
                    "amount": "2500.00",
                    "speed": "Same-Day Fedwire ($25.00)",
                    "note": "Honeypot transfer simulation test"
                },
                follow_redirects=True
            )
            self.assertEqual(res.status_code, 200)
            body = res.get_data(as_text=True)

            self.assertIn("Transfer of $2500.00 to account 984210948 (Offshore Merchant Corp) has been initiated successfully", body)
            self.assertIn("Confirmation #TR-", body)

            # Verify log entry
            logs = get_all_logs()
            self.assertGreater(len(logs), initial_log_count)
            transfer_logs = [l for l in logs if l.get("attack_type") == "TRANSFER_ATTEMPT"]
            self.assertTrue(len(transfer_logs) > 0)
            latest = transfer_logs[-1]
            self.assertEqual(latest["endpoint"], "/transfer")
            self.assertIn("984210948", latest["payload"])
            self.assertIn("2500.00", latest["payload"])

    # ─── 4. Pay Bills ──────────────────────────────────────────────────────

    def test_pay_bills_get_authenticated(self):
        """GET /pay-bills displays bill payment form and biller options."""
        with web_app.test_client() as client:
            acc = self._login_as(client)
            for path in ["/pay-bills", "/bills"]:
                res = client.get(path)
                self.assertEqual(res.status_code, 200)
                body = res.get_data(as_text=True)
                self.assertIn("Bill Payment Center", body)
                self.assertIn(acc["account"], body)
                self.assertIn("National Grid", body)
                self.assertIn('id="biller-account-input"', body)

    def test_pay_bills_post_logs_attack_and_confirms(self):
        """POST /pay-bills records submission in attack logs and returns confirmation."""
        initial_log_count = len(get_all_logs())

        with web_app.test_client() as client:
            self._login_as(client)
            res = client.post(
                "/pay-bills",
                data={
                    "from_account": "checking",
                    "biller": "National Grid — Electric & Gas",
                    "biller_account": "BILL-84920",
                    "amount": "145.75",
                    "payment_date": "2026-10-25",
                    "frequency": "One-Time",
                    "memo": "October Electric Utility"
                },
                follow_redirects=True
            )
            self.assertEqual(res.status_code, 200)
            body = res.get_data(as_text=True)

            self.assertIn("Payment of $145.75 to National Grid", body)
            self.assertIn("scheduled for 2026-10-25", body)
            self.assertIn("Confirmation #BP-", body)

            # Verify log entry
            logs = get_all_logs()
            self.assertGreater(len(logs), initial_log_count)
            bill_logs = [l for l in logs if l.get("attack_type") == "BILL_PAYMENT_ATTEMPT"]
            self.assertTrue(len(bill_logs) > 0)
            latest = bill_logs[-1]
            self.assertEqual(latest["endpoint"], "/pay-bills")
            self.assertIn("BILL-84920", latest["payload"])
            self.assertIn("145.75", latest["payload"])

    # ─── 5. Statements & CSV Download ──────────────────────────────────────

    def test_statements_get_authenticated(self):
        """GET /statements displays statement ledger and transaction records."""
        with web_app.test_client() as client:
            acc = self._login_as(client)
            res = client.get("/statements")
            self.assertEqual(res.status_code, 200)
            body = res.get_data(as_text=True)

            self.assertIn("Account Statements & Ledger", body)
            self.assertIn(acc["account"], body)
            self.assertIn(acc["balance"], body)
            self.assertIn('id="btn-download-csv"', body)
            self.assertIn("Monthly Statement Archive", body)

            # Verify statement view is logged
            logs = get_all_logs()
            view_logs = [l for l in logs if l.get("attack_type") == "STATEMENT_VIEW"]
            self.assertTrue(len(view_logs) > 0)

    def test_statements_csv_download(self):
        """GET /statements/download returns downloadable CSV with headers and records."""
        initial_log_count = len(get_all_logs())

        with web_app.test_client() as client:
            self._login_as(client)
            res = client.get("/statements/download?period=2026-09&format=csv")
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.mimetype, "text/csv")
            self.assertIn("attachment; filename=", res.headers.get("Content-Disposition", ""))

            csv_text = res.get_data(as_text=True)
            lines = csv_text.strip().splitlines()
            self.assertGreater(len(lines), 1)

            # Header verification
            header = lines[0]
            self.assertIn("Date", header)
            self.assertIn("Transaction ID", header)
            self.assertIn("Description", header)
            self.assertIn("Amount", header)

            # Verify download attempt is logged
            logs = get_all_logs()
            self.assertGreater(len(logs), initial_log_count)
            dl_logs = [l for l in logs if l.get("attack_type") == "STATEMENT_DOWNLOAD"]
            self.assertTrue(len(dl_logs) > 0)
            latest = dl_logs[-1]
            self.assertEqual(latest["endpoint"], "/statements/download")

    # ─── 6. Support & Contact ──────────────────────────────────────────────

    def test_support_get_authenticated(self):
        """GET /support displays customer support contact form and helpline numbers."""
        with web_app.test_client() as client:
            acc = self._login_as(client)
            for path in ["/support", "/contact"]:
                res = client.get(path)
                self.assertEqual(res.status_code, 200)
                body = res.get_data(as_text=True)

                self.assertIn("Client Support & Help Center", body)
                self.assertIn(acc["account"], body)
                self.assertIn('id="form-support-ticket"', body)
                self.assertIn("1-800-555-0199", body)

    def test_support_post_logs_attack_and_confirms(self):
        """POST /support records inquiry submission in attack logs and returns confirmation."""
        initial_log_count = len(get_all_logs())

        with web_app.test_client() as client:
            self._login_as(client)
            res = client.post(
                "/support",
                data={
                    "category": "Fraud & Suspicious Activity Dispute",
                    "priority": "Urgent",
                    "account": "****4521",
                    "email": "john.doe@securebank.com",
                    "subject": "Unrecognized charge inquiry",
                    "message": "I noticed an unrecognized charge and request urgent review."
                },
                follow_redirects=True
            )
            self.assertEqual(res.status_code, 200)
            body = res.get_data(as_text=True)

            self.assertIn("Support inquiry received (Ticket #SUP-", body)

            # Verify log entry
            logs = get_all_logs()
            self.assertGreater(len(logs), initial_log_count)
            supp_logs = [l for l in logs if l.get("attack_type") == "SUPPORT_TICKET_SUBMISSION"]
            self.assertTrue(len(supp_logs) > 0)
            latest = supp_logs[-1]
            self.assertEqual(latest["endpoint"], "/support")
            self.assertIn("Unrecognized charge inquiry", latest["payload"])


if __name__ == "__main__":
    unittest.main()
