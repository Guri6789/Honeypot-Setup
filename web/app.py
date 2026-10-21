"""
HoneyBank - Fake Banking Web Portal (Main Honeypot)
A convincing but entirely fake online banking portal that captures attacks
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import csv
import io
from flask import Flask, request, render_template, redirect, url_for, session, jsonify, Response
from functools import wraps

from core.logger import log_attack, log_login_attempt
from core.detector import analyze_request, track_brute_force, is_blacklisted, blacklist_ip
from core.alerter import alert
from core.geoip import enrich_ip
from config import BANK_NAME, BANK_PORT, FAKE_ACCOUNTS, FAKE_DB_VERSION

_WEB_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, template_folder=os.path.join(_WEB_DIR, "templates"))
app.secret_key = "fake_secret_key_honeypot_2024"


# ─── Middleware ─────────────────────────────────────────────────────────

def honeypot_middleware(f):
    """Decorator: analyze every request for threats before handling."""
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        path = request.path
        method = request.method
        user_agent = request.headers.get("User-Agent", "")
        params = {**request.args.to_dict(), **request.form.to_dict()}

        # Block blacklisted IPs
        if is_blacklisted(ip):
            return render_template("blocked.html", bank_name=BANK_NAME), 403

        # Analyze request for threats
        threats = analyze_request(ip, path, method, params, user_agent)

        for threat in threats:
            attack_data = log_attack(
                ip=ip,
                attack_type=threat.get("attack_type", "UNKNOWN"),
                endpoint=path,
                payload=str(params),
                method=method,
                user_agent=user_agent,
                extra=threat,
                severity=threat.get("severity", "MEDIUM")
            )
            alert(attack_data)

            # Auto-blacklist on critical scan rate
            if threat.get("attack_type") == "PORT_SCAN" and threat.get("requests_per_minute", 0) > 50:
                blacklist_ip(ip)

        return f(*args, **kwargs)
    return decorated


def login_required(f):
    """Ensure user is authenticated (fake session)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def find_account(identifier: str):
    """
    Find account by email or username (case-insensitive).
    Returns (account_email, account_dict) or (None, None).
    """
    if not identifier:
        return None, None
    clean_id = identifier.strip().lower()

    for email, data in FAKE_ACCOUNTS.items():
        if email.lower() == clean_id:
            return email, data
        if data.get("username", "").lower() == clean_id:
            return email, data
        if email.lower().split("@")[0] == clean_id:
            return email, data

    return None, None


# ─── Routes ─────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
@honeypot_middleware
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
@honeypot_middleware
def login():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user_agent = request.headers.get("User-Agent", "")

        # Check fake credentials (by email or username)
        matched_email, account = find_account(username)
        success = bool(account and account.get("password") == password)

        log_login_attempt(ip, username, password, success, user_agent)
        brute_result = track_brute_force(ip, success)

        # Log brute force if detected
        if brute_result["detected"]:
            attack_data = log_attack(
                ip=ip,
                attack_type="BRUTE_FORCE",
                endpoint="/login",
                payload=f"username={username}&password={password}",
                method="POST",
                user_agent=user_agent,
                severity=brute_result["severity"]
            )
            alert(attack_data)

        if success:
            session["user"] = matched_email
            session["account"] = account
            return redirect(url_for("dashboard"))
        else:
            # Fake delay to simulate real auth (also slows brute force)
            import time
            time.sleep(1.5)
            error = "Invalid username or password. Please try again."

    return render_template("login.html", bank_name=BANK_NAME, error=error, default_accounts=FAKE_ACCOUNTS)


@app.route("/dashboard", methods=["GET"])
@honeypot_middleware
@login_required
def dashboard():
    user = session.get("user", "Customer")
    account = session.get("account", {})
    return render_template(
        "dashboard.html",
        bank_name=BANK_NAME,
        user=user,
        user_name=account.get("name", user.split('@')[0].replace('.', ' ').title()),
        balance=account.get("balance", "$0.00"),
        savings_balance=account.get("savings", "$0.00"),
        credit_available=account.get("credit", "$0.00"),
        account_number=account.get("account", "****0000"),
        account_type=account.get("account_type", "Standard Checking"),
        transactions=account.get("transactions", [])
    )



def get_account_transactions(user_email: str, account: dict, period: str = "all", tx_type: str = "all") -> list:
    """Return fictional transactions for statements and CSV download."""
    base_txs = account.get("transactions", [])
    enriched = []
    for i, tx in enumerate(base_txs):
        name = tx.get("name", "Account Transaction")
        cat = "Shopping" if any(w in name.lower() for w in ["amazon", "store", "supermarket", "bookstore", "pizza", "coffee", "hotel", "flight"]) else \
              ("Income" if any(w in name.lower() for w in ["salary", "deposit", "dividend", "retainer", "invoice", "study"]) else "Utilities")
        enriched.append({
            "id": f"TXN-202609-{100 + i}",
            "date": tx.get("date", "Sep 15, 2026"),
            "period": "2026-09",
            "name": name,
            "category": cat,
            "type": tx.get("type", "debit"),
            "amount": tx.get("amount", "$0.00"),
            "status": "Cleared",
            "icon": tx.get("icon", "💳")
        })

    username = account.get("username", user_email.split("@")[0].lower())
    if "sarah" in username:
        historical = [
            {"id": "TXN-202608-201", "date": "Aug 28, 2026", "period": "2026-08", "name": "Boutique Fine Dining", "category": "Dining", "type": "debit", "amount": "-$420.00", "status": "Cleared", "icon": "🍷"},
            {"id": "TXN-202608-202", "date": "Aug 15, 2026", "period": "2026-08", "name": "Quarterly Advisory Retainer", "category": "Income", "type": "credit", "amount": "+$18,500.00", "status": "Cleared", "icon": "💼"},
            {"id": "TXN-202608-203", "date": "Aug 04, 2026", "period": "2026-08", "name": "Luxury Resort & Spa", "category": "Travel", "type": "debit", "amount": "-$1,850.00", "status": "Cleared", "icon": "🏨"},
            {"id": "TXN-202607-301", "date": "Jul 25, 2026", "period": "2026-07", "name": "Equities Portfolio Dividend", "category": "Investment", "type": "credit", "amount": "+$3,120.00", "status": "Cleared", "icon": "📈"},
            {"id": "TXN-202607-302", "date": "Jul 12, 2026", "period": "2026-07", "name": "Private Aviation Charter", "category": "Travel", "type": "debit", "amount": "-$4,200.00", "status": "Cleared", "icon": "✈️"},
        ]
    elif "finance" in username:
        historical = [
            {"id": "TXN-202608-201", "date": "Aug 31, 2026", "period": "2026-08", "name": "Global Tech Services Inbound", "category": "Income", "type": "credit", "amount": "+$72,400.00", "status": "Cleared", "icon": "💰"},
            {"id": "TXN-202608-202", "date": "Aug 15, 2026", "period": "2026-08", "name": "Staff Payroll Disbursement", "category": "Payroll", "type": "debit", "amount": "-$61,800.00", "status": "Cleared", "icon": "👥"},
            {"id": "TXN-202608-203", "date": "Aug 02, 2026", "period": "2026-08", "name": "Cloud Infrastructure AWS", "category": "Operations", "type": "debit", "amount": "-$8,450.00", "status": "Cleared", "icon": "☁️"},
            {"id": "TXN-202607-301", "date": "Jul 28, 2026", "period": "2026-07", "name": "Vendor Equipment Acquisition", "category": "Hardware", "type": "debit", "amount": "-$19,200.00", "status": "Cleared", "icon": "🏢"},
            {"id": "TXN-202607-302", "date": "Jul 15, 2026", "period": "2026-07", "name": "Staff Payroll Disbursement", "category": "Payroll", "type": "debit", "amount": "-$60,900.00", "status": "Cleared", "icon": "👥"},
        ]
    else:
        historical = [
            {"id": "TXN-202608-201", "date": "Aug 25, 2026", "period": "2026-08", "name": "Supermarket Fresh Foods", "category": "Groceries", "type": "debit", "amount": "-$112.40", "status": "Cleared", "icon": "🛒"},
            {"id": "TXN-202608-202", "date": "Aug 15, 2026", "period": "2026-08", "name": "Salary Direct Deposit", "category": "Income", "type": "credit", "amount": "+$3,450.00", "status": "Cleared", "icon": "💼"},
            {"id": "TXN-202608-203", "date": "Aug 10, 2026", "period": "2026-08", "name": "Metro Water & Utility", "category": "Utilities", "type": "debit", "amount": "-$78.20", "status": "Cleared", "icon": "💧"},
            {"id": "TXN-202607-301", "date": "Jul 29, 2026", "period": "2026-07", "name": "Fuel & Convenience Stop", "category": "Transport", "type": "debit", "amount": "-$52.10", "status": "Cleared", "icon": "⛽"},
            {"id": "TXN-202607-302", "date": "Jul 15, 2026", "period": "2026-07", "name": "Salary Direct Deposit", "category": "Income", "type": "credit", "amount": "+$3,450.00", "status": "Cleared", "icon": "💼"},
            {"id": "TXN-202607-303", "date": "Jul 05, 2026", "period": "2026-07", "name": "StreamBox Subscription", "category": "Entertainment", "type": "debit", "amount": "-$14.99", "status": "Cleared", "icon": "🎬"},
        ]

    all_txs = enriched + historical
    if period and period != "all":
        all_txs = [tx for tx in all_txs if tx.get("period") == period]
    if tx_type and tx_type != "all":
        all_txs = [tx for tx in all_txs if tx.get("type") == tx_type]

    return all_txs


@app.route("/transfer", methods=["GET", "POST"])
@honeypot_middleware
@login_required
def transfer():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    user = session.get("user", "Customer")
    account = session.get("account", {})
    message = None

    if request.method == "POST":
        from_account = request.form.get("from_account", "checking")
        recipient = request.form.get("recipient", "").strip()
        recipient_name = request.form.get("recipient_name", "").strip()
        amount = request.form.get("amount", "").strip()
        speed = request.form.get("speed", "Standard ACH")
        note = request.form.get("note", "").strip()
        user_agent = request.headers.get("User-Agent", "")

        ref_id = f"TR-{abs(hash(f'{recipient}:{amount}:{ip}')) % 900000 + 100000}"

        # Honeypot trap: log attempted transfer
        attack_data = log_attack(
            ip=ip,
            attack_type="TRANSFER_ATTEMPT",
            endpoint="/transfer",
            payload=f"from={from_account}&recipient={recipient}&name={recipient_name}&amount={amount}&speed={speed}&note={note}&ref={ref_id}",
            method="POST",
            user_agent=user_agent,
            severity="LOW"
        )
        alert(attack_data)

        target_display = f"{recipient} ({recipient_name})" if recipient_name else recipient
        message = f"Transfer of ${amount} to account {target_display} has been initiated successfully. Confirmation #{ref_id}."

    return render_template(
        "transfer.html",
        bank_name=BANK_NAME,
        user=user,
        user_name=account.get("name", user.split('@')[0].replace('.', ' ').title()),
        balance=account.get("balance", "$0.00"),
        savings_balance=account.get("savings", "$0.00"),
        account_number=account.get("account", "****0000"),
        account_type=account.get("account_type", "Standard Checking"),
        message=message
    )


@app.route("/pay-bills", methods=["GET", "POST"])
@app.route("/bills", methods=["GET", "POST"])
@honeypot_middleware
@login_required
def pay_bills():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    user = session.get("user", "Customer")
    account = session.get("account", {})
    message = None

    if request.method == "POST":
        from_account = request.form.get("from_account", "checking")
        biller = request.form.get("biller", "").strip()
        custom_biller = request.form.get("custom_biller", "").strip()
        biller_account = request.form.get("biller_account", "").strip()
        amount = request.form.get("amount", "").strip()
        payment_date = request.form.get("payment_date", "").strip()
        frequency = request.form.get("frequency", "One-Time")
        memo = request.form.get("memo", "").strip()
        user_agent = request.headers.get("User-Agent", "")

        payee = custom_biller if biller == "__custom__" and custom_biller else biller
        ref_id = f"BP-{abs(hash(f'{payee}:{biller_account}:{amount}:{ip}')) % 900000 + 100000}"

        # Honeypot trap: log bill payment submission
        attack_data = log_attack(
            ip=ip,
            attack_type="BILL_PAYMENT_ATTEMPT",
            endpoint="/pay-bills",
            payload=f"from={from_account}&payee={payee}&biller_acct={biller_account}&amount={amount}&date={payment_date}&frequency={frequency}&memo={memo}&ref={ref_id}",
            method="POST",
            user_agent=user_agent,
            severity="LOW"
        )
        alert(attack_data)

        message = f"Payment of ${amount} to {payee} scheduled for {payment_date}. Confirmation #{ref_id}."

    return render_template(
        "bills.html",
        bank_name=BANK_NAME,
        user=user,
        user_name=account.get("name", user.split('@')[0].replace('.', ' ').title()),
        balance=account.get("balance", "$0.00"),
        savings_balance=account.get("savings", "$0.00"),
        account_number=account.get("account", "****0000"),
        account_type=account.get("account_type", "Standard Checking"),
        message=message
    )


@app.route("/statements", methods=["GET"])
@honeypot_middleware
@login_required
def statements():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    user = session.get("user", "Customer")
    account = session.get("account", {})
    user_agent = request.headers.get("User-Agent", "")

    period = request.args.get("period", "all")
    tx_type = request.args.get("type", "all")

    # Honeypot trap: log statement inspection probe
    attack_data = log_attack(
        ip=ip,
        attack_type="STATEMENT_VIEW",
        endpoint="/statements",
        payload=str(request.args.to_dict()),
        method="GET",
        user_agent=user_agent,
        severity="LOW"
    )
    alert(attack_data)

    txs = get_account_transactions(user, account, period=period, tx_type=tx_type)

    return render_template(
        "statements.html",
        bank_name=BANK_NAME,
        user=user,
        user_name=account.get("name", user.split('@')[0].replace('.', ' ').title()),
        balance=account.get("balance", "$0.00"),
        savings_balance=account.get("savings", "$0.00"),
        credit_available=account.get("credit", "$0.00"),
        account_number=account.get("account", "****0000"),
        account_type=account.get("account_type", "Standard Checking"),
        transactions=txs,
        selected_period=period,
        selected_type=tx_type
    )


@app.route("/statements/download", methods=["GET"])
@honeypot_middleware
@login_required
def statements_download():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    user = session.get("user", "Customer")
    account = session.get("account", {})
    user_agent = request.headers.get("User-Agent", "")

    period = request.args.get("period", "all")
    tx_type = request.args.get("type", "all")

    # Honeypot trap: log statement download / exfiltration attempt
    attack_data = log_attack(
        ip=ip,
        attack_type="STATEMENT_DOWNLOAD",
        endpoint="/statements/download",
        payload=str(request.args.to_dict()),
        method="GET",
        user_agent=user_agent,
        severity="LOW"
    )
    alert(attack_data)

    txs = get_account_transactions(user, account, period=period, tx_type=tx_type)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Date", "Transaction ID", "Description", "Category", "Type", "Amount", "Status"])
    for tx in txs:
        writer.writerow([
            tx.get("date", ""),
            tx.get("id", ""),
            tx.get("name", ""),
            tx.get("category", ""),
            tx.get("type", "").upper(),
            tx.get("amount", ""),
            tx.get("status", "Cleared")
        ])

    csv_data = output.getvalue()
    clean_account = account.get("account", "0000").replace("*", "")
    filename = f"statement_{clean_account}_{period}.csv"

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Content-Type": "text/csv; charset=utf-8"
        }
    )


@app.route("/support", methods=["GET", "POST"])
@app.route("/contact", methods=["GET", "POST"])
@honeypot_middleware
@login_required
def support():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    user = session.get("user", "Customer")
    account = session.get("account", {})
    message = None

    if request.method == "POST":
        category = request.form.get("category", "").strip()
        priority = request.form.get("priority", "Standard").strip()
        subject = request.form.get("subject", "").strip()
        msg_body = request.form.get("message", "").strip()
        acct = request.form.get("account", "").strip()
        email = request.form.get("email", "").strip()
        user_agent = request.headers.get("User-Agent", "")

        ticket_id = f"SUP-{abs(hash(f'{category}:{subject}:{ip}')) % 90000 + 10000}"

        # Honeypot trap: log support inquiry submission
        attack_data = log_attack(
            ip=ip,
            attack_type="SUPPORT_TICKET_SUBMISSION",
            endpoint="/support",
            payload=f"ticket={ticket_id}&category={category}&priority={priority}&subject={subject}&message={msg_body}&email={email}&account={acct}",
            method="POST",
            user_agent=user_agent,
            severity="LOW"
        )
        alert(attack_data)

        message = f"Support inquiry received (Ticket #{ticket_id}). Our security and client services team will review it within 24 hours."

    return render_template(
        "support.html",
        bank_name=BANK_NAME,
        user=user,
        user_name=account.get("name", user.split('@')[0].replace('.', ' ').title()),
        account_number=account.get("account", "****0000"),
        account_type=account.get("account_type", "Standard Checking"),
        message=message
    )


@app.route("/admin", methods=["GET", "POST"])
@honeypot_middleware
def admin():
    """Hidden admin panel — anyone probing this is flagged immediately."""
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    user_agent = request.headers.get("User-Agent", "")
    params = {**request.args.to_dict(), **request.form.to_dict()}

    attack_data = log_attack(
        ip=ip,
        attack_type="ADMIN_PANEL_PROBE",
        endpoint="/admin",
        payload=str(params),
        method=request.method,
        user_agent=user_agent,
        severity="HIGH"
    )
    alert(attack_data)

    # Show a convincing fake admin login page
    return render_template("admin.html", bank_name=BANK_NAME)


@app.route("/admin/login", methods=["POST"])
@honeypot_middleware
def admin_login():
    """Capture admin credential attempts."""
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    user_agent = request.headers.get("User-Agent", "")

    attack_data = log_attack(
        ip=ip,
        attack_type="ADMIN_CREDENTIAL_ATTEMPT",
        endpoint="/admin/login",
        payload=f"username={username}&password={password}",
        method="POST",
        user_agent=user_agent,
        severity="CRITICAL"
    )
    alert(attack_data)

    # Always return 401 — never let them in
    return render_template("admin.html", bank_name=BANK_NAME, error="Invalid credentials"), 401


# ─── Fake API Endpoints ─────────────────────────────────────────────────

@app.route("/api/v1/accounts", methods=["GET"])
@honeypot_middleware
def api_accounts():
    """Fake API endpoint — returns convincing fake data."""
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    log_attack(ip=ip, attack_type="API_PROBE", endpoint="/api/v1/accounts",
               method="GET", severity="MEDIUM")

    # Return fake data that looks real
    return jsonify({
        "status": "success",
        "data": {
            "accounts": [
                {"id": "ACC-4521", "balance": 24890.50, "currency": "USD"},
                {"id": "ACC-7823", "balance": 8340.00, "currency": "USD"}
            ],
            "db_version": FAKE_DB_VERSION  # Intentional "info leak" — another trap
        }
    })


@app.route("/api/v1/transfer", methods=["POST"])
@honeypot_middleware
def api_transfer():
    """Fake transfer API — captures automated attack tools."""
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    body = request.get_json(silent=True) or {}

    log_attack(
        ip=ip,
        attack_type="API_TRANSFER_ATTEMPT",
        endpoint="/api/v1/transfer",
        payload=str(body),
        method="POST",
        severity="HIGH"
    )
    return jsonify({"status": "error", "message": "Unauthorized"}), 401


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ─── Catch-All: Log Unknown Paths ──────────────────────────────────────

@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE"])
@honeypot_middleware
def catch_all(path):
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    log_attack(
        ip=ip,
        attack_type="UNKNOWN_PATH_PROBE",
        endpoint=f"/{path}",
        payload=str(request.args.to_dict()),
        method=request.method,
        severity="LOW"
    )
    return render_template("404.html", bank_name=BANK_NAME), 404


if __name__ == "__main__":
    print(f"[*] Starting {BANK_NAME} Honeypot on port {BANK_PORT}")
    app.run(host="0.0.0.0", port=BANK_PORT, debug=False)
