"""
HoneyBank - Monitoring Dashboard
Real-time attack visualization and statistics
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from core.logger import get_stats, get_all_logs, get_brute_force_logs
from config import DASHBOARD_PORT, DASHBOARD_SECRET, BANK_NAME, DASHBOARD_USERS

_DASH_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, template_folder=os.path.join(_DASH_DIR, "templates"))
app.secret_key = "dashboard_secret_key_change_me"


def require_auth(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("dash_auth"):
            return redirect(url_for("dash_login"))
        return f(*args, **kwargs)
    return decorated


@app.route("/", methods=["GET"])
@require_auth
def dashboard():
    return render_template(
        "monitor.html",
        bank_name=BANK_NAME,
        user=session.get("dash_user", "admin"),
        role=session.get("dash_role", "Administrator"),
        name=session.get("dash_name", "Security Administrator"),
        default_users=DASHBOARD_USERS
    )


@app.route("/login", methods=["GET", "POST"])
def dash_login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "").strip()

        user_info = DASHBOARD_USERS.get(username)

        if user_info and user_info.get("password") == password:
            session["dash_auth"] = True
            session["dash_user"] = username
            session["dash_role"] = user_info.get("role", "Administrator")
            session["dash_name"] = user_info.get("name", username.title())
            return redirect(url_for("dashboard"))
        # Fallback: support backward compatibility with admin + DASHBOARD_SECRET
        elif (username in ["admin", ""] and password == DASHBOARD_SECRET):
            session["dash_auth"] = True
            session["dash_user"] = "admin"
            session["dash_role"] = "Administrator"
            session["dash_name"] = "Security Administrator"
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid username or password"

    return render_template("dash_login.html", error=error, default_users=DASHBOARD_USERS)


@app.route("/logout")
def dash_logout():
    session.clear()
    return redirect(url_for("dash_login"))


@app.route("/api/stats")
@require_auth
def api_stats():
    """Live stats JSON endpoint (polled by dashboard)."""
    return jsonify(get_stats())


@app.route("/api/logs")
@require_auth
def api_logs():
    """All attack logs."""
    logs = get_all_logs()
    return jsonify({"logs": logs[-100:][::-1]})  # Last 100, newest first


@app.route("/api/brute")
@require_auth
def api_brute():
    """Brute force login attempts."""
    logs = get_brute_force_logs()
    return jsonify({"logs": logs[-100:][::-1]})


if __name__ == "__main__":
    print(f"[*] Monitoring Dashboard running on http://0.0.0.0:{DASHBOARD_PORT}")
    print("[*] Default Dashboard Users:")
    for u, data in DASHBOARD_USERS.items():
        print(f"    - {u}:{data['password']} ({data['role']})")
    app.run(host="0.0.0.0", port=DASHBOARD_PORT, debug=False)

