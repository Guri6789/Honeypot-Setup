# 🍯 HoneyBank — Online Banking Honeypot

A fake online banking portal designed to attract, detect, and log cyberattacks.  
Built for cybersecurity learning and research.

---

## 🏗️ Project Structure

```
honeypot-banking/
├── config.py                    # All settings
├── main.py                      # Launch all services
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
│
├── core/
│   ├── logger.py                # Structured JSON attack logger
│   ├── detector.py              # SQLi, XSS, brute force detection
│   ├── alerter.py               # Discord & email alerts
│   └── geoip.py                 # IP geolocation & reputation
│
├── web/                         # 🏦 Fake Banking Portal (port 8080)
│   ├── app.py
│   └── templates/
│       ├── login.html           # Credential capture trap
│       ├── dashboard.html       # Fake account dashboard
│       ├── transfer.html        # SQLi / XSS trap
│       ├── admin.html           # Admin panel probe trap
│       ├── 404.html
│       └── blocked.html
│
├── services/
│   └── ssh_trap.py              # 🔒 Fake SSH server (port 2222)
│
├── dashboard/                   # 📊 Monitoring Dashboard (port 5000)
│   ├── app.py
│   └── templates/
│       ├── monitor.html         # Live attack visualization
│       └── dash_login.html
│
└── data/
    ├── logs/
    │   ├── attacks.json         # All attack logs
    │   ├── bruteforce.json      # Login attempts
    │   ├── ssh_attempts.json    # SSH brute force
    │   └── scans.json           # Scanner activity
    └── payloads/                # Raw attacker payloads
```

---

## 🚀 Quick Start (Kali Linux)

### Direct Python

```bash
# 1. Clone / copy the project to Kali
cd ~/honeypot-banking

# 2. Install dependencies
pip3 install -r requirements.txt

# 3. Run all services
python3 main.py
```



## 🌐 Services

| Service | URL / Port | Purpose |
|---------|------------|---------|
| 🏦 Banking Portal | `http://localhost:8080` | Main honeypot trap |
| 📊 Dashboard | `http://localhost:5000` | Attack monitoring |
| 🔒 SSH Trap | Port `2222` | Brute force capture |

---

## 👥 Default User Accounts

### 1. 🏦 Fake Banking Web Portal (`http://localhost:8080`)
*You can log in using either the full email address or the username prefix.*

| Account Name | Username / Email | Password | Account Type | Balance |
|---|---|---|---|---|
| **John Doe** | `john.doe@securebank.com` or `john.doe` | `password123` | Personal Checking | $24,890.50 |
| **Sarah Smith** | `sarah.smith@securebank.com` or `sarah.smith` | `sarah2024` | Premier Wealth | $84,340.00 |
| **Demo User** | `demo@securebank.com` or `demo` | `demo1234` | Everyday Checking | $5,250.75 |
| **Alex Morgan** | `alex.morgan@securebank.com` or `alex.morgan` | `alex2024` | Student Advantage | $1,820.40 |
| **Acme Corp Treasury** | `finance@acmecorp.com` or `finance` | `acme2024` | Commercial Corporate | $154,200.00 |
| **Admin (Decoy)** | `admin@securebank.com` or `admin` | `admin` | Decoy Admin | $0.00 |

### 2. 📊 Threat Monitoring Dashboard (`http://localhost:5000`)
*Authenticate with these operator credentials to monitor honeypot logs and analytics in real time.*

| Role | Username | Password | Operator Name | Permissions |
|---|---|---|---|---|
| **Administrator** | `admin` | `admin123` | Security Administrator | Full Dashboard & Configuration |
| **SOC Analyst** | `analyst` | `analyst123` | SOC Incident Analyst | Live Telemetry & Log Stream |
| **Auditor** | `auditor` | `auditor123` | Compliance Auditor | Read-Only Audit Telemetry |

---

## 🔧 Configuration

Edit `config.py` or set environment variables:

```bash
# Optional: Discord alerts
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."

# Optional: AbuseIPDB threat intelligence
export ABUSEIPDB_API_KEY="your_key_here"

# Optional: Email alerts
export ALERT_EMAIL="your@email.com"
export SMTP_USER="sender@gmail.com"
export SMTP_PASS="app_password"

# Dashboard password
export DASHBOARD_SECRET="your_secure_password"
```

---

## 🧪 Testing Your Honeypot

From another terminal on Kali, attack your own honeypot:

```bash
# 1. Brute force SSH
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://localhost -p 2222

# 2. SQL injection test
sqlmap -u "http://localhost:8080/login" --data="username=admin&password=test" --level=3

# 3. Directory scan
gobuster dir -u http://localhost:8080 -w /usr/share/wordlists/dirb/common.txt

# 4. Nikto web scan
nikto -h http://localhost:8080

# 5. Manual SQLi test (browser or curl)
curl -X POST http://localhost:8080/login \
  -d "username=' OR '1'='1&password=anything"

# 6. XSS test
curl -X POST http://localhost:8080/transfer \
  -d "recipient=<script>alert(1)</script>&amount=100&note=test"
```

Then open the **Dashboard** at `http://localhost:5000` to see all attacks logged!

---

## 📋 Cybersecurity Concepts Covered

| Concept | Where in Project |
|---------|----------------|
| Network sockets & TCP | `ssh_trap.py` |
| HTTP request analysis | `web/app.py` middleware |
| SQL Injection detection | `core/detector.py` |
| XSS detection | `core/detector.py` |
| Path traversal detection | `core/detector.py` |
| Brute force detection | `core/detector.py` |
| Structured logging (SIEM) | `core/logger.py` |
| Threat intelligence | `core/geoip.py` |
| Real-time alerting | `core/alerter.py` |
| Docker containerization | `docker-compose.yml` |
| Session management | `web/app.py` |
| Data visualization | `dashboard/templates/monitor.html` |

---

## ⚠️ Legal & Ethical Notice

> **Only deploy on infrastructure you own.**  
> This tool is for **educational and research purposes only**.  
> Do NOT expose to the internet without understanding the legal implications in your country.  
> All captured data is stored locally — handle responsibly.

---


