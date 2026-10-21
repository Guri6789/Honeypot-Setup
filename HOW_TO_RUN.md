# 🍯 HoneyBank — Step-by-Step Execution Guide

This guide details how to set up, run, test, and access the **HoneyBank Online Banking Honeypot & Monitoring System**.

---

## 📌 Project Overview & Architecture

The system consists of three concurrent services:
1. **🏦 Fake Banking Web Portal (`http://localhost:8080`)**: Convincing online banking decoy interface that lures attackers, captures credential attempts, and logs SQL injection, XSS, and reconnaissance probes.
2. **📊 Threat Monitoring Dashboard (`http://localhost:5000`)**: SIEM and SOC telemetry console visualizing live attacks, top attacker IPs, attack categories, and brute-force attempt streams.
3. **🔒 SSH Trap Server (`Port 2222`)**: Low-interaction fake SSH server that captures SSH brute-force credential pairs.

---

## 🚀 Step 1: Initial Setup (Run Once)

If this is your first time setting up the project, navigate to the folder and run the setup script:

```bash
cd ~/Desktop/honeypot-banking
bash setup.sh
```

*What this does:*
- Creates required log directories in `data/logs/` and `data/payloads/`.
- Creates a Python virtual environment (`venv/`).
- Installs all dependencies (`Flask`, `paramiko`, `requests`, `geoip2`).

---

## ▶️ Step 2: Running the Honeypot System

Choose **one** of the methods below to start the services:

### Method A — Run Script (Recommended)
```bash
cd ~/Desktop/honeypot-banking
./run.sh
```

### Method B — Direct Python Launch
```bash
cd ~/Desktop/honeypot-banking
./venv/bin/python main.py
```

### Method C — Docker Compose
If you prefer running in containerized background services:
```bash
cd ~/Desktop/honeypot-banking
docker compose up -d --build
```
*(To stop docker containers later: `docker compose down`)*

---

## 🌐 Step 3: Accessing the Portals & Default User Logins

Once running, open your web browser to access both portals:

### 1. 🏦 Fake Banking Web Portal
- **URL**: `http://localhost:8080` (or `http://localhost:8080/login`)
- **Note**: You can log in with **either** the full email or the username alias.

| Account Name | Username / Email | Password | Account Type | Checking Balance |
|---|---|---|---|---|
| **John Doe** | `john.doe` / `john.doe@securebank.com` | `password123` | Personal Checking | $24,890.50 |
| **Sarah Smith** | `sarah.smith` / `sarah.smith@securebank.com` | `sarah2024` | Premier Wealth | $84,340.00 |
| **Demo User** | `demo` / `demo@securebank.com` | `demo1234` | Everyday Checking | $5,250.75 |
| **Alex Morgan** | `alex.morgan` / `alex.morgan@securebank.com` | `alex2024` | Student Advantage | $1,820.40 |
| **Acme Corp Treasury** | `finance` / `finance@acmecorp.com` | `acme2024` | Commercial Corporate | $154,200.00 |
| **System Admin (Decoy)** | `admin` / `admin@securebank.com` | `admin` | Decoy Admin | $0.00 |

*Tip: The login page has an interactive **Click to fill** helper box to instantly test any of these profiles!*

---

### 2. 📊 SOC Threat Monitoring Dashboard
- **URL**: `http://localhost:5000` (or `http://localhost:5000/login`)
- **Note**: Authenticate with operator credentials to view real-time attack telemetry and charts.

| Role | Username | Password | Operator Name | Permissions |
|---|---|---|---|---|
| **Administrator** | `admin` | `admin123` | Security Administrator | Full Dashboard & Configuration |
| **SOC Analyst** | `analyst` | `analyst123` | SOC Incident Analyst | Live Telemetry & Log Stream |
| **Auditor** | `auditor` | `auditor123` | Compliance Auditor | Read-Only Audit Telemetry |

*Tip: The login page has **Fill →** buttons for one-click access.*

---

## ✅ Step 4: Testing & Verifying User Credentials

To verify that all accounts on both portals are functioning properly, run the verification tool:

```bash
cd ~/Desktop/honeypot-banking
python3 verify_credentials.py
```

You can also run the automated test suite:
```bash
cd ~/Desktop/honeypot-banking
./venv/bin/python -m unittest -v tests/test_users.py
```

---

## 🧪 Step 5: Simulating Attacks & Testing Honeypot Traps

From another terminal tab, simulate cyberattacks against your honeypot to watch them register live on the monitoring dashboard:

```bash
# 1. Test SQL Injection on Login
curl -X POST http://localhost:8080/login \
  -d "username=' OR '1'='1&password=anything"

# 2. Test Cross-Site Scripting (XSS) on Transfer Form
curl -X POST http://localhost:8080/transfer \
  -d "recipient=<script>alert(1)</script>&amount=100&note=test"

# 3. Test Path Traversal Probe
curl http://localhost:8080/../../etc/passwd

# 4. Probe Hidden Admin Panel
curl http://localhost:8080/admin

# 5. Probe Fake API
curl http://localhost:8080/api/v1/accounts

# 6. Test SSH Brute Force (Port 2222)
hydra -l admin -p password ssh://localhost -P /dev/null -s 2222
```

Now refresh or watch `http://localhost:5000` — all attacks, IPs, payloads, and severity levels appear in real time!

---

## 📁 Step 6: Viewing Raw Attack Logs

All captured attack data is stored as structured JSON logs in the `data/logs/` directory:

- **Attacks Log**: `data/logs/attacks.json`
- **Brute Force Login Log**: `data/logs/bruteforce.json`
- **SSH Attempt Log**: `data/logs/ssh_attempts.json`
- **Raw Attack Payloads**: `data/payloads/`

To inspect the latest attack logs in real time:
```bash
tail -f ~/Desktop/honeypot-banking/data/logs/attacks.json
```

---

## 🛑 Step 7: Stopping the Services

If you ran the system via terminal (`./run.sh` or `python main.py`):
- Press `Ctrl + C` in the running terminal window.

If you ran via Docker:
```bash
cd ~/Desktop/honeypot-banking
docker compose down
```
