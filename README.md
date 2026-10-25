# BreakPoint & NSMS — Chaos Engineering & Closed-Loop SOAR Defense Platform

A unified cybersecurity and performance testing platform featuring:
1. **Break Point (Attacker / Load Testing Engine)** — High-concurrency virtual users, chaos fault injections, and multi-vector attack simulations.
2. **NSMS (Defender / SOAR Engine)** — Real-time Web Application Firewall (WAF), multi-vector packet sniffer, SIEM audit logger, and automated OS firewall mitigation with auto-expiring rules.

---

## 📁 Project Structure

```text
BreakPoint-NSMS/
├── .gitignore               # Root git ignore file
├── README.md                # System documentation
├── start-all.bat            # One-click starter script for both servers
├── start-nsms.bat           # Starts NSMS Defender server (Port 4000)
├── start-breakpoint.bat     # Starts Break Point Load Engine (Port 3000)
│
├── breakpoint/              # Break Point Load Testing Platform (Node.js + Socket.IO)
│   ├── package.json
│   ├── server.js            # Server entry (Port 3000)
│   ├── data/
│   │   └── database.json    # Pre-configured targets & attack scenarios
│   ├── src/                 # Concurrency & chaos engine services
│   └── public/              # Linear/Grafana inspired Dark UI
│       ├── index.html
│       ├── css/styles.css
│       └── js/app.js
│
└── nsms/                    # Network Security Management System (Node.js + MySQL + Python)
    ├── package.json
    ├── schema_mysql.sql     # MySQL 8 database schema
    ├── .env                 # Port 4000 + MySQL configuration
    ├── src/
    │   ├── app.js           # Server entry (Port 4000)
    │   ├── db/              # MySQL connection pool
    │   ├── middleware/      # In-line WAF & IDS (SQLi, Recon, HTTP Flood detector)
    │   ├── controllers/     # SOAR mitigation controller (allowlist + TTL auto-block)
    │   ├── routes/          # REST APIs for stats, alerts, firewall rules, allowlist
    │   └── services/        # Real OS firewall (netsh/iptables) & TTL expiry worker
    ├── public/              # Real-time Security Dashboard UI
    │   ├── index.html
    │   ├── css/dashboard.css
    │   └── js/dashboard.js
    └── python/
        └── sniffer.py       # Advanced Scapy packet sniffer (SYN flood, port scan detector)
```

---

## ⚡ Quick Start (Windows)

Double click `start-all.bat` or run:
```cmd
start-all.bat
```
This opens both servers in separate command windows:
- **NSMS Security Dashboard**: [http://localhost:4000](http://localhost:4000)
- **Break Point Load Platform**: [http://localhost:3000](http://localhost:3000)

---

## 🛠️ Manual Setup & Execution

### 1. Database Setup (MySQL)
Ensure MySQL is running (default credentials: `root` / `root`), then run:
```powershell
cd nsms
mysql -u root -proot -e "CREATE DATABASE IF NOT EXISTS nsms;"
Get-Content schema_mysql.sql | mysql -u root -proot nsms
```

### 2. Start NSMS Defender (Port 4000)
```powershell
cd nsms
npm install
node src/app.js
```
* Dashboard: `http://localhost:4000`
* API: `http://localhost:4000/api`

### 3. Start Break Point Load Engine (Port 3000)
```powershell
cd breakpoint
npm install
node server.js
```
* Dashboard: `http://localhost:3000`

### 4. (Optional) Run Live Network Sniffer
Run from an Administrator terminal:
```powershell
cd nsms
pip install scapy requests
python python/sniffer.py
```

---

## 🎯 How to Run Attacks

### Method A: Concurrency Flooding (DDoS with 30-100+ Virtual Users)
1. Open [http://localhost:3000](http://localhost:3000)
2. In **Quick Launch**, select one of the pre-configured attack scenarios:
   - `💉 SQL Injection & Database Fuzzing Attack on NSMS`
   - `🕵️ Unauthorized Sensitive Endpoint Recon Attack on NSMS`
   - `⚡ Rapid-Fire API Flood & Resource Exhaustion (HTTP DoS)`
   - `🔥 High-Concurrency DDoS Flood Attack on NSMS`
3. Click **"Start Test Now"**.
4. Open [http://localhost:4000](http://localhost:4000) to see the WAF intercepting threats, issuing kernel-level firewall blocks, and emitting live Socket.IO alerts.

### Method B: Attack Simulator Tab
1. Open [http://localhost:3000](http://localhost:3000) and click **"🔴 Attack Simulator"**.
2. Select the vector:
   - `SQL Injection Probe (UNION SELECT)`
   - `Sensitive Path Recon (/.env probe)`
   - `Direct HTTP Layer 7 Flood (DDoS)`
   - `SYN Flood / Brute Force Threat Alert`
3. Click **"Launch Attack Simulation"**.

---

## 🛡️ Allowlist Failsafe Verification
In the Attack Simulator, set **Target IP** to `10.0.0.99`.
Because `10.0.0.99` is registered in the allowlist, the SOAR engine will automatically bypass the block rule, ensuring critical infrastructure cannot be locked out.
