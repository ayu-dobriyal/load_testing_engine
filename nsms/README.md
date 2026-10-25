# NSMS – Network & Security Management System

## Overview
This repository contains the **backend** for a closed‑loop Network and Security Management System (NSMS) with SOAR capabilities.

- **Node.js + Express** – REST API
- **PostgreSQL** – raw SQL (`pg` driver) for data persistence
- **Python (Scapy)** – packet sniffing micro‑service that forwards threat alerts to the API
- **No ORM** – all queries are handwritten for full control and auditability

The frontend (React) is not part of this scaffold – you can plug it in later using the existing API endpoints.

## Prerequisites
- Node.js 18+ / npm
- PostgreSQL 15+ (with the `pgcrypto` extension for `gen_random_uuid()`)
- Python 3.11+ and the `scapy` library (`pip install scapy`)
- `git` (optional, for version control)

## Setup
1. **Clone & install dependencies**
   ```bash
   git clone <repo‑url>
   cd nsms
   npm install
   ```
2. **Create a PostgreSQL database** and enable the `pgcrypto` extension:
   ```sql
   CREATE DATABASE nsms;
   \c nsms
   CREATE EXTENSION IF NOT EXISTS "pgcrypto";
   ```
3. **Run the schema migration**
   ```bash
   psql -d nsms -f schema.sql
   ```
4. **Configure environment variables** – copy the example file and fill in the values:
   ```bash
   cp .env.example .env
   ```
   The required variables are:
   - `PORT` – HTTP port (default 3000)
   - `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`
   - `FIREWALL_TTL_HOURS` – default TTL for auto‑expiring firewall rules (e.g., `1`)
5. **Start the server**
   ```bash
   npm run start
   ```
   The API will be available at `http://localhost:${PORT}`.

## API Endpoint (Mitigation Engine)
- **POST** `/api/mitigation/alert`
  - Payload example:
    ```json
    {
      "sourceIp": "192.168.1.42",
      "targetIp": "10.0.0.5",
      "severity": "high",
      "threatType": "brute_force"
    }
    ```
  - The controller checks the **allowlist**, inserts a record into `firewall_rules` with a TTL, and returns the created rule ID.

## Python Sniffer (demo)
Run the sniffer script to capture packets and forward threat alerts:
```bash
python python/sniffer.py
```
Edit the `API_URL` constant inside the script if your Node server runs on a different host/port.

## Development Tips
- All DB interactions use parameterised queries via the `pg` pool (`src/db/index.js`).
- Error handling is functional – every route calls `next(err)` and the `errorHandler` middleware formats the response.
- The allowlist is stored in the `allowlist` table; add entries manually or via a future admin UI.
- TTL expiry is handled by the `expires_at` column; a background job (e.g., `cron`) can delete expired rows.

---
*Happy coding!*