-- schema.sql for NSMS
-- UUID primary keys (using gen_random_uuid(), compatible with PostgreSQL 13+)
-- Note: UUIDv7 not natively supported; replace with appropriate generator when available.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. Assets discovered on the network
CREATE TABLE IF NOT EXISTS assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip INET NOT NULL,
    mac MACADDR,
    os TEXT,
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- 2. Centralised logs / SIEM entries
CREATE TABLE IF NOT EXISTS logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    message TEXT NOT NULL,
    severity TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- 3. Active firewall blocking rules (SOAR output)
CREATE TABLE IF NOT EXISTS firewall_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_ip INET NOT NULL,
    target_ip INET NOT NULL,
    rule TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    active BOOLEAN DEFAULT true
);

-- 4. Hard‑coded IP allowlist (must never be blocked)
CREATE TABLE IF NOT EXISTS allowlist (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip INET NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Indexes for fast look‑ups
CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip);
CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs(severity);
CREATE INDEX IF NOT EXISTS idx_firewall_target_ip ON firewall_rules(target_ip);
CREATE INDEX IF NOT EXISTS idx_allowlist_ip ON allowlist(ip);
