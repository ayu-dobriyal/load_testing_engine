-- schema_mysql.sql – MySQL 8+ compatible
-- Run: mysql -u root -p nsms < schema_mysql.sql

-- 1. Assets discovered on the network
CREATE TABLE IF NOT EXISTS assets (
    id CHAR(36) PRIMARY KEY,
    ip VARCHAR(45) NOT NULL,
    mac VARCHAR(17),
    os VARCHAR(255),
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Centralised logs / SIEM entries
CREATE TABLE IF NOT EXISTS logs (
    id CHAR(36) PRIMARY KEY,
    asset_id CHAR(36),
    message TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE SET NULL
);

-- 3. Active firewall blocking rules (SOAR output)
CREATE TABLE IF NOT EXISTS firewall_rules (
    id CHAR(36) PRIMARY KEY,
    source_ip VARCHAR(45) NOT NULL,
    target_ip VARCHAR(45) NOT NULL,
    rule TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    active BOOLEAN DEFAULT TRUE
);

-- 4. Hard-coded IP allowlist (must never be blocked)
CREATE TABLE IF NOT EXISTS allowlist (
    id CHAR(36) PRIMARY KEY,
    ip VARCHAR(45) NOT NULL UNIQUE,
    description VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX idx_assets_ip ON assets(ip);
CREATE INDEX idx_logs_severity ON logs(severity);
CREATE INDEX idx_firewall_target_ip ON firewall_rules(target_ip);
