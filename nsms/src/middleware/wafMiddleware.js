// src/middleware/wafMiddleware.js
// In-line Web Application Firewall (WAF) & Intrusion Detection System (IDS)
const db = require('../db');
const { addFirewallRule } = require('../services/realFirewall');
const { randomUUID } = require('crypto');

// Rate limiting & flood tracking cache
const ipRequestWindow = new Map(); // ip -> [timestamps]
const activeBlockCache = new Set(); // in-memory set of blocked IPs for microsecond rejection

// Refresh in-memory blocked cache every 10 seconds from DB
async function syncBlockedIps() {
  try {
    const rows = await db.query('SELECT DISTINCT source_ip FROM firewall_rules WHERE active = TRUE AND expires_at > NOW()');
    activeBlockCache.clear();
    rows.forEach(r => activeBlockCache.add(r.source_ip));
  } catch (e) {
    // silently catch on init
  }
}
setInterval(syncBlockedIps, 10000);
syncBlockedIps();

// SQL Injection signatures
const SQLI_REGEX = /(\bunion(\s+all)?\s+select\b|\bselect\s+.+\s+from\b|\binsert\s+into\b|\bdrop\s+table\b|\bsleep\s*\(\d+\)|'\s*or\s*'?\d+'?\s*=\s*'?\d+|--|\bexec(\s|\+)+(s|x)p\w+)/i;

// Sensitive Path Reconnaissance signatures
const RECON_REGEX = /(\.env|\.git|\.htaccess|\.bak|\.sql|\/phpmyadmin|\/wp-admin|\/wp-login|\/actuator|\/debug|\/etc\/passwd)/i;

async function wafMiddleware(req, res, next) {
  // Always allow static frontend assets, dashboard UI, and socket.io
  if (!req.path.startsWith('/api') || req.path.startsWith('/socket.io')) {
    return next();
  }

  // Extract client IP (handles spoofed header for testing or real IP)
  const clientIp = (req.headers['x-forwarded-for'] || req.headers['x-attack-source-ip'] || req.socket.remoteAddress || '127.0.0.1').replace(/^::ffff:/, '');

  // Localhost admin viewing dashboard APIs should never be blocked from reading stats/alerts
  const isLocalAdmin = (clientIp === '127.0.0.1' || clientIp === '::1') && !req.headers['x-attack-source-ip'];
  if (isLocalAdmin && req.method === 'GET') {
    return next();
  }

  // 1. FAST CHECK: Is client IP already blocked?
  if (activeBlockCache.has(clientIp) && !isLocalAdmin) {
    return res.status(403).json({
      status: 'blocked',
      error: '403 Forbidden: IP address is actively blocked by NSMS Firewall Rule.',
      clientIp
    });
  }

  // Skip checks for mitigation alert webhook ingestion
  if (req.path === '/api/mitigation/alert') {
    return next();
  }

  const io = req.app.get('io');
  const now = Date.now();

  // 2. CHECK: HTTP Flood / Layer 7 DDoS Detection
  if (!ipRequestWindow.has(clientIp)) {
    ipRequestWindow.set(clientIp, []);
  }
  const timestamps = ipRequestWindow.get(clientIp);
  timestamps.push(now);

  // Clean timestamps older than 3 seconds
  while (timestamps.length > 0 && timestamps[0] < now - 3000) {
    timestamps.shift();
  }

  // Threshold: >30 requests in 3 seconds from same IP -> HTTP Flood Attack
  if (timestamps.length > 30) {
    timestamps.length = 0; // reset
    return await triggerWafMitigation({
      sourceIp: clientIp,
      threatType: 'http_flood_l7',
      severity: 'high',
      detail: `HTTP Flood: ${timestamps.length} req/3s to ${req.method} ${req.path}`,
      io,
      res
    });
  }

  // 3. CHECK: SQL Injection Attack Detection
  const inspectTargets = [
    req.url,
    JSON.stringify(req.query || {}),
    JSON.stringify(req.body || {})
  ].join(' ');

  if (SQLI_REGEX.test(inspectTargets)) {
    return await triggerWafMitigation({
      sourceIp: clientIp,
      threatType: 'sql_injection',
      severity: 'high',
      detail: `SQLi attempt detected in payload targeting ${req.method} ${req.path}`,
      io,
      res
    });
  }

  // 4. CHECK: Sensitive File / Path Reconnaissance
  if (RECON_REGEX.test(req.path)) {
    return await triggerWafMitigation({
      sourceIp: clientIp,
      threatType: 'path_reconnaissance',
      severity: 'high',
      detail: `Unauthorized reconnaissance probe to ${req.path}`,
      io,
      res
    });
  }

  next();
}

async function triggerWafMitigation({ sourceIp, threatType, severity, detail, io, res }) {
  try {
    // Check allowlist
    const allowRows = await db.query('SELECT 1 FROM allowlist WHERE ip = ?', [sourceIp]);
    if (allowRows.length > 0) {
      return res.status(200).json({
        status: 'allowed',
        message: 'Source IP is on allowlist; WAF bypass granted'
      });
    }

    const ruleId = randomUUID();
    const ttlHours = parseInt(process.env.FIREWALL_TTL_HOURS || '1', 10);
    const ruleDesc = `[WAF] BLOCK ${sourceIp} — ${threatType}`;

    // Add to DB
    await db.query(
      `INSERT INTO firewall_rules (id, source_ip, target_ip, rule, expires_at)
       VALUES (?, ?, '127.0.0.1', ?, DATE_ADD(NOW(), INTERVAL ? HOUR))`,
      [ruleId, sourceIp, ruleDesc, ttlHours]
    );

    // Add to in-memory block cache immediately
    activeBlockCache.add(sourceIp);

    // Call OS firewall
    await addFirewallRule({ sourceIp, targetIp: '127.0.0.1', rule: ruleDesc, ttlHours, ruleId });

    // Log to SIEM logs
    await db.query(
      'INSERT INTO logs (id, message, severity, created_at) VALUES (?, ?, ?, NOW())',
      [randomUUID(), `[WAF AUTO-BLOCK] ${detail} | Rule ID: ${ruleId.substring(0, 8)}`, 'high']
    );

    // Broadcast to Live Dashboard
    if (io) {
      io.emit('security:alert', {
        sourceIp,
        targetIp: '127.0.0.1',
        severity: 'high',
        threatType,
        status: 'blocked',
        ruleId,
        detail,
        timestamp: new Date().toISOString()
      });
    }

    return res.status(403).json({
      status: 'blocked',
      error: `403 Forbidden: [WAF/IDS] Threat detected (${threatType}). IP ${sourceIp} has been automatically blocked.`,
      ruleId
    });
  } catch (err) {
    console.error('[WAF] Mitigation error:', err);
    return res.status(500).json({ error: 'WAF mitigation internal error' });
  }
}

module.exports = { wafMiddleware };
