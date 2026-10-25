// src/controllers/mitigationController.js
const db = require('../db');
const { addFirewallRule } = require('../services/realFirewall');
const { randomUUID } = require('crypto');

async function handleAlert(req, res, next) {
  try {
    const { sourceIp, targetIp, severity, threatType } = req.body;

    if (!sourceIp || !targetIp || !severity) {
      const err = new Error('sourceIp, targetIp and severity are required');
      err.status = 400;
      throw err;
    }

    const io = req.app.get('io');
    const timestamp = new Date().toISOString();

    // 1. Check allowlist
    const allowRows = await db.query('SELECT 1 FROM allowlist WHERE ip = ?', [targetIp]);
    if (allowRows.length > 0) {
      // Log the attempt
      await db.query(
        'INSERT INTO logs (id, message, severity, created_at) VALUES (?, ?, ?, NOW())',
        [randomUUID(), `[ALLOWLIST] Attack from ${sourceIp} targeting ${targetIp} (${threatType}) — target is allowlisted, no action`, severity]
      );

      const alertData = { sourceIp, targetIp, severity, threatType, status: 'allowed', timestamp };
      if (io) io.emit('security:alert', alertData);

      return res.status(200).json({ status: 'allowed', message: 'Target IP is on the allowlist; no action taken' });
    }

    // 2. Severity gate
    if (severity !== 'high') {
      await db.query(
        'INSERT INTO logs (id, message, severity, created_at) VALUES (?, ?, ?, NOW())',
        [randomUUID(), `[IGNORED] ${severity} severity ${threatType} from ${sourceIp} → ${targetIp}`, severity]
      );

      const alertData = { sourceIp, targetIp, severity, threatType, status: 'ignored', timestamp };
      if (io) io.emit('security:alert', alertData);

      return res.status(200).json({ status: 'ignored', message: 'Severity not high enough for automatic mitigation' });
    }

    // 3. Insert firewall rule with TTL
    const ruleId = randomUUID();
    const ttlHours = parseInt(process.env.FIREWALL_TTL_HOURS || '1', 10);
    const ruleDescription = `BLOCK ${sourceIp} — ${threatType}`;

    await db.query(
      `INSERT INTO firewall_rules (id, source_ip, target_ip, rule, expires_at)
       VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL ? HOUR))`,
      [ruleId, sourceIp, targetIp, ruleDescription, ttlHours]
    );

    // 4. Real OS firewall block
    const fwResult = await addFirewallRule({ sourceIp, targetIp, rule: ruleDescription, ttlHours, ruleId });

    // 5. Audit log
    await db.query(
      'INSERT INTO logs (id, message, severity, created_at) VALUES (?, ?, ?, NOW())',
      [randomUUID(), `[BLOCKED] ${threatType} from ${sourceIp} → ${targetIp} | Rule: ${ruleId.substring(0, 8)} | TTL: ${ttlHours}h | FW: ${fwResult.success ? 'Applied' : 'Mock'}`, 'high']
    );

    // 6. Broadcast to dashboard
    const alertData = { sourceIp, targetIp, severity, threatType, status: 'blocked', ruleId, ttlHours, timestamp };
    if (io) io.emit('security:alert', alertData);

    res.status(201).json({ status: 'blocked', ruleId, expiresInHours: ttlHours });
  } catch (err) {
    next(err);
  }
}

module.exports = { handleAlert };
