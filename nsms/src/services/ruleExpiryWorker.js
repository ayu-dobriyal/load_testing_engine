// src/services/ruleExpiryWorker.js
// Background worker that auto-expires firewall rules whose TTL has passed
const db = require('../db');
const { removeFirewallRule } = require('./realFirewall');

let intervalHandle = null;

async function cleanExpiredRules() {
  try {
    // Find all active rules that have expired
    const expired = await db.query(
      'SELECT id, source_ip, target_ip, rule FROM firewall_rules WHERE active = TRUE AND expires_at < NOW()'
    );

    if (expired.length === 0) return;

    console.log(`[ExpiryWorker] Found ${expired.length} expired rule(s). Cleaning up...`);

    for (const rule of expired) {
      // 1. Remove from OS firewall
      await removeFirewallRule(rule.id);

      // 2. Mark inactive in DB
      await db.query(
        'UPDATE firewall_rules SET active = FALSE WHERE id = ?',
        [rule.id]
      );

      // 3. Log the expiry
      const { randomUUID } = require('crypto');
      await db.query(
        'INSERT INTO logs (id, message, severity, created_at) VALUES (?, ?, ?, NOW())',
        [randomUUID(), `[AUTO-EXPIRY] Firewall rule ${rule.id.substring(0, 8)} for ${rule.source_ip} expired and removed`, 'info']
      );

      console.log(`[ExpiryWorker] Removed expired rule: ${rule.id.substring(0, 8)} (${rule.source_ip})`);
    }
  } catch (err) {
    console.error('[ExpiryWorker] Error cleaning expired rules:', err.message);
  }
}

function start(intervalSec = 30) {
  console.log(`[ExpiryWorker] Started. Checking every ${intervalSec}s for expired rules.`);
  cleanExpiredRules(); // Run immediately once
  intervalHandle = setInterval(cleanExpiredRules, intervalSec * 1000);
}

function stop() {
  if (intervalHandle) {
    clearInterval(intervalHandle);
    intervalHandle = null;
    console.log('[ExpiryWorker] Stopped.');
  }
}

module.exports = { start, stop };
