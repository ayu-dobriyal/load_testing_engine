// src/routes/dashboard.js
const express = require('express');
const router = express.Router();
const db = require('../db');
const { randomUUID } = require('crypto');

// GET /api/dashboard/stats
router.get('/stats', async (req, res, next) => {
  try {
    const [totalAlerts] = await db.query('SELECT COUNT(*) as count FROM logs');
    const [activeRules] = await db.query('SELECT COUNT(*) as count FROM firewall_rules WHERE active = TRUE');
    const [blockedIps] = await db.query('SELECT COUNT(DISTINCT source_ip) as count FROM firewall_rules WHERE active = TRUE');
    const [allowlisted] = await db.query('SELECT COUNT(*) as count FROM allowlist');
    const [recentAlerts] = await db.query('SELECT COUNT(*) as count FROM logs WHERE created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)');

    res.json({
      totalAlerts: totalAlerts.count,
      activeRules: activeRules.count,
      blockedIps: blockedIps.count,
      allowlistedIps: allowlisted.count,
      alertsLast24h: recentAlerts.count
    });
  } catch (err) { next(err); }
});

// GET /api/alerts
router.get('/alerts', async (req, res, next) => {
  try {
    const rows = await db.query('SELECT * FROM logs ORDER BY created_at DESC LIMIT 200');
    res.json({ alerts: rows });
  } catch (err) { next(err); }
});

// GET /api/firewall-rules
router.get('/firewall-rules', async (req, res, next) => {
  try {
    const rows = await db.query('SELECT * FROM firewall_rules ORDER BY created_at DESC LIMIT 100');
    res.json({ rules: rows });
  } catch (err) { next(err); }
});

// GET /api/allowlist
router.get('/allowlist', async (req, res, next) => {
  try {
    const rows = await db.query('SELECT * FROM allowlist ORDER BY created_at DESC');
    res.json({ entries: rows });
  } catch (err) { next(err); }
});

// POST /api/allowlist
router.post('/allowlist', async (req, res, next) => {
  try {
    const { ip, description } = req.body;
    if (!ip) {
      const err = new Error('ip is required');
      err.status = 400;
      throw err;
    }
    const id = randomUUID();
    await db.query('INSERT INTO allowlist (id, ip, description) VALUES (?, ?, ?)', [id, ip, description || '']);
    res.status(201).json({ id, ip, description });
  } catch (err) { next(err); }
});

// DELETE /api/allowlist/:id
router.delete('/allowlist/:id', async (req, res, next) => {
  try {
    await db.query('DELETE FROM allowlist WHERE id = ?', [req.params.id]);
    res.json({ message: 'Deleted' });
  } catch (err) { next(err); }
});

// GET /api/assets
router.get('/assets', async (req, res, next) => {
  try {
    const rows = await db.query('SELECT * FROM assets ORDER BY discovered_at DESC');
    res.json({ assets: rows });
  } catch (err) { next(err); }
});

module.exports = router;
