// src/routes/firewallRules.js
const express = require('express');
const db = require('../db');

const router = express.Router();

// GET /api/firewall-rules
router.get('/', async (req, res, next) => {
  try {
    const rows = await db.query(
      'SELECT * FROM firewall_rules ORDER BY created_at DESC'
    );
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
