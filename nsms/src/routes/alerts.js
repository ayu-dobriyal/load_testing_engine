// src/routes/alerts.js
const express = require('express');
const db = require('../db');

const router = express.Router();

// GET /api/alerts
router.get('/', async (req, res, next) => {
  try {
    const rows = await db.query(
      'SELECT * FROM logs ORDER BY created_at DESC LIMIT 100'
    );
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
