// src/routes/assets.js
const express = require('express');
const db = require('../db');

const router = express.Router();

// GET /api/assets
router.get('/', async (req, res, next) => {
  try {
    const rows = await db.query('SELECT * FROM assets');
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
