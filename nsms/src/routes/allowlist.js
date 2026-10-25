// src/routes/allowlist.js
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const db = require('../db');

const router = express.Router();

// GET /api/allowlist
router.get('/', async (req, res, next) => {
  try {
    const rows = await db.query('SELECT * FROM allowlist');
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

// POST /api/allowlist
router.post('/', async (req, res, next) => {
  try {
    const { ip, description } = req.body;

    if (!ip) {
      const err = new Error('ip is required');
      err.status = 400;
      throw err;
    }

    const id = uuidv4();
    await db.query(
      'INSERT INTO allowlist (id, ip, description) VALUES (?, ?, ?)',
      [id, ip, description || null]
    );

    res.status(201).json({ id, ip, description: description || null });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/allowlist/:id
router.delete('/:id', async (req, res, next) => {
  try {
    const { id } = req.params;
    const result = await db.query('DELETE FROM allowlist WHERE id = ?', [id]);

    if (result.affectedRows === 0) {
      const err = new Error('Allowlist entry not found');
      err.status = 404;
      throw err;
    }

    res.json({ message: 'Allowlist entry deleted', id });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
