// src/routes/mitigation.js
const express = require('express');
const { handleAlert } = require('../controllers/mitigationController');

const router = express.Router();

// POST /api/mitigation/alert
router.post('/alert', handleAlert);

module.exports = router;
