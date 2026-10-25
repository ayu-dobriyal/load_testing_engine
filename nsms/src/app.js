// src/app.js
require('dotenv').config();
const http = require('http');
const path = require('path');
const express = require('express');
const cors = require('cors');
const { Server } = require('socket.io');

const mitigationRouter = require('./routes/mitigation');
const dashboardRouter = require('./routes/dashboard');
const { errorHandler } = require('./middleware/errorHandler');
const { wafMiddleware } = require('./middleware/wafMiddleware');
const expiryWorker = require('./services/ruleExpiryWorker');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*', methods: ['GET', 'POST', 'DELETE'] } });

// Make io available to controllers via app
app.set('io', io);

// Middleware
app.use(cors());
app.use(express.json());

// In-line WAF & Intrusion Detection System
app.use(wafMiddleware);

// Serve static dashboard
app.use(express.static(path.join(__dirname, '..', 'public')));

// API Routes
app.use('/api/mitigation', mitigationRouter);
app.use('/api', dashboardRouter);

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ONLINE', project: 'NSMS — Network Security Management System', timestamp: new Date().toISOString() });
});

// SPA fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// 404 for API routes
app.use('/api/*', (req, res) => {
  res.status(404).json({ status: 404, message: 'API endpoint not found' });
});

// Error handler
app.use(errorHandler);

// Socket.IO
io.on('connection', (socket) => {
  console.log(`[Socket.IO] Client connected: ${socket.id}`);
  socket.emit('connected', { message: 'Connected to NSMS Security Feed' });
  socket.on('disconnect', () => {
    console.log(`[Socket.IO] Client disconnected: ${socket.id}`);
  });
});

// Start
const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
  console.log('='.repeat(55));
  console.log('  NSMS — Network Security Management System');
  console.log('  Real-time Threat Detection & Automated Mitigation');
  console.log('='.repeat(55));
  console.log(`  Dashboard:  http://localhost:${PORT}`);
  console.log(`  API:        http://localhost:${PORT}/api`);
  console.log('='.repeat(55));

  // Start background expiry worker
  const interval = parseInt(process.env.RULE_EXPIRY_CHECK_INTERVAL_SEC || '30', 10);
  expiryWorker.start(interval);
});

module.exports = app;
