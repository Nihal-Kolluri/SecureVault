const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const authRouter = require('./routes/auth');
const { getVaultStatus } = require('./status');

function createApp() {
  const app = express();

  // Standard middleware
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(cookieParser());

  // Basic security headers
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
  });

  // Serve static UI assets
  app.use(express.static(path.join(__dirname, 'public')));

  // Health / Status endpoint
  app.get('/api/status', (req, res) => {
    res.json(getVaultStatus());
  });

  // Auth API router
  app.use('/api/auth', authRouter);

  // Fallback to index.html for frontend routing
  app.use((req, res) => {
    // If asking for API, send 404
    if (req.path.startsWith('/api')) {
      return res.status(404).json({ error: 'Endpoint not found' });
    }
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });

  return app;
}

module.exports = {
  createApp
};
