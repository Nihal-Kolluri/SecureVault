const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const { createGatewayMiddleware } = require('./gateway/gateway');
const { authRateLimiter, apiRateLimiter } = require('./gateway/rate-limiter');
const authRouter = require('./routes/auth');
const vaultRouter = require('./routes/vault');
const filesRouter = require('./routes/files');
const adminRouter = require('./routes/admin');
const sessionsRouter = require('./routes/sessions');
const auditRouter = require('./routes/audit');
const { getVaultStatus } = require('./status');

/**
 * Creates and configures the Express application with Gateway, RBAC, and rate limiting.
 * @param {object} [options]
 * @param {boolean|string[]} [options.trustProxy=false]
 * @param {boolean} [options.enableRateLimit=true]
 * @returns {express.Application}
 */
function createApp(options = {}) {
  const app = express();

  // 1. Gateway middleware stack (Request ID, IP anti-spoofing, Security headers)
  app.use(createGatewayMiddleware(options));

  // 2. Body parsing and cookies
  app.use(express.json({ limit: '1mb' }));
  app.use(express.urlencoded({ extended: true, limit: '1mb' }));
  app.use(cookieParser());

  // 3. Static assets
  app.use(express.static(path.join(__dirname, 'public')));

  // 4. Health / Status endpoint
  app.get('/api/status', (req, res) => {
    res.json(getVaultStatus());
  });

  // 5. Rate limiting & API routers
  const rateLimitEnabled = options.enableRateLimit !== false;
  if (rateLimitEnabled) {
    app.use('/api/auth', authRateLimiter, authRouter);
    app.use('/api/vault', apiRateLimiter, vaultRouter);
    app.use('/api/files', apiRateLimiter, filesRouter);
    app.use('/api/admin', apiRateLimiter, adminRouter);
    app.use('/api/sessions', apiRateLimiter, sessionsRouter);
    app.use('/api/audit', apiRateLimiter, auditRouter);
  } else {
    app.use('/api/auth', authRouter);
    app.use('/api/vault', vaultRouter);
    app.use('/api/files', filesRouter);
    app.use('/api/admin', adminRouter);
    app.use('/api/sessions', sessionsRouter);
    app.use('/api/audit', auditRouter);
  }

  // 6. Frontend fallback handler
  app.use((req, res) => {
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
