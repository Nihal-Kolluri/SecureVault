const http = require('http');
const { initDatabase } = require('./db/database');

/**
 * SecureVault core status reporting
 */
function getVaultStatus() {
  return {
    status: 'online',
    version: '0.1.0',
    phase: 'Phase 1: Authentication and sessions',
    timestamp: new Date().toISOString()
  };
}

let serverInstance = null;

function startServer(port = process.env.PORT || 3000) {
  // Lazy require createApp to avoid circular dependencies
  const { createApp } = require('./app');

  initDatabase();
  const app = createApp();
  const server = http.createServer(app);

  return new Promise((resolve, reject) => {
    server.listen(port, () => {
      console.log(`[SecureVault] Server running at http://localhost:${port}`);
      serverInstance = server;
      resolve(server);
    });
    server.on('error', reject);
  });
}

function stopServer() {
  return new Promise((resolve) => {
    if (serverInstance) {
      serverInstance.close(() => {
        serverInstance = null;
        resolve();
      });
    } else {
      resolve();
    }
  });
}

// Start automatically if run as entry point
if (require.main === module) {
  startServer().catch((err) => {
    console.error('[SecureVault] Failed to start server:', err);
    process.exit(1);
  });
}

module.exports = {
  getVaultStatus,
  startServer,
  stopServer
};
