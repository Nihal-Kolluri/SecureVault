/**
 * SecureVault core status reporting
 */
function getVaultStatus() {
  return {
    status: 'online',
    version: '0.3.0',
    phase: 'Phase 3: Gateway, RBAC and rate limiting',
    timestamp: new Date().toISOString()
  };
}

module.exports = {
  getVaultStatus
};
