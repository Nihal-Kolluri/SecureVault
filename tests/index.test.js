const test = require('node:test');
const assert = require('node:assert/strict');
const { getVaultStatus } = require('../src/index');

test('vault status reports online and version', () => {
  const status = getVaultStatus();
  assert.equal(status.status, 'online');
  assert.equal(status.version, '0.4.0');
  assert.ok(status.timestamp);
});
