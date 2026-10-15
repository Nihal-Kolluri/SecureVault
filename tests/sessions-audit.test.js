const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const crypto = require('crypto');
const { createApp } = require('../src/app');
const { initDatabase, closeDatabase, getDatabase } = require('../src/db/database');
const {
  GENESIS_HASH,
  appendAuditEntry,
  verifyAuditChain,
  calculateEntryHash,
  sanitizeDetails
} = require('../src/audit/audit-chain');
const { registerUser, loginUser } = require('../src/auth/service');
const { setStorageClient } = require('../src/storage/minio');
const { MemoryStorageClient } = require('../src/storage/memory-storage');
const { resetKeyManager } = require('../src/crypto/key-manager');

test.beforeEach(() => {
  closeDatabase();
  initDatabase(':memory:');
  setStorageClient(new MemoryStorageClient());
  resetKeyManager();
});

test.afterEach(() => {
  closeDatabase();
});

/* -------------------------------------------------------------------------- */
/*                       1. Cryptographic Hash-Chain Engine                   */
/* -------------------------------------------------------------------------- */

test('Audit Engine: Genesis block starts with GENESIS_HASH and increments sequence monotonically', () => {
  const db = getDatabase();

  const entry1 = appendAuditEntry({
    action: 'TEST_ACTION_1',
    actorId: 'user-1',
    actorIp: '127.0.0.1',
    details: { event: 'first' }
  }, db);

  assert.equal(entry1.sequence, 1);
  assert.equal(entry1.prevHash, GENESIS_HASH);
  assert.ok(entry1.entryHash);

  const entry2 = appendAuditEntry({
    action: 'TEST_ACTION_2',
    actorId: 'user-1',
    actorIp: '127.0.0.1',
    details: { event: 'second' }
  }, db);

  assert.equal(entry2.sequence, 2);
  assert.equal(entry2.prevHash, entry1.entryHash);

  const entry3 = appendAuditEntry({
    action: 'TEST_ACTION_3',
    actorId: 'user-2',
    actorIp: '192.168.1.1'
  }, db);

  assert.equal(entry3.sequence, 3);
  assert.equal(entry3.prevHash, entry2.entryHash);

  const report = verifyAuditChain(db);
  assert.equal(report.verified, true);
  assert.equal(report.count, 3);
  assert.equal(report.status, 'CHAIN_INTACT');
  assert.equal(report.headHash, entry3.entryHash);
});

test('Audit Engine: Zero-Secret scrubbing redacts sensitive keys from audit details', () => {
  const details = {
    username: 'alice',
    password: 'test-pass-1',
    apiKey: 'mock-key-1',
    refreshToken: 'mock-tok-1',
    recoveryCode: 'RC-1234',
    safeMetadata: 'public-value'
  };

  const sanitized = JSON.parse(sanitizeDetails(details));
  assert.equal(sanitized.username, 'alice');
  assert.equal(sanitized.password, '[REDACTED]');
  assert.equal(sanitized.apiKey, '[REDACTED]');
  assert.equal(sanitized.refreshToken, '[REDACTED]');
  assert.equal(sanitized.recoveryCode, '[REDACTED]');
  assert.equal(sanitized.safeMetadata, 'public-value');
});

test('Audit Engine: Tamper detection catches modified entry payload', () => {
  const db = getDatabase();

  appendAuditEntry({ action: 'ACTION_A', details: { value: 100 } }, db);
  appendAuditEntry({ action: 'ACTION_B', details: { value: 200 } }, db);
  appendAuditEntry({ action: 'ACTION_C', details: { value: 300 } }, db);

  assert.equal(verifyAuditChain(db).verified, true);

  // Attacker directly modifies the SQLite database to alter details of sequence 2
  db.prepare(`UPDATE audit_logs SET details = ? WHERE sequence = 2`).run(
    JSON.stringify({ value: 999999 })
  );

  const tamperReport = verifyAuditChain(db);
  assert.equal(tamperReport.verified, false);
  assert.equal(tamperReport.status, 'TAMPER_DETECTED');
  assert.equal(tamperReport.brokenSequence, 2);
  assert.match(tamperReport.reason, /Entry hash mismatch/i);
});

test('Audit Engine: Tamper detection catches modified prev_hash (broken chain pointer)', () => {
  const db = getDatabase();

  appendAuditEntry({ action: 'STEP_1' }, db);
  appendAuditEntry({ action: 'STEP_2' }, db);

  // Attacker tampers with prev_hash
  const fakeHash = crypto.createHash('sha256').update('corrupt').digest('hex');
  db.prepare(`UPDATE audit_logs SET prev_hash = ? WHERE sequence = 2`).run(fakeHash);

  const report = verifyAuditChain(db);
  assert.equal(report.verified, false);
  assert.equal(report.brokenSequence, 2);
  assert.match(report.reason, /Previous hash mismatch/i);
});

test('Audit Engine: Tamper detection catches deleted row / sequence gap', () => {
  const db = getDatabase();

  appendAuditEntry({ action: 'TX_1' }, db);
  appendAuditEntry({ action: 'TX_2' }, db);
  appendAuditEntry({ action: 'TX_3' }, db);

  // Attacker deletes TX_2
  db.prepare('DELETE FROM audit_logs WHERE sequence = 2').run();

  const report = verifyAuditChain(db);
  assert.equal(report.verified, false);
  assert.equal(report.status, 'TAMPER_DETECTED');
  assert.match(report.reason, /Sequence gap/i);
});

/* -------------------------------------------------------------------------- */
/*                    2. Sessions API & Real-Time Revocation                  */
/* -------------------------------------------------------------------------- */

test('Sessions API: lists sessions and identifies active current session', async () => {
  const app = createApp({ enableRateLimit: false });
  const email = 'session.user@securevault.io';
  const password = 'VaultPass12!';

  await registerUser({ email, password });

  // First login (Device 1)
  const login1 = await request(app)
    .post('/api/auth/login')
    .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0')
    .send({ email, password });

  assert.equal(login1.status, 200);
  const token1 = login1.body.accessToken;

  // Second login (Device 2)
  const login2 = await request(app)
    .post('/api/auth/login')
    .set('User-Agent', 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)')
    .send({ email, password });

  assert.equal(login2.status, 200);
  const token2 = login2.body.accessToken;

  // Query sessions using Device 2's token
  const listRes = await request(app)
    .get('/api/sessions')
    .set('Authorization', `Bearer ${token2}`);

  assert.equal(listRes.status, 200);
  assert.ok(Array.isArray(listRes.body.sessions));
  assert.equal(listRes.body.sessions.length, 2);

  const currentSession = listRes.body.sessions.find((s) => s.isCurrent === true);
  assert.ok(currentSession, 'Exactly one session must be flagged as current');
  assert.match(currentSession.userAgent, /iPhone/i);

  const otherSession = listRes.body.sessions.find((s) => s.isCurrent === false);
  assert.ok(otherSession);
  assert.match(otherSession.userAgent, /Windows/i);
});

test('Sessions API: revoking a session immediately invalidates its access JWT in real-time', async () => {
  const app = createApp({ enableRateLimit: false });
  const email = 'revoke.user@securevault.io';
  const password = 'VaultPass12!';

  await registerUser({ email, password });

  // Login session A
  const loginA = await request(app)
    .post('/api/auth/login')
    .send({ email, password });
  const tokenA = loginA.body.accessToken;

  // Login session B
  const loginB = await request(app)
    .post('/api/auth/login')
    .send({ email, password });
  const tokenB = loginB.body.accessToken;

  // Verify both tokens are valid
  const checkA = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${tokenA}`);
  assert.equal(checkA.status, 200);

  const checkB = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${tokenB}`);
  assert.equal(checkB.status, 200);

  // Fetch session IDs using session A
  const listRes = await request(app).get('/api/sessions').set('Authorization', `Bearer ${tokenA}`);
  const sessionBId = listRes.body.sessions.find((s) => !s.isCurrent).id;

  // Revoke session B from session A
  const revokeRes = await request(app)
    .delete(`/api/sessions/${sessionBId}`)
    .set('Authorization', `Bearer ${tokenA}`);

  assert.equal(revokeRes.status, 200);
  assert.equal(revokeRes.body.message, 'Session revoked successfully.');

  // Immediate Real-Time Revocation Test:
  // Session B's 15-minute access token must now be rejected immediately!
  const rejectedB = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${tokenB}`);
  assert.equal(rejectedB.status, 401);
  assert.equal(rejectedB.body.code, 'SESSION_REVOKED');

  // Session A remains active
  const stillValidA = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${tokenA}`);
  assert.equal(stillValidA.status, 200);
});

test('Sessions API: revoke-others terminates all foreign sessions and logs audit event', async () => {
  const app = createApp({ enableRateLimit: false });
  const email = 'revoke.others@securevault.io';
  const password = 'VaultPass12!';

  await registerUser({ email, password });

  const login1 = await request(app).post('/api/auth/login').send({ email, password });
  const login2 = await request(app).post('/api/auth/login').send({ email, password });
  const login3 = await request(app).post('/api/auth/login').send({ email, password });

  // Call revoke-others from login3
  const revokeAllRes = await request(app)
    .post('/api/sessions/revoke-others')
    .set('Authorization', `Bearer ${login3.body.accessToken}`);

  assert.equal(revokeAllRes.status, 200);
  assert.equal(revokeAllRes.body.revokedCount, 2);

  // Tokens 1 and 2 must now be rejected
  const test1 = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${login1.body.accessToken}`);
  assert.equal(test1.status, 401);
  assert.equal(test1.body.code, 'SESSION_REVOKED');

  const test2 = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${login2.body.accessToken}`);
  assert.equal(test2.status, 401);
  assert.equal(test2.body.code, 'SESSION_REVOKED');

  // Login 3 remains valid
  const test3 = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${login3.body.accessToken}`);
  assert.equal(test3.status, 200);
});

/* -------------------------------------------------------------------------- */
/*                 3. Audit Verification & Query API Endpoints                */
/* -------------------------------------------------------------------------- */

test('Audit API: /api/audit/verify returns 200 and intact report', async () => {
  const app = createApp({ enableRateLimit: false });
  const email = 'audit.admin@securevault.io';
  const password = 'AdmPass12!';

  await registerUser({ email, password, role: 'admin' });
  const login = await request(app).post('/api/auth/login').send({ email, password });
  const token = login.body.accessToken;

  const verifyRes = await request(app)
    .get('/api/audit/verify')
    .set('Authorization', `Bearer ${token}`);

  assert.equal(verifyRes.status, 200);
  assert.equal(verifyRes.body.verified, true);
  assert.equal(verifyRes.body.status, 'CHAIN_INTACT');
  assert.ok(verifyRes.body.headHash);
});

test('Audit API: /api/audit/verify returns 400 when database tamper is detected', async () => {
  const app = createApp({ enableRateLimit: false });
  const email = 'audit.tamper@securevault.io';
  const password = 'AdmPass12!';

  await registerUser({ email, password, role: 'admin' });
  const login = await request(app).post('/api/auth/login').send({ email, password });
  const token = login.body.accessToken;

  // Simulate SQL injection / physical database tamper
  const db = getDatabase();
  db.prepare('UPDATE audit_logs SET actor_ip = ? WHERE sequence = 1').run('66.66.66.66');

  const verifyRes = await request(app)
    .get('/api/audit/verify')
    .set('Authorization', `Bearer ${token}`);

  assert.equal(verifyRes.status, 400);
  assert.equal(verifyRes.body.verified, false);
  assert.equal(verifyRes.body.status, 'TAMPER_DETECTED');
  assert.equal(verifyRes.body.brokenSequence, 1);
});

test('Audit API: /api/audit returns paginated filterable audit logs', async () => {
  const app = createApp({ enableRateLimit: false });
  const email = 'audit.query@securevault.io';
  const password = 'AdmPass12!';

  await registerUser({ email, password, role: 'admin' });
  const login = await request(app).post('/api/auth/login').send({ email, password });
  const token = login.body.accessToken;

  // Create a secret
  await request(app)
    .post('/api/vault/items')
    .set('Authorization', `Bearer ${token}`)
    .send({ title: 'Audit Test Secret', secret: 'mock-secret-val' });

  const queryRes = await request(app)
    .get('/api/audit?limit=10')
    .set('Authorization', `Bearer ${token}`);

  assert.equal(queryRes.status, 200);
  assert.ok(Array.isArray(queryRes.body.logs));
  assert.ok(queryRes.body.logs.length >= 3); // REGISTER, LOGIN_SUCCESS, VAULT_SECRET_CREATE
  assert.ok(queryRes.body.pagination);
  assert.equal(queryRes.body.verification.verified, true);

  // Filter by action
  const filterRes = await request(app)
    .get('/api/audit?action=VAULT_SECRET_CREATE')
    .set('Authorization', `Bearer ${token}`);

  assert.equal(filterRes.status, 200);
  assert.equal(filterRes.body.logs.length, 1);
  assert.equal(filterRes.body.logs[0].action, 'VAULT_SECRET_CREATE');
});

/* -------------------------------------------------------------------------- */
/*           4. End-to-End Sensitive Operations Hash-Chain Verification       */
/* -------------------------------------------------------------------------- */

test('E2E Audit Trail: All sensitive actions (Auth, Vault, Files, Keys, Roles) write intact chain', async () => {
  const app = createApp({ enableRateLimit: false });

  // 1. Register & Login Admin
  const adminEmail = 'superadmin@securevault.io';
  const password = 'CmplxPass1!';
  await registerUser({ email: adminEmail, password, role: 'admin' });
  const adminLogin = await request(app).post('/api/auth/login').send({ email: adminEmail, password });
  const adminToken = adminLogin.body.accessToken;

  // 2. Register & Login Regular User
  const userEmail = 'bob@securevault.io';
  await registerUser({ email: userEmail, password, role: 'user' });
  const userLogin = await request(app).post('/api/auth/login').send({ email: userEmail, password });
  const userToken = userLogin.body.accessToken;

  // 3. Admin promotes User to Manager
  const targetUserRow = getDatabase().prepare('SELECT id FROM users WHERE email = ?').get(userEmail);
  const roleRes = await request(app)
    .put(`/api/admin/users/${targetUserRow.id}/role`)
    .set('Authorization', `Bearer ${adminToken}`)
    .send({ role: 'manager' });
  assert.equal(roleRes.status, 200);

  // 4. Create and Read Vault Item
  const secretRes = await request(app)
    .post('/api/vault/items')
    .set('Authorization', `Bearer ${userToken}`)
    .send({ title: 'Production API Key', secret: 'mock-api-key' });
  assert.equal(secretRes.status, 201);
  const secretId = secretRes.body.item.id;

  const readRes = await request(app)
    .get(`/api/vault/items/${secretId}`)
    .set('Authorization', `Bearer ${userToken}`);
  assert.equal(readRes.status, 200);

  // 5. Rotate KEK
  const rotateRes = await request(app)
    .post('/api/vault/rotate-keys')
    .set('Authorization', `Bearer ${adminToken}`)
    .send({ newVersion: 'kek_v2' });
  assert.equal(rotateRes.status, 200);

  // 6. Upload and Verify Encrypted File
  const uploadRes = await request(app)
    .post('/api/files/upload')
    .set('Authorization', `Bearer ${userToken}`)
    .attach('file', Buffer.from('Sensitive financial document contents'), 'statement.pdf');
  assert.equal(uploadRes.status, 201);
  const fileId = uploadRes.body.file.id;

  const verifyFileRes = await request(app)
    .get(`/api/files/${fileId}/verify`)
    .set('Authorization', `Bearer ${userToken}`);
  assert.equal(verifyFileRes.status, 200);

  // 7. Verify complete audit chain across all these actions
  const chainCheck = await request(app)
    .get('/api/audit/verify')
    .set('Authorization', `Bearer ${adminToken}`);

  assert.equal(chainCheck.status, 200);
  assert.equal(chainCheck.body.verified, true);
  assert.equal(chainCheck.body.status, 'CHAIN_INTACT');
  assert.ok(chainCheck.body.count >= 8, `Expected at least 8 events, got ${chainCheck.body.count}`);

  // Inspect the sequence monotonicity in database
  const db = getDatabase();
  const allLogs = db.prepare('SELECT sequence, action, prev_hash, entry_hash FROM audit_logs ORDER BY sequence ASC').all();
  for (let i = 0; i < allLogs.length; i++) {
    assert.equal(allLogs[i].sequence, i + 1);
    if (i === 0) {
      assert.equal(allLogs[i].prev_hash, GENESIS_HASH);
    } else {
      assert.equal(allLogs[i].prev_hash, allLogs[i - 1].entry_hash);
    }
  }
});
