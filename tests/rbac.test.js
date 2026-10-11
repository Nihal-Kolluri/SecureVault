const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { initDatabase, closeDatabase, getDatabase } = require('../src/db/database');
const { registerUser } = require('../src/auth/service');
const { generateAccessToken } = require('../src/auth/tokens');
const { createApp } = require('../src/app');
const { resetRateLimits } = require('../src/gateway/rate-limiter');

test.beforeEach(async () => {
  closeDatabase();
  initDatabase(':memory:');
  await resetRateLimits();
});

test.afterEach(() => {
  closeDatabase();
});

/* -------------------------------------------------------------------------- */
/*                 1. RBAC Middleware & Admin Role Protection                 */
/* -------------------------------------------------------------------------- */

test('RBAC: unauthenticated requests to admin endpoints return 401', async () => {
  const app = createApp({ enableRateLimit: false });

  const res = await request(app).get('/api/admin/users');
  assert.equal(res.status, 401);
  assert.match(res.body.error, /Authentication required/i);
});

test('RBAC: standard user attempting admin actions receives 403 Forbidden', async () => {
  const app = createApp({ enableRateLimit: false });

  const regularUser = await registerUser({
    email: 'user@securevault.io',
    password: 'UserPass123!@#',
    role: 'user'
  });

  const token = generateAccessToken(regularUser);

  const res = await request(app)
    .get('/api/admin/users')
    .set('Authorization', `Bearer ${token}`);

  assert.equal(res.status, 403);
  assert.match(res.body.error, /Insufficient privileges/i);
});

test('RBAC: manager attempting admin actions receives 403 Forbidden', async () => {
  const app = createApp({ enableRateLimit: false });

  const managerUser = await registerUser({
    email: 'manager@securevault.io',
    password: 'ManagerPass123!@#',
    role: 'manager'
  });

  const token = generateAccessToken(managerUser);

  const res = await request(app)
    .get('/api/admin/users')
    .set('Authorization', `Bearer ${token}`);

  assert.equal(res.status, 403);
  assert.match(res.body.error, /Insufficient privileges/i);
});

test('RBAC: admin user can list users and update roles', async () => {
  const app = createApp({ enableRateLimit: false });

  const admin = await registerUser({
    email: 'admin@securevault.io',
    password: 'AdminPass123!@#',
    role: 'admin'
  });

  const targetUser = await registerUser({
    email: 'target@securevault.io',
    password: 'TargetPass123!@#',
    role: 'user'
  });

  const adminToken = generateAccessToken(admin);

  // 1. List users
  const listRes = await request(app)
    .get('/api/admin/users')
    .set('Authorization', `Bearer ${adminToken}`);

  assert.equal(listRes.status, 200);
  assert.ok(Array.isArray(listRes.body.users));
  assert.ok(listRes.body.users.some((u) => u.email === 'target@securevault.io'));

  // 2. Change role from user to manager
  const updateRes = await request(app)
    .put(`/api/admin/users/${targetUser.id}/role`)
    .set('Authorization', `Bearer ${adminToken}`)
    .send({ role: 'manager' });

  assert.equal(updateRes.status, 200);
  assert.equal(updateRes.body.user.role, 'manager');

  // Verify in database
  const db = getDatabase();
  const updatedRow = db.prepare('SELECT role FROM users WHERE id = ?').get(targetUser.id);
  assert.equal(updatedRow.role, 'manager');
});

/* -------------------------------------------------------------------------- */
/*                 2. Ownership and Share Authorization                       */
/* -------------------------------------------------------------------------- */

test('Ownership: owner has full access (create, read, update, delete)', async () => {
  const app = createApp({ enableRateLimit: false });

  const owner = await registerUser({
    email: 'owner@securevault.io',
    password: 'OwnerPassword123!',
    role: 'user'
  });
  const ownerToken = generateAccessToken(owner);

  // 1. Create vault item
  const createRes = await request(app)
    .post('/api/vault/items')
    .set('Authorization', `Bearer ${ownerToken}`)
    .send({
      title: 'Production API Key',
      encryptedData: 'aes-gcm-cipher-payload-string'
    });

  assert.equal(createRes.status, 201);
  const itemId = createRes.body.item.id;
  assert.ok(itemId);

  // 2. Read vault item
  const getRes = await request(app)
    .get(`/api/vault/items/${itemId}`)
    .set('Authorization', `Bearer ${ownerToken}`);

  assert.equal(getRes.status, 200);
  assert.equal(getRes.body.item.title, 'Production API Key');
  assert.equal(getRes.body.access.isOwner, true);

  // 3. Update vault item
  const updateRes = await request(app)
    .put(`/api/vault/items/${itemId}`)
    .set('Authorization', `Bearer ${ownerToken}`)
    .send({
      title: 'Production API Key (Updated)',
      encryptedData: 'updated-cipher-payload'
    });

  assert.equal(updateRes.status, 200);
  assert.equal(updateRes.body.item.title, 'Production API Key (Updated)');

  // 4. Delete vault item
  const deleteRes = await request(app)
    .delete(`/api/vault/items/${itemId}`)
    .set('Authorization', `Bearer ${ownerToken}`);

  assert.equal(deleteRes.status, 200);

  // 5. Verify 404 after deletion
  const verifyRes = await request(app)
    .get(`/api/vault/items/${itemId}`)
    .set('Authorization', `Bearer ${ownerToken}`);

  assert.equal(verifyRes.status, 404);
});

test('Ownership: unrelated user receives 403 Forbidden', async () => {
  const app = createApp({ enableRateLimit: false });

  const owner = await registerUser({
    email: 'alice@securevault.io',
    password: 'AlicePassword123!',
    role: 'user'
  });
  const attacker = await registerUser({
    email: 'eve@securevault.io',
    password: 'EvePassword123!',
    role: 'user'
  });

  const ownerToken = generateAccessToken(owner);
  const attackerToken = generateAccessToken(attacker);

  // Alice creates secret
  const createRes = await request(app)
    .post('/api/vault/items')
    .set('Authorization', `Bearer ${ownerToken}`)
    .send({
      title: 'Alice Secret',
      encryptedData: 'super-confidential-bytes'
    });
  const itemId = createRes.body.item.id;

  // Eve tries to read -> 403
  const getRes = await request(app)
    .get(`/api/vault/items/${itemId}`)
    .set('Authorization', `Bearer ${attackerToken}`);
  assert.equal(getRes.status, 403);

  // Eve tries to edit -> 403
  const putRes = await request(app)
    .put(`/api/vault/items/${itemId}`)
    .set('Authorization', `Bearer ${attackerToken}`)
    .send({ title: 'Hacked Title' });
  assert.equal(putRes.status, 403);

  // Eve tries to delete -> 403
  const delRes = await request(app)
    .delete(`/api/vault/items/${itemId}`)
    .set('Authorization', `Bearer ${attackerToken}`);
  assert.equal(delRes.status, 403);
});

test('Sharing: "read" share allows viewing but denies write, delete, and re-sharing', async () => {
  const app = createApp({ enableRateLimit: false });

  const owner = await registerUser({
    email: 'owner-read@securevault.io',
    password: 'OwnerPassword123!'
  });
  const recipient = await registerUser({
    email: 'reader@securevault.io',
    password: 'ReaderPassword123!'
  });
  const thirdParty = await registerUser({
    email: 'thirdparty@securevault.io',
    password: 'ThirdParty123!'
  });

  const ownerToken = generateAccessToken(owner);
  const readerToken = generateAccessToken(recipient);

  // Owner creates item
  const createRes = await request(app)
    .post('/api/vault/items')
    .set('Authorization', `Bearer ${ownerToken}`)
    .send({ title: 'Shared Document', encryptedData: 'data-payload' });
  const itemId = createRes.body.item.id;

  // Owner shares with recipient as 'read'
  const shareRes = await request(app)
    .post(`/api/vault/items/${itemId}/share`)
    .set('Authorization', `Bearer ${ownerToken}`)
    .send({
      sharedWithUserId: recipient.id,
      permission: 'read'
    });
  assert.equal(shareRes.status, 201);
  assert.equal(shareRes.body.share.permission, 'read');

  // Recipient views item in their items list
  const listRes = await request(app)
    .get('/api/vault/items')
    .set('Authorization', `Bearer ${readerToken}`);
  assert.equal(listRes.status, 200);
  assert.ok(listRes.body.items.some((i) => i.id === itemId && i.access_level === 'read'));

  // Recipient reads single item -> allowed
  const readRes = await request(app)
    .get(`/api/vault/items/${itemId}`)
    .set('Authorization', `Bearer ${readerToken}`);
  assert.equal(readRes.status, 200);
  assert.equal(readRes.body.access.permission, 'read');

  // Recipient tries to modify item -> 403 Forbidden
  const modifyRes = await request(app)
    .put(`/api/vault/items/${itemId}`)
    .set('Authorization', `Bearer ${readerToken}`)
    .send({ title: 'Tampered Title' });
  assert.equal(modifyRes.status, 403);
  assert.match(modifyRes.body.error, /Write permission required/i);

  // Recipient tries to delete item -> 403 Forbidden
  const deleteRes = await request(app)
    .delete(`/api/vault/items/${itemId}`)
    .set('Authorization', `Bearer ${readerToken}`);
  assert.equal(deleteRes.status, 403);
  assert.match(deleteRes.body.error, /Only the resource owner/i);

  // Recipient tries to share with third party -> 403 Forbidden
  const reShareRes = await request(app)
    .post(`/api/vault/items/${itemId}/share`)
    .set('Authorization', `Bearer ${readerToken}`)
    .send({ sharedWithUserId: thirdParty.id, permission: 'read' });
  assert.equal(reShareRes.status, 403);
  assert.match(reShareRes.body.error, /Only the resource owner/i);
});

test('Sharing: "write" share allows updating but denies delete', async () => {
  const app = createApp({ enableRateLimit: false });

  const owner = await registerUser({
    email: 'owner-write@securevault.io',
    password: 'OwnerPassword123!'
  });
  const editor = await registerUser({
    email: 'editor@securevault.io',
    password: 'EditorPassword123!'
  });

  const ownerToken = generateAccessToken(owner);
  const editorToken = generateAccessToken(editor);

  // Owner creates item
  const createRes = await request(app)
    .post('/api/vault/items')
    .set('Authorization', `Bearer ${ownerToken}`)
    .send({ title: 'Team Secret', encryptedData: 'initial-state' });
  const itemId = createRes.body.item.id;

  // Owner shares with editor with 'write'
  const shareRes = await request(app)
    .post(`/api/vault/items/${itemId}/share`)
    .set('Authorization', `Bearer ${ownerToken}`)
    .send({ sharedWithUserId: editor.id, permission: 'write' });
  assert.equal(shareRes.status, 201);

  // Editor updates item -> 200 OK
  const updateRes = await request(app)
    .put(`/api/vault/items/${itemId}`)
    .set('Authorization', `Bearer ${editorToken}`)
    .send({ title: 'Team Secret (Modified)', encryptedData: 'updated-by-editor' });
  assert.equal(updateRes.status, 200);
  assert.equal(updateRes.body.item.title, 'Team Secret (Modified)');

  // Editor tries to delete item -> 403 Forbidden
  const delRes = await request(app)
    .delete(`/api/vault/items/${itemId}`)
    .set('Authorization', `Bearer ${editorToken}`);
  assert.equal(delRes.status, 403);
});

test('Sharing: revoking share removes access immediately', async () => {
  const app = createApp({ enableRateLimit: false });

  const owner = await registerUser({
    email: 'owner-revoke@securevault.io',
    password: 'OwnerPassword123!'
  });
  const user = await registerUser({
    email: 'user-revoke@securevault.io',
    password: 'UserPassword123!'
  });

  const ownerToken = generateAccessToken(owner);
  const userToken = generateAccessToken(user);

  const createRes = await request(app)
    .post('/api/vault/items')
    .set('Authorization', `Bearer ${ownerToken}`)
    .send({ title: 'Temporary Share', encryptedData: 'temp-data' });
  const itemId = createRes.body.item.id;

  // Share
  await request(app)
    .post(`/api/vault/items/${itemId}/share`)
    .set('Authorization', `Bearer ${ownerToken}`)
    .send({ sharedWithUserId: user.id, permission: 'read' });

  // User can read
  const readRes1 = await request(app)
    .get(`/api/vault/items/${itemId}`)
    .set('Authorization', `Bearer ${userToken}`);
  assert.equal(readRes1.status, 200);

  // Owner revokes share
  const revokeRes = await request(app)
    .delete(`/api/vault/items/${itemId}/share/${user.id}`)
    .set('Authorization', `Bearer ${ownerToken}`);
  assert.equal(revokeRes.status, 200);

  // User can no longer read -> 403
  const readRes2 = await request(app)
    .get(`/api/vault/items/${itemId}`)
    .set('Authorization', `Bearer ${userToken}`);
  assert.equal(readRes2.status, 403);
});
