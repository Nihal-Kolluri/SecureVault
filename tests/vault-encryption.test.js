const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { initDatabase, closeDatabase, getDatabase } = require('../src/db/database');
const { registerUser } = require('../src/auth/service');
const { generateAccessToken } = require('../src/auth/tokens');
const { createApp } = require('../src/app');
const {
  encryptEnvelope,
  decryptEnvelope,
  rewrapEnvelope
} = require('../src/crypto/envelope');
const {
  getActiveKek,
  rotateActiveKek,
  registerKek,
  resetKeyManager,
  wrapDek,
  unwrapDek
} = require('../src/crypto/key-manager');

test.beforeEach(() => {
  closeDatabase();
  initDatabase(':memory:');
  resetKeyManager();
});

test.afterEach(() => {
  closeDatabase();
});

/* -------------------------------------------------------------------------- */
/*                     1. Envelope Encryption Primitives                      */
/* -------------------------------------------------------------------------- */

test('Envelope Encryption: encrypts and decrypts payloads accurately', () => {
  const plainText = 'mock-api-key-9988';
  const aad = 'item-123:v1';

  const envelope = encryptEnvelope(plainText, { aad });

  assert.ok(envelope.ciphertext);
  assert.ok(envelope.iv);
  assert.ok(envelope.tag);
  assert.ok(envelope.wrappedDek);
  assert.ok(envelope.dekIv);
  assert.ok(envelope.dekTag);
  assert.equal(envelope.kekVersion, 'kek_v1');
  assert.equal(envelope.algorithm, 'aes-256-gcm');

  // Verify IV lengths (12 bytes = 24 hex characters)
  assert.equal(envelope.iv.length, 24);
  assert.equal(envelope.dekIv.length, 24);

  // Verify Auth Tag lengths (16 bytes = 32 hex characters)
  assert.equal(envelope.tag.length, 32);
  assert.equal(envelope.dekTag.length, 32);

  // Decrypt
  const decrypted = decryptEnvelope(envelope, { aad });
  assert.equal(decrypted, plainText);
});

test('Envelope Encryption: random IVs and DEKs ensure semantic security across encryptions', () => {
  const plainText = 'identical-mock-secret';

  const env1 = encryptEnvelope(plainText);
  const env2 = encryptEnvelope(plainText);

  assert.notEqual(env1.ciphertext, env2.ciphertext, 'Ciphertexts must differ due to distinct DEKs & IVs');
  assert.notEqual(env1.iv, env2.iv, 'Payload IVs must be unique per encryption');
  assert.notEqual(env1.wrappedDek, env2.wrappedDek, 'Wrapped DEKs must be unique');
  assert.notEqual(env1.dekIv, env2.dekIv, 'DEK IVs must be unique');

  assert.equal(decryptEnvelope(env1), plainText);
  assert.equal(decryptEnvelope(env2), plainText);
});

/* -------------------------------------------------------------------------- */
/*                         2. Ciphertext at Rest Proof                        */
/* -------------------------------------------------------------------------- */

test('Ciphertext at Rest: plaintext secret NEVER appears anywhere in database tables', async () => {
  const app = createApp({ enableRateLimit: false });

  const user = await registerUser({
    email: 'alice.vault@securevault.io',
    password: 'Password123!@#'
  });
  const token = generateAccessToken(user);

  const sensitiveSample = 'CONFIDENTIAL_DATA_9988';

  const createRes = await request(app)
    .post('/api/vault/items')
    .set('Authorization', `Bearer ${token}`)
    .send({
      title: 'Stripe Production Key',
      category: 'api_key',
      secret: sensitiveSample
    });

  assert.equal(createRes.status, 201);
  const itemId = createRes.body.item.id;

  // Inspect database directly using raw SQL
  const db = getDatabase();
  const rawItem = db.prepare('SELECT * FROM vault_items WHERE id = ?').get(itemId);
  const rawVersion = db.prepare('SELECT * FROM vault_item_versions WHERE item_id = ?').get(itemId);

  // 1. Verify item fields are purely cryptographic tokens and ciphertext
  assert.ok(rawItem.ciphertext);
  assert.ok(rawItem.encrypted_dek);
  assert.ok(rawItem.iv);
  assert.ok(rawItem.tag);
  assert.ok(rawItem.dek_iv);
  assert.ok(rawItem.dek_tag);

  // 2. Strict assertion: plaintext secret must NOT exist in any column
  for (const [col, value] of Object.entries(rawItem)) {
    if (typeof value === 'string') {
      assert.ok(
        !value.includes(sensitiveSample),
        `Plaintext secret leaked in vault_items column '${col}'!`
      );
    }
  }

  // 3. Strict assertion: plaintext secret must NOT exist in version history
  for (const [col, value] of Object.entries(rawVersion)) {
    if (typeof value === 'string') {
      assert.ok(
        !value.includes(sensitiveSample),
        `Plaintext secret leaked in vault_item_versions column '${col}'!`
      );
    }
  }
});

/* -------------------------------------------------------------------------- */
/*                       3. Tamper Detection & Integrity                      */
/* -------------------------------------------------------------------------- */

test('Tamper detection: modifying 1 bit of ciphertext causes AES-GCM tag verification failure', () => {
  const plainText = 'financial-payload';
  const envelope = encryptEnvelope(plainText);

  // Tamper with first byte of ciphertext
  const tamperedCiphertext = (envelope.ciphertext[0] === 'a' ? 'b' : 'a') + envelope.ciphertext.slice(1);
  const tamperedEnvelope = { ...envelope, ciphertext: tamperedCiphertext };

  assert.throws(
    () => decryptEnvelope(tamperedEnvelope),
    (err) => err.code === 'ERR_CIPHERTEXT_TAMPER' && /tamper detected/i.test(err.message),
    'Must reject tampered ciphertext with ERR_CIPHERTEXT_TAMPER'
  );
});

test('Tamper detection: modifying IV, tag, or AAD causes tag verification failure', () => {
  const plainText = 'auth-credential';
  const aad = 'doc-1:v1';
  const envelope = encryptEnvelope(plainText, { aad });

  // 1. Tampered payload IV
  const tamperedIv = (envelope.iv[0] === '1' ? '2' : '1') + envelope.iv.slice(1);
  assert.throws(
    () => decryptEnvelope({ ...envelope, iv: tamperedIv }, { aad }),
    (err) => err.code === 'ERR_CIPHERTEXT_TAMPER'
  );

  // 2. Tampered auth tag
  const tamperedTag = (envelope.tag[0] === '0' ? '1' : '0') + envelope.tag.slice(1);
  assert.throws(
    () => decryptEnvelope({ ...envelope, tag: tamperedTag }, { aad }),
    (err) => err.code === 'ERR_CIPHERTEXT_TAMPER'
  );

  // 3. Transposition attack: Tampered AAD context
  assert.throws(
    () => decryptEnvelope(envelope, { aad: 'doc-999:v2' }),
    (err) => err.code === 'ERR_CIPHERTEXT_TAMPER'
  );

  // 4. Tampered wrapped DEK
  const tamperedDek = (envelope.wrappedDek[0] === 'f' ? 'e' : 'f') + envelope.wrappedDek.slice(1);
  assert.throws(
    () => decryptEnvelope({ ...envelope, wrappedDek: tamperedDek }, { aad }),
    (err) => err.code === 'ERR_DEK_TAMPER'
  );
});

test('Tamper detection: API endpoint returns 400 when database record has been tampered', async () => {
  const app = createApp({ enableRateLimit: false });

  const user = await registerUser({
    email: 'bob.vault@securevault.io',
    password: 'Password123!@#'
  });
  const token = generateAccessToken(user);

  const createRes = await request(app)
    .post('/api/vault/items')
    .set('Authorization', `Bearer ${token}`)
    .send({
      title: 'Database Password',
      secret: 'mock-db-pass-1'
    });
  const itemId = createRes.body.item.id;

  // Tamper with ciphertext in database directly
  const db = getDatabase();
  const current = db.prepare('SELECT ciphertext FROM vault_items WHERE id = ?').get(itemId);
  const tampered = (current.ciphertext[0] === 'c' ? 'd' : 'c') + current.ciphertext.slice(1);
  db.prepare('UPDATE vault_items SET ciphertext = ? WHERE id = ?').run(tampered, itemId);

  // Requesting item now should detect tampering and fail with 400
  const getRes = await request(app)
    .get(`/api/vault/items/${itemId}`)
    .set('Authorization', `Bearer ${token}`);

  assert.equal(getRes.status, 400);
  assert.match(getRes.body.error, /Cryptographic tamper detected/i);
});

/* -------------------------------------------------------------------------- */
/*                         4. Key Rotation & Re-Wrapping                      */
/* -------------------------------------------------------------------------- */

test('Key Rotation: rotates KEK from v1 to v2, re-wrapping DEKs without re-encrypting payloads', async () => {
  const app = createApp({ enableRateLimit: false });

  const user = await registerUser({
    email: 'carol.vault@securevault.io',
    password: 'Password123!@#'
  });
  const token = generateAccessToken(user);

  // 1. Create two items under KEK v1
  const item1Res = await request(app)
    .post('/api/vault/items')
    .set('Authorization', `Bearer ${token}`)
    .send({ title: 'Item 1', secret: 'mock-secret-one' });
  const item1Id = item1Res.body.item.id;

  const item2Res = await request(app)
    .post('/api/vault/items')
    .set('Authorization', `Bearer ${token}`)
    .send({ title: 'Item 2', secret: 'mock-secret-two' });
  const item2Id = item2Res.body.item.id;

  const db = getDatabase();
  const item1Before = db.prepare('SELECT * FROM vault_items WHERE id = ?').get(item1Id);
  assert.equal(item1Before.kek_version, 'kek_v1');

  // 2. Perform Key Rotation
  const rotateRes = await request(app)
    .post('/api/vault/rotate-keys')
    .set('Authorization', `Bearer ${token}`)
    .send({ newVersion: 'kek_v2' });

  assert.equal(rotateRes.status, 200);
  assert.equal(rotateRes.body.activeKekVersion, 'kek_v2');
  assert.ok(rotateRes.body.itemsRotated >= 2);

  // 3. Inspect database: verify kek_version updated and DEK re-wrapped
  const item1After = db.prepare('SELECT * FROM vault_items WHERE id = ?').get(item1Id);
  assert.equal(item1After.kek_version, 'kek_v2');
  assert.notEqual(item1After.encrypted_dek, item1Before.encrypted_dek, 'DEK must be re-wrapped with new KEK');
  assert.equal(item1After.ciphertext, item1Before.ciphertext, 'Payload ciphertext remains unchanged (re-wrapping efficiency)');

  // 4. Decrypt via API: succeeds under rotated key
  const readRes1 = await request(app)
    .get(`/api/vault/items/${item1Id}`)
    .set('Authorization', `Bearer ${token}`);
  assert.equal(readRes1.status, 200);
  assert.equal(readRes1.body.secret, 'mock-secret-one');

  const readRes2 = await request(app)
    .get(`/api/vault/items/${item2Id}`)
    .set('Authorization', `Bearer ${token}`);
  assert.equal(readRes2.status, 200);
  assert.equal(readRes2.body.secret, 'mock-secret-two');
});

/* -------------------------------------------------------------------------- */
/*                     5. Vault CRUD with Versions & Sharing                  */
/* -------------------------------------------------------------------------- */

test('Vault Versions: updating secret creates new version with distinct DEK while preserving history', async () => {
  const app = createApp({ enableRateLimit: false });

  const user = await registerUser({
    email: 'dave.vault@securevault.io',
    password: 'Password123!@#'
  });
  const token = generateAccessToken(user);

  // 1. Create initial version (v1)
  const createRes = await request(app)
    .post('/api/vault/items')
    .set('Authorization', `Bearer ${token}`)
    .send({
      title: 'OAuth Secret',
      category: 'api_key',
      secret: 'initial-payload-v1'
    });
  const itemId = createRes.body.item.id;

  // 2. Update item with new secret (v2)
  const updateRes = await request(app)
    .put(`/api/vault/items/${itemId}`)
    .set('Authorization', `Bearer ${token}`)
    .send({
      title: 'OAuth Secret (Rotated)',
      secret: 'updated-payload-v2'
    });
  assert.equal(updateRes.status, 200);
  assert.equal(updateRes.body.item.current_version, 2);

  // 3. Read active item -> returns v2
  const activeRes = await request(app)
    .get(`/api/vault/items/${itemId}`)
    .set('Authorization', `Bearer ${token}`);
  assert.equal(activeRes.status, 200);
  assert.equal(activeRes.body.version, 2);
  assert.equal(activeRes.body.secret, 'updated-payload-v2');

  // 4. Read historical version 1 via ?version=1 -> recovers original secret
  const historicalRes = await request(app)
    .get(`/api/vault/items/${itemId}?version=1`)
    .set('Authorization', `Bearer ${token}`);
  assert.equal(historicalRes.status, 200);
  assert.equal(historicalRes.body.version, 1);
  assert.equal(historicalRes.body.secret, 'initial-payload-v1');

  // 5. Query version list
  const versionsListRes = await request(app)
    .get(`/api/vault/items/${itemId}/versions`)
    .set('Authorization', `Bearer ${token}`);
  assert.equal(versionsListRes.status, 200);
  assert.equal(versionsListRes.body.versions.length, 2);
  assert.equal(versionsListRes.body.versions[0].version, 2);
  assert.equal(versionsListRes.body.versions[1].version, 1);
});

test('Vault Sharing: recipient can decrypt item, collaborator can create new version, revoked share denies access', async () => {
  const app = createApp({ enableRateLimit: false });

  const owner = await registerUser({
    email: 'owner.team@securevault.io',
    password: 'Password123!@#'
  });
  const collaborator = await registerUser({
    email: 'collab.team@securevault.io',
    password: 'Password123!@#'
  });

  const ownerToken = generateAccessToken(owner);
  const collabToken = generateAccessToken(collaborator);

  // 1. Owner creates secret
  const createRes = await request(app)
    .post('/api/vault/items')
    .set('Authorization', `Bearer ${ownerToken}`)
    .send({
      title: 'Shared SSH Key',
      secret: 'mock-ssh-key-data'
    });
  const itemId = createRes.body.item.id;

  // 2. Owner shares with collaborator with 'write' permission using collaborator's email
  const shareRes = await request(app)
    .post(`/api/vault/items/${itemId}/share`)
    .set('Authorization', `Bearer ${ownerToken}`)
    .send({
      email: 'collab.team@securevault.io',
      permission: 'write'
    });
  assert.equal(shareRes.status, 201);
  assert.equal(shareRes.body.share.permission, 'write');

  // 3. Collaborator reads and decrypts item
  const collabReadRes = await request(app)
    .get(`/api/vault/items/${itemId}`)
    .set('Authorization', `Bearer ${collabToken}`);
  assert.equal(collabReadRes.status, 200);
  assert.equal(collabReadRes.body.secret, 'mock-ssh-key-data');

  // 4. Collaborator updates secret (bumping version to 2)
  const collabUpdateRes = await request(app)
    .put(`/api/vault/items/${itemId}`)
    .set('Authorization', `Bearer ${collabToken}`)
    .send({
      secret: 'mock-ssh-key-v2'
    });
  assert.equal(collabUpdateRes.status, 200);
  assert.equal(collabUpdateRes.body.item.current_version, 2);

  // 5. Owner reads and verifies updated version
  const ownerReadRes = await request(app)
    .get(`/api/vault/items/${itemId}`)
    .set('Authorization', `Bearer ${ownerToken}`);
  assert.equal(ownerReadRes.body.secret, 'mock-ssh-key-v2');

  // 6. Owner revokes share
  const revokeRes = await request(app)
    .delete(`/api/vault/items/${itemId}/share/${collaborator.id}`)
    .set('Authorization', `Bearer ${ownerToken}`);
  assert.equal(revokeRes.status, 200);

  // 7. Collaborator is immediately blocked (403 Forbidden)
  const blockedRes = await request(app)
    .get(`/api/vault/items/${itemId}`)
    .set('Authorization', `Bearer ${collabToken}`);
  assert.equal(blockedRes.status, 403);
});
