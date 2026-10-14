const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const crypto = require('crypto');
const { Readable } = require('stream');

const { createApp } = require('../src/app');
const { initDatabase, closeDatabase, getDatabase } = require('../src/db/database');
const {
  FileEncryptionPipeline,
  FileDecryptionPipeline,
  createFileEnvelope,
  verifyCiphertextStream
} = require('../src/crypto/stream-crypto');
const {
  MemoryStorageClient
} = require('../src/storage/memory-storage');
const {
  setStorageClient,
  resetStorageClient,
  getBucketName
} = require('../src/storage/minio');

// Helper to convert Buffer to Readable stream
function bufferToStream(buffer) {
  return new Readable({
    read() {
      this.push(buffer);
      this.push(null);
    }
  });
}

// Helper to collect stream into buffer
async function streamToBuffer(stream) {
  const chunks = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

test('Storage: MemoryStorageClient put, get, stat, and remove streaming', async () => {
  const storage = new MemoryStorageClient();
  const bucket = 'test-bucket';
  const objectKey = 'folder/test.dat';
  const content = Buffer.from('Secure storage test payload 1234567890');

  // Put object
  await storage.putObject(bucket, objectKey, bufferToStream(content), content.length, {
    'custom-meta': 'vault-meta'
  });

  // Stat object
  const stat = await storage.statObject(bucket, objectKey);
  assert.equal(stat.size, content.length);
  assert.equal(stat.metaData['custom-meta'], 'vault-meta');

  // Get object
  const downloadStream = await storage.getObject(bucket, objectKey);
  const downloadedBuffer = await streamToBuffer(downloadStream);
  assert.deepEqual(downloadedBuffer, content);

  // Remove object
  await storage.removeObject(bucket, objectKey);
  await assert.rejects(async () => {
    await storage.getObject(bucket, objectKey);
  }, /does not exist/);
});

test('Crypto Stream: encrypts and decrypts payload with AES-256-GCM and SHA-256 verification', async () => {
  const dek = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const aad = 'file:file-123:user-456:document.pdf';
  const plaintext = Buffer.from('Top Secret Document Content - Stream Cryptography in Action!');
  const expectedChecksum = crypto.createHash('sha256').update(plaintext).digest('hex');

  // Encryption pipeline
  const encPipeline = new FileEncryptionPipeline({ dek, iv, aad });
  const encStream = bufferToStream(plaintext).pipe(encPipeline);
  const ciphertext = await streamToBuffer(encStream);

  assert.notDeepEqual(ciphertext, plaintext, 'Ciphertext must not match plaintext');
  assert.equal(encPipeline.plaintextSize, plaintext.length);
  assert.ok(encPipeline.ciphertextSize > 0);
  assert.ok(encPipeline.authTag instanceof Buffer);
  assert.equal(encPipeline.authTag.length, 16);
  assert.equal(encPipeline.sha256Checksum, expectedChecksum);

  // Decryption pipeline
  const decPipeline = new FileDecryptionPipeline({
    dek,
    iv,
    tag: encPipeline.authTag,
    aad,
    expectedChecksum
  });
  const decStream = bufferToStream(ciphertext).pipe(decPipeline);
  const decrypted = await streamToBuffer(decStream);

  assert.deepEqual(decrypted, plaintext, 'Decrypted buffer must match original plaintext exactly');
  assert.equal(decPipeline.computedChecksum, expectedChecksum);
  assert.equal(decPipeline.isVerified, true);
});

test('Crypto Stream: tamper detection on ciphertext flip and tag corruption', async () => {
  const dek = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const aad = 'file:test:integrity:doc.txt';
  const plaintext = Buffer.from('Confidential vault data for tamper test');
  const expectedChecksum = crypto.createHash('sha256').update(plaintext).digest('hex');

  const encPipeline = new FileEncryptionPipeline({ dek, iv, aad });
  const ciphertext = await streamToBuffer(bufferToStream(plaintext).pipe(encPipeline));
  const validTag = encPipeline.authTag;

  // 1. Bit flip in ciphertext
  const tamperedCiphertext = Buffer.from(ciphertext);
  tamperedCiphertext[0] ^= 0x01; // flip 1 bit

  const decPipelineTampered = new FileDecryptionPipeline({
    dek,
    iv,
    tag: validTag,
    aad,
    expectedChecksum
  });

  await assert.rejects(async () => {
    await streamToBuffer(bufferToStream(tamperedCiphertext).pipe(decPipelineTampered));
  }, (err) => err.code === 'ERR_CIPHERTEXT_TAMPER');

  // 2. Corrupt auth tag
  const corruptedTag = Buffer.from(validTag);
  corruptedTag[0] ^= 0x01;

  const decPipelineCorruptTag = new FileDecryptionPipeline({
    dek,
    iv,
    tag: corruptedTag,
    aad,
    expectedChecksum
  });

  await assert.rejects(async () => {
    await streamToBuffer(bufferToStream(ciphertext).pipe(decPipelineCorruptTag));
  }, (err) => err.code === 'ERR_CIPHERTEXT_TAMPER');

  // 3. Altered AAD context
  const decPipelineAlteredAad = new FileDecryptionPipeline({
    dek,
    iv,
    tag: validTag,
    aad: 'file:wrong:context:doc.txt',
    expectedChecksum
  });

  await assert.rejects(async () => {
    await streamToBuffer(bufferToStream(ciphertext).pipe(decPipelineAlteredAad));
  }, (err) => err.code === 'ERR_CIPHERTEXT_TAMPER');
});

test('Crypto Stream: enforces size limits during streaming', async () => {
  const dek = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const pipeline = new FileEncryptionPipeline({ dek, iv, maxSizeBytes: 20 });
  const oversizedData = Buffer.alloc(100, 'A');

  await assert.rejects(async () => {
    await streamToBuffer(bufferToStream(oversizedData).pipe(pipeline));
  }, (err) => err.code === 'LIMIT_FILE_SIZE');
});

test('E2E Files API: Streaming Upload -> Checksum -> Download -> Verify -> Delete', async () => {
  closeDatabase();
  initDatabase(':memory:');
  const memoryStorage = new MemoryStorageClient();
  setStorageClient(memoryStorage);

  const app = createApp({ enableRateLimit: false });

  // 1. Register and sign in user A
  const userAEmail = 'alice.files@securevault.io';
  const passA = 'SecureFilesPass123!';
  await request(app)
    .post('/api/auth/register')
    .send({ email: userAEmail, password: passA })
    .expect(201);

  const loginRes = await request(app)
    .post('/api/auth/login')
    .send({ email: userAEmail, password: passA })
    .expect(200);

  const authCookie = loginRes.headers['set-cookie'];
  const accessToken = loginRes.body.accessToken;

  // 2. Prepare file data and compute expected SHA-256
  const originalContent = Buffer.from('Alpha Bravo Charlie Delta - Confidential Financial Forecast 2027');
  const calculatedSha256 = crypto.createHash('sha256').update(originalContent).digest('hex');

  // 3. Upload file via multipart/form-data
  const uploadRes = await request(app)
    .post('/api/files/upload')
    .set('Cookie', authCookie)
    .set('Authorization', `Bearer ${accessToken}`)
    .set('X-Checksum-SHA256', calculatedSha256)
    .attach('file', originalContent, { filename: 'financial_forecast_2027.pdf', contentType: 'application/pdf' })
    .expect(201);

  assert.ok(uploadRes.body.file);
  const uploadedFile = uploadRes.body.file;
  assert.equal(uploadedFile.filename, 'financial_forecast_2027.pdf');
  assert.equal(uploadedFile.sizeBytes, originalContent.length);
  assert.equal(uploadedFile.sha256Checksum, calculatedSha256);
  assert.equal(uploadedFile.algorithm, 'aes-256-gcm');

  // 4. Verify Ciphertext at Rest: plaintext NEVER appears in object storage or database!
  const db = getDatabase();
  const dbRow = db.prepare('SELECT * FROM vault_files WHERE id = ?').get(uploadedFile.id);
  assert.ok(dbRow);
  assert.equal(dbRow.sha256_checksum, calculatedSha256);
  assert.ok(dbRow.encrypted_dek);

  const storageKey = dbRow.storage_key;
  const rawCiphertextBuffer = memoryStorage._getRawBuffer(getBucketName(), storageKey);
  assert.ok(rawCiphertextBuffer);
  assert.equal(rawCiphertextBuffer.includes(originalContent), false, 'Storage must contain ciphertext, not plaintext!');

  // Check SQLite database raw text for plaintext leaks
  const allDbText = JSON.stringify(dbRow);
  assert.equal(allDbText.includes(originalContent.toString('utf8')), false, 'Database must never store plaintext payload');

  // 5. Download and verify exact streaming decryption
  const downloadRes = await request(app)
    .get(`/api/files/${uploadedFile.id}/download`)
    .set('Cookie', authCookie)
    .set('Authorization', `Bearer ${accessToken}`)
    .expect(200);

  assert.equal(downloadRes.headers['content-type'], 'application/pdf');
  assert.equal(downloadRes.headers['x-checksum-sha256'], calculatedSha256);
  assert.equal(downloadRes.headers['content-length'], String(originalContent.length));
  assert.deepEqual(downloadRes.body, originalContent, 'Downloaded file must match uploaded file byte-for-byte');

  // 6. Test Integrity Verification endpoint
  const verifyRes = await request(app)
    .get(`/api/files/${uploadedFile.id}/verify`)
    .set('Cookie', authCookie)
    .set('Authorization', `Bearer ${accessToken}`)
    .expect(200);

  assert.equal(verifyRes.body.verified, true);
  assert.equal(verifyRes.body.sha256Checksum, calculatedSha256);
  assert.equal(verifyRes.body.status, 'INTACT_AND_AUTHENTICATED');

  // 7. Tamper Detection at Rest: Modify 1 bit in MinIO storage and verify download/verify fails!
  const tamperedStorageBuf = Buffer.from(rawCiphertextBuffer);
  tamperedStorageBuf[0] ^= 0x01; // flip 1 bit
  memoryStorage._setRawBuffer(getBucketName(), storageKey, tamperedStorageBuf);

  // Verify endpoint must report tamper
  const tamperedVerifyRes = await request(app)
    .get(`/api/files/${uploadedFile.id}/verify`)
    .set('Cookie', authCookie)
    .set('Authorization', `Bearer ${accessToken}`)
    .expect(400);

  assert.equal(tamperedVerifyRes.body.verified, false);
  assert.equal(tamperedVerifyRes.body.code, 'ERR_CIPHERTEXT_TAMPER');

  // Download must fail
  await request(app)
    .get(`/api/files/${uploadedFile.id}/download`)
    .set('Cookie', authCookie)
    .set('Authorization', `Bearer ${accessToken}`)
    .expect(400);

  // Restore storage buffer
  memoryStorage._setRawBuffer(getBucketName(), storageKey, rawCiphertextBuffer);

  // 8. Access control test: User B cannot access User A's file
  const userBEmail = 'bob.attacker@securevault.io';
  const passB = 'AttackerPass123!';
  await request(app)
    .post('/api/auth/register')
    .send({ email: userBEmail, password: passB })
    .expect(201);

  const loginResB = await request(app)
    .post('/api/auth/login')
    .send({ email: userBEmail, password: passB })
    .expect(200);

  const authCookieB = loginResB.headers['set-cookie'];
  const tokenB = loginResB.body.accessToken;

  await request(app)
    .get(`/api/files/${uploadedFile.id}`)
    .set('Cookie', authCookieB)
    .set('Authorization', `Bearer ${tokenB}`)
    .expect(403);

  await request(app)
    .get(`/api/files/${uploadedFile.id}/download`)
    .set('Cookie', authCookieB)
    .set('Authorization', `Bearer ${tokenB}`)
    .expect(403);

  // 9. Disallowed executable file upload blocked
  await request(app)
    .post('/api/files/upload')
    .set('Cookie', authCookie)
    .set('Authorization', `Bearer ${accessToken}`)
    .attach('file', Buffer.from('echo malicious script'), { filename: 'exploit.sh', contentType: 'application/x-sh' })
    .expect(400);

  await request(app)
    .post('/api/files/upload')
    .set('Cookie', authCookie)
    .set('Authorization', `Bearer ${accessToken}`)
    .attach('file', Buffer.from('MZ binary executable payload'), { filename: 'malware.exe', contentType: 'application/octet-stream' })
    .expect(400);

  // 10. Checksum mismatch test: client sends incorrect expected checksum
  await request(app)
    .post('/api/files/upload')
    .set('Cookie', authCookie)
    .set('Authorization', `Bearer ${accessToken}`)
    .set('X-Checksum-SHA256', '0000000000000000000000000000000000000000000000000000000000000000')
    .attach('file', Buffer.from('legitimate data'), { filename: 'safe_document.txt', contentType: 'text/plain' })
    .expect(400);

  // 11. Delete file
  await request(app)
    .delete(`/api/files/${uploadedFile.id}`)
    .set('Cookie', authCookie)
    .set('Authorization', `Bearer ${accessToken}`)
    .expect(200);

  // File record and storage object are gone
  await request(app)
    .get(`/api/files/${uploadedFile.id}`)
    .set('Cookie', authCookie)
    .set('Authorization', `Bearer ${accessToken}`)
    .expect(404);

  assert.equal(memoryStorage._getRawBuffer(getBucketName(), storageKey), undefined);

  resetStorageClient();
  closeDatabase();
});

test('Files Security: enforces upload size limits, filename sanitization, and auth protection', async () => {
  closeDatabase();
  initDatabase(':memory:');
  const memoryStorage = new MemoryStorageClient();
  setStorageClient(memoryStorage);

  // Set tight file limit (100 bytes) for this test
  process.env.MAX_FILE_SIZE_BYTES = '100';

  const app = createApp({ enableRateLimit: false });

  // 1. Unauthenticated upload fails with 401
  await request(app)
    .post('/api/files/upload')
    .attach('file', Buffer.from('hello'), 'test.txt')
    .expect(401);

  // Register user
  const user = 'dave@securevault.io';
  const pass = 'DavePassword123!';
  await request(app).post('/api/auth/register').send({ email: user, password: pass }).expect(201);
  const loginRes = await request(app).post('/api/auth/login').send({ email: user, password: pass }).expect(200);
  const token = loginRes.body.accessToken;

  // 2. Upload exceeding MAX_FILE_SIZE_BYTES (150 bytes > 100 bytes limit)
  const oversizedPayload = Buffer.alloc(150, 'Z');
  const sizeRes = await request(app)
    .post('/api/files/upload')
    .set('Authorization', `Bearer ${token}`)
    .attach('file', oversizedPayload, 'large.dat')
    .expect(413);

  assert.match(sizeRes.body.error, /exceeds maximum allowed limit/i);

  // 3. Filename path traversal sanitization
  const normalPayload = Buffer.from('Safe content under 100 bytes');
  const traversalRes = await request(app)
    .post('/api/files/upload')
    .set('Authorization', `Bearer ${token}`)
    .attach('file', normalPayload, '../../../../etc/shadow.txt')
    .expect(201);

  assert.equal(traversalRes.body.file.filename, 'shadow.txt', 'Path traversal characters must be stripped');

  // 4. Missing file in multipart body
  await request(app)
    .post('/api/files/upload')
    .set('Authorization', `Bearer ${token}`)
    .field('dummyField', 'no file attached')
    .expect(400);

  // Clean up env
  delete process.env.MAX_FILE_SIZE_BYTES;
  resetStorageClient();
  closeDatabase();
});

