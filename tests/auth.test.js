const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { initDatabase, closeDatabase, getDatabase } = require('../src/db/database');
const { createApp } = require('../src/app');
const {
  validatePasswordStrength,
  hashPassword,
  verifyPassword,
  dummyVerify
} = require('../src/auth/hash');
const {
  generateAccessToken,
  verifyAccessToken,
  generateRefreshToken,
  hashToken,
  ACCESS_TOKEN_EXPIRATION_SECONDS
} = require('../src/auth/tokens');
const {
  registerUser,
  loginUser,
  refreshSession,
  logoutSession,
  getRecentFailedAttempts,
  MAX_FAILED_ATTEMPTS
} = require('../src/auth/service');

// Setup in-memory database before running tests
test.beforeEach(() => {
  closeDatabase();
  initDatabase(':memory:');
});

test.afterEach(() => {
  closeDatabase();
});

/* -------------------------------------------------------------------------- */
/*                        1. Argon2id & Password Security                     */
/* -------------------------------------------------------------------------- */

test('Argon2id: hashes and verifies password correctly', async () => {
  const plain = 'VaultMaster2026!#';
  const hashed = await hashPassword(plain);

  assert.ok(hashed.startsWith('$argon2id$'), 'Hash must use the argon2id algorithm');
  assert.equal(await verifyPassword(hashed, plain), true);
  assert.equal(await verifyPassword(hashed, 'WrongPassword123!'), false);
});

test('Argon2id: dummy verify executes safely and returns false', async () => {
  const result = await dummyVerify('anypassword');
  assert.equal(result, false);
});

test('Password complexity: validates password requirements strictly', () => {
  // Too short
  assert.equal(validatePasswordStrength('Short1!').valid, false);
  // Missing uppercase
  assert.equal(validatePasswordStrength('lowercase123!').valid, false);
  // Missing lowercase
  assert.equal(validatePasswordStrength('UPPERCASE123!').valid, false);
  // Missing digit
  assert.equal(validatePasswordStrength('NoDigitsHere!').valid, false);
  // Missing symbol
  assert.equal(validatePasswordStrength('NoSymbols1234').valid, false);
  // Valid
  assert.equal(validatePasswordStrength('StrongP@ssw0rd!').valid, true);
});

/* -------------------------------------------------------------------------- */
/*                        2. Token Generation & Expiration                    */
/* -------------------------------------------------------------------------- */

test('JWT: issues 15-minute access token', () => {
  const user = { id: 'test-user-uuid', email: 'test@securevault.io' };
  const token = generateAccessToken(user);
  const payload = verifyAccessToken(token);

  assert.equal(payload.sub, user.id);
  assert.equal(payload.email, user.email);
  assert.ok(payload.jti, 'JWT must contain unique jti');

  const lifetime = payload.exp - payload.iat;
  assert.equal(lifetime, ACCESS_TOKEN_EXPIRATION_SECONDS);
  assert.equal(lifetime, 15 * 60, 'Access token must expire in exactly 15 minutes');
});

test('Refresh token: generates high-entropy random string and hashes with SHA-256', () => {
  const token = generateRefreshToken();
  assert.equal(token.length, 64, 'Hex token of 32 random bytes must be 64 characters');

  const hashed = hashToken(token);
  assert.equal(hashed.length, 64, 'SHA-256 digest must be 64 characters');
  assert.notEqual(hashed, token, 'Token hash must differ from plaintext token');
});

/* -------------------------------------------------------------------------- */
/*                        3. Auth Service & Generic Errors                    */
/* -------------------------------------------------------------------------- */

test('Auth Service: user registration succeeds with valid data', async () => {
  const user = await registerUser({
    email: 'alice@securevault.io',
    password: 'SuperSecurePassword123!'
  });

  assert.ok(user.id);
  assert.equal(user.email, 'alice@securevault.io');

  // Verify hash in DB is argon2id
  const db = getDatabase();
  const row = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(user.id);
  assert.ok(row.password_hash.startsWith('$argon2id$'));
});

test('Auth Service: registration rejects duplicate email', async () => {
  await registerUser({
    email: 'alice@securevault.io',
    password: 'SuperSecurePassword123!'
  });

  await assert.rejects(
    async () => {
      await registerUser({
        email: 'alice@securevault.io',
        password: 'AnotherPassword456!'
      });
    },
    (err) => err.statusCode === 409
  );
});

test('Auth Service: login produces generic error for non-existent user and wrong password', async () => {
  await registerUser({
    email: 'bob@securevault.io',
    password: 'BobSecurePassword123!'
  });

  // 1. Non-existent user
  await assert.rejects(
    async () => {
      await loginUser({
        email: 'nonexistent@securevault.io',
        password: 'BobSecurePassword123!'
      });
    },
    (err) => {
      assert.equal(err.statusCode, 401);
      assert.equal(err.message, 'Invalid email or password.');
      return true;
    }
  );

  // 2. Wrong password for existing user
  await assert.rejects(
    async () => {
      await loginUser({
        email: 'bob@securevault.io',
        password: 'IncorrectPassword999!'
      });
    },
    (err) => {
      assert.equal(err.statusCode, 401);
      assert.equal(err.message, 'Invalid email or password.');
      return true;
    }
  );
});

/* -------------------------------------------------------------------------- */
/*                        4. login_attempts & Lockout Policy                  */
/* -------------------------------------------------------------------------- */

test('Login attempts: tracks failed attempts and enforces lockout', async () => {
  const email = 'lockout.target@securevault.io';
  await registerUser({ email, password: 'TargetPassword123!' });

  // 4 failed attempts: not yet locked out
  for (let i = 0; i < MAX_FAILED_ATTEMPTS - 1; i++) {
    await assert.rejects(async () => {
      await loginUser({ email, password: 'WrongPassword!' });
    });
  }
  assert.equal(getRecentFailedAttempts(email), MAX_FAILED_ATTEMPTS - 1);

  // 5th failed attempt: reaches threshold
  await assert.rejects(async () => {
    await loginUser({ email, password: 'WrongPassword!' });
  });
  assert.equal(getRecentFailedAttempts(email), MAX_FAILED_ATTEMPTS);

  // 6th attempt: triggers lockout (HTTP 429)
  await assert.rejects(
    async () => {
      await loginUser({ email, password: 'TargetPassword123!' });
    },
    (err) => {
      assert.equal(err.statusCode, 429);
      assert.match(err.message, /Too many failed login attempts/i);
      return true;
    }
  );
});

/* -------------------------------------------------------------------------- */
/*               5. Sessions Table, Token Rotation & Reuse Detection          */
/* -------------------------------------------------------------------------- */

test('Sessions & Rotation: records session and rotates token cleanly', async () => {
  const email = 'rotation@securevault.io';
  await registerUser({ email, password: 'RotationPassword123!' });

  const loginRes = await loginUser({ email, password: 'RotationPassword123!' });
  assert.ok(loginRes.accessToken);
  assert.ok(loginRes.refreshToken);

  const db = getDatabase();
  const sessionRow = db.prepare('SELECT * FROM sessions WHERE user_id = ?').get(loginRes.user.id);
  assert.ok(sessionRow);
  assert.equal(sessionRow.is_revoked, 0);
  assert.equal(sessionRow.refresh_token_hash, hashToken(loginRes.refreshToken));

  // Perform rotation
  const refreshRes = await refreshSession({ refreshToken: loginRes.refreshToken });
  assert.ok(refreshRes.accessToken);
  assert.ok(refreshRes.refreshToken);
  assert.notEqual(refreshRes.refreshToken, loginRes.refreshToken, 'New refresh token must be issued');

  // Verify old token is recorded in consumed_tokens
  const consumed = db.prepare('SELECT * FROM consumed_tokens WHERE token_hash = ?').get(hashToken(loginRes.refreshToken));
  assert.ok(consumed, 'Old token must be marked as consumed');

  // Second legitimate rotation using the new token
  const refreshRes2 = await refreshSession({ refreshToken: refreshRes.refreshToken });
  assert.ok(refreshRes2.accessToken);
});

test('Reuse Detection: presenting a consumed refresh token revokes session', async () => {
  const email = 'reuse.target@securevault.io';
  await registerUser({ email, password: 'ReusePassword123!' });

  const loginRes = await loginUser({ email, password: 'ReusePassword123!' });
  const originalToken = loginRes.refreshToken;

  // Legitimate client rotates token
  const refreshRes = await refreshSession({ refreshToken: originalToken });
  assert.ok(refreshRes.refreshToken);

  // Attacker (or replay) presents the original token again!
  await assert.rejects(
    async () => {
      await refreshSession({ refreshToken: originalToken });
    },
    (err) => {
      assert.equal(err.statusCode, 401);
      assert.equal(err.code, 'TOKEN_REUSE_DETECTED');
      return true;
    }
  );

  // Verify that the entire session is now revoked in the database
  const db = getDatabase();
  const session = db.prepare('SELECT is_revoked FROM sessions WHERE user_id = ?').get(loginRes.user.id);
  assert.equal(session.is_revoked, 1, 'Compromised session family must be immediately revoked');

  // Even the legitimate token is now denied due to compromised session family
  await assert.rejects(
    async () => {
      await refreshSession({ refreshToken: refreshRes.refreshToken });
    },
    (err) => {
      assert.equal(err.statusCode, 401);
      return true;
    }
  );
});

test('Logout: revokes session in sessions table', async () => {
  const email = 'logout.user@securevault.io';
  await registerUser({ email, password: 'LogoutPassword123!' });
  const loginRes = await loginUser({ email, password: 'LogoutPassword123!' });

  await logoutSession(loginRes.refreshToken);

  const db = getDatabase();
  const session = db.prepare('SELECT is_revoked FROM sessions WHERE user_id = ?').get(loginRes.user.id);
  assert.equal(session.is_revoked, 1);

  // Subsequent refresh must fail
  await assert.rejects(
    async () => {
      await refreshSession({ refreshToken: loginRes.refreshToken });
    },
    (err) => err.statusCode === 401
  );
});

/* -------------------------------------------------------------------------- */
/*                           6. End-to-End API Routes                         */
/* -------------------------------------------------------------------------- */

test('E2E API: Register -> Login -> /me -> Refresh -> Logout', async () => {
  const app = createApp();

  // 1. Register
  const regRes = await request(app)
    .post('/api/auth/register')
    .send({
      email: 'e2e@securevault.io',
      password: 'E2ePassword123!'
    })
    .expect(201);

  assert.equal(regRes.body.user.email, 'e2e@securevault.io');

  // 2. Login
  const loginRes = await request(app)
    .post('/api/auth/login')
    .send({
      email: 'e2e@securevault.io',
      password: 'E2ePassword123!'
    })
    .expect(200);

  const { accessToken, refreshToken } = loginRes.body;
  assert.ok(accessToken);
  assert.ok(refreshToken);

  // 3. Access Protected Route (/api/auth/me) with 15-minute JWT
  const meRes = await request(app)
    .get('/api/auth/me')
    .set('Authorization', `Bearer ${accessToken}`)
    .expect(200);

  assert.equal(meRes.body.user.email, 'e2e@securevault.io');

  // 4. Unauthorized request without token
  await request(app)
    .get('/api/auth/me')
    .expect(401);

  // 5. Rotate refresh token via API
  const refreshRes = await request(app)
    .post('/api/auth/refresh')
    .send({ refreshToken })
    .expect(200);

  const newAccessToken = refreshRes.body.accessToken;
  const newRefreshToken = refreshRes.body.refreshToken;
  assert.ok(newAccessToken);
  assert.ok(newRefreshToken);
  assert.notEqual(newRefreshToken, refreshToken);

  // 6. Test reuse attack via API
  const reuseRes = await request(app)
    .post('/api/auth/refresh')
    .send({ refreshToken }) // Sending previously consumed token
    .expect(401);

  assert.equal(reuseRes.body.code, 'TOKEN_REUSE_DETECTED');

  // 7. Logout
  await request(app)
    .post('/api/auth/logout')
    .send({ refreshToken: newRefreshToken })
    .expect(200);
});
