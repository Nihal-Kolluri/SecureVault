const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { initDatabase, closeDatabase, getDatabase } = require('../src/db/database');
const { createApp } = require('../src/app');
const {
  generateTotpEnrollment,
  generateRecoveryCodes,
  verifyTotpCode,
  generateTotpCode,
  verifyAndConsumeRecoveryCode,
  getRemainingRecoveryCodesCount,
  getRecentMfaFailures,
  recordMfaAttempt,
  MAX_MFA_FAILURES
} = require('../src/auth/mfa');
const { registerUser, loginUser, verifyMfaLogin } = require('../src/auth/service');

test.beforeEach(() => {
  closeDatabase();
  initDatabase(':memory:');
});

test.afterEach(() => {
  closeDatabase();
});

/* -------------------------------------------------------------------------- */
/*                         1. TOTP Primitives & QR Code                       */
/* -------------------------------------------------------------------------- */

test('MFA: generates TOTP enrollment secret, URI, and QR code data URL', async () => {
  const enrollment = await generateTotpEnrollment('test@securevault.io');

  assert.ok(enrollment.secret, 'Secret must be generated');
  assert.match(enrollment.otpAuthUrl, /^otpauth:\/\/totp\//, 'Must be valid otpauth URI');
  assert.match(enrollment.qrCodeDataUrl, /^data:image\/png;base64,/, 'QR code must be a valid base64 PNG data URL');
});

test('MFA: verifies 6-digit TOTP codes accurately', async () => {
  const enrollment = await generateTotpEnrollment('totp.user@securevault.io');
  const validCode = await generateTotpCode({ secret: enrollment.secret });

  assert.equal(await verifyTotpCode(enrollment.secret, validCode), true);
  assert.equal(await verifyTotpCode(enrollment.secret, '000000'), false);
  assert.equal(await verifyTotpCode(enrollment.secret, 'invalid'), false);
  assert.equal(await verifyTotpCode(enrollment.secret, ''), false);
});

/* -------------------------------------------------------------------------- */
/*                      2. Hashed Emergency Recovery Codes                    */
/* -------------------------------------------------------------------------- */

test('Recovery Codes: generates formatted codes and enforces one-time use', async () => {
  const user = await registerUser({
    email: 'recovery@securevault.io',
    password: 'RecoveryPassword123!'
  });

  const codes = generateRecoveryCodes(8);
  assert.equal(codes.length, 8);
  codes.forEach((code) => {
    assert.match(code, /^[2-9A-Z]{4}-[2-9A-Z]{4}$/, 'Recovery code must match XXXX-XXXX pattern');
  });

  // Setup MFA with these recovery codes
  const app = createApp();
  const loginRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'recovery@securevault.io', password: 'RecoveryPassword123!' });

  const setupRes = await request(app)
    .post('/api/auth/mfa/setup')
    .set('Authorization', `Bearer ${loginRes.body.accessToken}`)
    .expect(200);

  const testCode = await generateTotpCode({ secret: setupRes.body.secret });
  await request(app)
    .post('/api/auth/mfa/confirm')
    .set('Authorization', `Bearer ${loginRes.body.accessToken}`)
    .send({ setupToken: setupRes.body.setupToken, code: testCode })
    .expect(200);

  assert.equal(getRemainingRecoveryCodesCount(user.id), 8);

  // Consume first recovery code
  const firstCode = setupRes.body.recoveryCodes[0];
  const validFirstUse = verifyAndConsumeRecoveryCode(user.id, firstCode);
  assert.equal(validFirstUse, true);
  assert.equal(getRemainingRecoveryCodesCount(user.id), 7);

  // Re-use of consumed recovery code must fail
  const secondUse = verifyAndConsumeRecoveryCode(user.id, firstCode);
  assert.equal(secondUse, false);
  assert.equal(getRemainingRecoveryCodesCount(user.id), 7);
});

/* -------------------------------------------------------------------------- */
/*                        3. MFA Attempt Limits & Lockout                     */
/* -------------------------------------------------------------------------- */

test('MFA Attempts: tracks failures and locks out after threshold', async () => {
  const user = await registerUser({
    email: 'mfa.lockout@securevault.io',
    password: 'MfaLockoutPass123!'
  });

  // Enable MFA
  const enrollment = await generateTotpEnrollment(user.email);
  const db = getDatabase();
  db.prepare('UPDATE users SET mfa_enabled = 1, mfa_secret = ? WHERE id = ?').run(enrollment.secret, user.id);

  // Initial login returns mfaToken
  const step1 = await loginUser({ email: user.email, password: 'MfaLockoutPass123!' });
  assert.equal(step1.mfaRequired, true);
  assert.ok(step1.mfaToken);

  // Fail 4 times: under limit
  for (let i = 0; i < MAX_MFA_FAILURES - 1; i++) {
    await assert.rejects(
      async () => {
        await verifyMfaLogin({ mfaToken: step1.mfaToken, code: '000000' });
      },
      (err) => err.statusCode === 401
    );
  }
  assert.equal(getRecentMfaFailures(user.id), MAX_MFA_FAILURES - 1);

  // 5th failure: hits limit
  await assert.rejects(
    async () => {
      await verifyMfaLogin({ mfaToken: step1.mfaToken, code: '000000' });
    },
    (err) => err.statusCode === 401
  );
  assert.equal(getRecentMfaFailures(user.id), MAX_MFA_FAILURES);

  // 6th attempt: triggers 429 lockout
  await assert.rejects(
    async () => {
      await verifyMfaLogin({ mfaToken: step1.mfaToken, code: '000000' });
    },
    (err) => {
      assert.equal(err.statusCode, 429);
      assert.match(err.message, /Too many failed MFA attempts/i);
      return true;
    }
  );
});

/* -------------------------------------------------------------------------- */
/*                     4. End-to-End 2-Step Authentication Flow               */
/* -------------------------------------------------------------------------- */

test('E2E MFA: Enroll -> Require 2-Step Login -> TOTP Verify -> Recovery Login -> Disable', async () => {
  const app = createApp();

  // 1. Register user
  await request(app)
    .post('/api/auth/register')
    .send({ email: 'fullmfa@securevault.io', password: 'FullMfaPassword123!' })
    .expect(201);

  // 2. Normal login before MFA
  const initialLogin = await request(app)
    .post('/api/auth/login')
    .send({ email: 'fullmfa@securevault.io', password: 'FullMfaPassword123!' })
    .expect(200);

  assert.equal(initialLogin.body.mfaRequired, false);
  const jwtToken = initialLogin.body.accessToken;

  // 3. Initiate MFA Setup
  const setupRes = await request(app)
    .post('/api/auth/mfa/setup')
    .set('Authorization', `Bearer ${jwtToken}`)
    .expect(200);

  assert.ok(setupRes.body.qrCode);
  assert.ok(setupRes.body.secret);
  assert.equal(setupRes.body.recoveryCodes.length, 8);

  // 4. Confirm MFA Setup
  const validTotp = await generateTotpCode({ secret: setupRes.body.secret });
  await request(app)
    .post('/api/auth/mfa/confirm')
    .set('Authorization', `Bearer ${jwtToken}`)
    .send({ setupToken: setupRes.body.setupToken, code: validTotp })
    .expect(200);

  // Verify status endpoint reports MFA enabled
  const statusRes = await request(app)
    .get('/api/auth/mfa/status')
    .set('Authorization', `Bearer ${jwtToken}`)
    .expect(200);
  assert.equal(statusRes.body.mfaEnabled, true);
  assert.equal(statusRes.body.remainingRecoveryCodes, 8);

  // 5. Subsequent Login requires MFA
  const mfaLoginStep1 = await request(app)
    .post('/api/auth/login')
    .send({ email: 'fullmfa@securevault.io', password: 'FullMfaPassword123!' })
    .expect(200);

  assert.equal(mfaLoginStep1.body.mfaRequired, true);
  assert.ok(mfaLoginStep1.body.mfaToken);
  assert.equal(mfaLoginStep1.body.accessToken, undefined, 'Access token must not be issued prior to MFA verification');

  // 6. Complete MFA login step with TOTP
  const nextTotp = await generateTotpCode({ secret: setupRes.body.secret });
  const mfaLoginStep2 = await request(app)
    .post('/api/auth/mfa/verify')
    .send({
      mfaToken: mfaLoginStep1.body.mfaToken,
      code: nextTotp
    })
    .expect(200);

  assert.ok(mfaLoginStep2.body.accessToken);
  assert.ok(mfaLoginStep2.body.refreshToken);
  assert.equal(mfaLoginStep2.body.user.mfaEnabled, true);

  // 7. Verify login using emergency recovery code
  const emergencyLoginStep1 = await request(app)
    .post('/api/auth/login')
    .send({ email: 'fullmfa@securevault.io', password: 'FullMfaPassword123!' })
    .expect(200);

  const recoveryCodeToUse = setupRes.body.recoveryCodes[1];
  const emergencyLoginStep2 = await request(app)
    .post('/api/auth/mfa/verify')
    .send({
      mfaToken: emergencyLoginStep1.body.mfaToken,
      recoveryCode: recoveryCodeToUse
    })
    .expect(200);

  assert.ok(emergencyLoginStep2.body.accessToken);

  // 8. Disable MFA
  await request(app)
    .post('/api/auth/mfa/disable')
    .set('Authorization', `Bearer ${emergencyLoginStep2.body.accessToken}`)
    .expect(200);

  // Subsequent login is now single-step
  const postDisableLogin = await request(app)
    .post('/api/auth/login')
    .send({ email: 'fullmfa@securevault.io', password: 'FullMfaPassword123!' })
    .expect(200);

  assert.equal(postDisableLogin.body.mfaRequired, false);
  assert.ok(postDisableLogin.body.accessToken);
});
