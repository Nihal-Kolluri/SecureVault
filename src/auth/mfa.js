const crypto = require('crypto');
const { generateSecret, generateURI, verify, generate } = require('otplib');
const qrcode = require('qrcode');
const jwt = require('jsonwebtoken');
const { getDatabase } = require('../db/database');
const { hashToken } = require('./tokens');

const MAX_MFA_FAILURES = 5;
const MFA_LOCKOUT_WINDOW_MINUTES = 15;
const MFA_PENDING_TOKEN_LIFETIME_SECONDS = 5 * 60; // 5 minutes

const JWT_SECRET = process.env.JWT_SECRET || 'securevault_dev_jwt_secret_key_minimum_32_bytes_long!!';

/**
 * Generates TOTP secret and QR code data URL for enrollment.
 * @param {string} email
 * @returns {Promise<{ secret: string, otpAuthUrl: string, qrCodeDataUrl: string }>}
 */
async function generateTotpEnrollment(email) {
  const secret = generateSecret();
  const otpAuthUrl = generateURI({
    secret,
    label: email,
    issuer: 'SecureVault'
  });

  const qrCodeDataUrl = await qrcode.toDataURL(otpAuthUrl, {
    margin: 2,
    width: 240,
    color: {
      dark: '#04101e',
      light: '#ffffff'
    }
  });

  return {
    secret,
    otpAuthUrl,
    qrCodeDataUrl
  };
}

/**
 * Generates an array of plaintext emergency recovery codes (e.g., 8 codes).
 * Format: XXXX-XXXX (alphanumeric uppercase)
 * @param {number} [count=8]
 * @returns {string[]}
 */
function generateRecoveryCodes(count = 8) {
  const codes = [];
  const chars = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
  for (let i = 0; i < count; i++) {
    const bytes = crypto.randomBytes(8);
    let part1 = '';
    let part2 = '';
    for (let j = 0; j < 4; j++) {
      part1 += chars[bytes[j] % chars.length];
      part2 += chars[bytes[j + 4] % chars.length];
    }
    codes.push(`${part1}-${part2}`);
  }
  return codes;
}

/**
 * Gets count of recent failed MFA attempts for a user within the lockout window.
 * @param {string} userId
 * @param {number} [windowMinutes=15]
 * @returns {number}
 */
function getRecentMfaFailures(userId, windowMinutes = MFA_LOCKOUT_WINDOW_MINUTES) {
  const db = getDatabase();
  const windowStart = new Date(Date.now() - windowMinutes * 60 * 1000).toISOString();

  // Find last successful MFA attempt if any
  const lastSuccess = db.prepare(`
    SELECT attempted_at FROM mfa_attempts
    WHERE user_id = ? AND success = 1 AND attempted_at >= ?
    ORDER BY attempted_at DESC LIMIT 1
  `).get(userId, windowStart);

  const afterTime = lastSuccess ? lastSuccess.attempted_at : windowStart;

  const row = db.prepare(`
    SELECT COUNT(*) as failedCount FROM mfa_attempts
    WHERE user_id = ? AND success = 0 AND attempted_at >= ?
  `).get(userId, afterTime);

  return row ? row.failedCount : 0;
}

/**
 * Records an MFA verification attempt.
 * @param {string} userId
 * @param {boolean} success
 */
function recordMfaAttempt(userId, success) {
  const db = getDatabase();
  db.prepare(`
    INSERT INTO mfa_attempts (id, user_id, attempted_at, success)
    VALUES (?, ?, ?, ?)
  `).run(
    crypto.randomUUID(),
    userId,
    new Date().toISOString(),
    success ? 1 : 0
  );
}

/**
 * Verifies a 6-digit TOTP code against a secret.
 * @param {string} secret
 * @param {string} token
 * @returns {Promise<boolean>}
 */
async function verifyTotpCode(secret, token) {
  if (!secret || !token) return false;
  const sanitized = String(token).replace(/[\s-]/g, '').trim();
  if (!/^\d{6}$/.test(sanitized)) return false;

  try {
    const result = await verify({
      token: sanitized,
      secret,
      epochWindow: 1
    });
    return !!(result && result.valid);
  } catch {
    return false;
  }
}

/**
 * Verifies an emergency recovery code against hashed codes in the database.
 * If valid and unused, marks it as consumed and returns true.
 * @param {string} userId
 * @param {string} rawCode
 * @returns {boolean}
 */
function verifyAndConsumeRecoveryCode(userId, rawCode) {
  if (!rawCode || typeof rawCode !== 'string') return false;
  const normalized = rawCode.replace(/[\s]/g, '').toUpperCase().trim();
  const codeHash = hashToken(normalized);

  const db = getDatabase();
  const row = db.prepare(`
    SELECT id FROM recovery_codes
    WHERE user_id = ? AND code_hash = ? AND used_at IS NULL
  `).get(userId, codeHash);

  if (!row) {
    return false;
  }

  // Consume code
  const now = new Date().toISOString();
  db.prepare('UPDATE recovery_codes SET used_at = ? WHERE id = ?').run(now, row.id);
  return true;
}

/**
 * Generates a short-lived MFA pending token for intermediate 2-step login.
 * @param {{ id: string, email: string }} user
 * @returns {string}
 */
function generateMfaPendingToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      email: user.email,
      type: 'mfa_pending',
      jti: crypto.randomUUID()
    },
    JWT_SECRET,
    { expiresIn: MFA_PENDING_TOKEN_LIFETIME_SECONDS }
  );
}

/**
 * Verifies the short-lived MFA pending token.
 * @param {string} mfaToken
 * @returns {{ id: string, email: string }}
 */
function verifyMfaPendingToken(mfaToken) {
  if (!mfaToken) {
    const error = new Error('MFA session token is required.');
    error.statusCode = 401;
    throw error;
  }

  try {
    const payload = jwt.verify(mfaToken, JWT_SECRET);
    if (payload.type !== 'mfa_pending') {
      const error = new Error('Invalid MFA session token.');
      error.statusCode = 401;
      throw error;
    }
    return {
      id: payload.sub,
      email: payload.email
    };
  } catch {
    const error = new Error('MFA session expired. Please sign in again.');
    error.statusCode = 401;
    throw error;
  }
}

/**
 * Generates an encrypted/signed setup token containing the pending secret and recovery code hashes.
 * @param {string} userId
 * @param {string} secret
 * @param {string[]} recoveryCodes
 * @returns {string}
 */
function generateMfaSetupToken(userId, secret, recoveryCodes) {
  const codeHashes = recoveryCodes.map((c) => hashToken(c.replace(/[\s]/g, '').toUpperCase().trim()));
  return jwt.sign(
    {
      sub: userId,
      secret,
      codeHashes,
      type: 'mfa_setup'
    },
    JWT_SECRET,
    { expiresIn: 10 * 60 } // 10 minutes to complete setup
  );
}

/**
 * Confirms MFA enrollment after user enters their first valid TOTP code.
 * @param {string} userId
 * @param {string} setupToken
 * @param {string} code
 * @returns {Promise<{ success: boolean }>}
 */
async function confirmMfaEnrollment(userId, setupToken, code) {
  if (!setupToken || !code) {
    const error = new Error('Setup token and confirmation code are required.');
    error.statusCode = 400;
    throw error;
  }

  let payload;
  try {
    payload = jwt.verify(setupToken, JWT_SECRET);
    if (payload.type !== 'mfa_setup' || payload.sub !== userId) {
      throw new Error('Invalid setup token.');
    }
  } catch {
    const error = new Error('MFA setup session expired or invalid. Please try again.');
    error.statusCode = 400;
    throw error;
  }

  const isValid = await verifyTotpCode(payload.secret, code);
  if (!isValid) {
    const error = new Error('Invalid verification code. Please check your authenticator app.');
    error.statusCode = 400;
    throw error;
  }

  const db = getDatabase();
  const now = new Date().toISOString();

  // 1. Enable MFA on user record
  db.prepare(`
    UPDATE users 
    SET mfa_enabled = 1, mfa_secret = ?, updated_at = ?
    WHERE id = ?
  `).run(payload.secret, now, userId);

  // 2. Remove any prior recovery codes for this user
  db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(userId);

  // 3. Save hashed recovery codes
  const insertCodeStmt = db.prepare(`
    INSERT INTO recovery_codes (id, user_id, code_hash, used_at, created_at)
    VALUES (?, ?, ?, NULL, ?)
  `);

  for (const hash of payload.codeHashes) {
    insertCodeStmt.run(crypto.randomUUID(), userId, hash, now);
  }

  return { success: true };
}

/**
 * Disables MFA for a user account.
 * @param {string} userId
 */
function disableMfa(userId) {
  const db = getDatabase();
  const now = new Date().toISOString();

  db.prepare(`
    UPDATE users 
    SET mfa_enabled = 0, mfa_secret = NULL, updated_at = ?
    WHERE id = ?
  `).run(now, userId);

  db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(userId);
  return { success: true };
}

/**
 * Counts remaining unused recovery codes for a user.
 * @param {string} userId
 * @returns {number}
 */
function getRemainingRecoveryCodesCount(userId) {
  const db = getDatabase();
  const row = db.prepare(`
    SELECT COUNT(*) as count FROM recovery_codes
    WHERE user_id = ? AND used_at IS NULL
  `).get(userId);
  return row ? row.count : 0;
}

module.exports = {
  MAX_MFA_FAILURES,
  MFA_LOCKOUT_WINDOW_MINUTES,
  generateTotpEnrollment,
  generateRecoveryCodes,
  getRecentMfaFailures,
  recordMfaAttempt,
  verifyTotpCode,
  verifyAndConsumeRecoveryCode,
  generateMfaPendingToken,
  verifyMfaPendingToken,
  generateMfaSetupToken,
  confirmMfaEnrollment,
  disableMfa,
  getRemainingRecoveryCodesCount,
  generateTotpCode: generate // Exported for testing
};
