const crypto = require('crypto');
const { getDatabase } = require('../db/database');
const {
  validatePasswordStrength,
  hashPassword,
  verifyPassword,
  dummyVerify
} = require('./hash');
const {
  generateAccessToken,
  generateRefreshToken,
  hashToken,
  getRefreshTokenExpiresAt
} = require('./tokens');
const {
  generateMfaPendingToken,
  verifyMfaPendingToken,
  getRecentMfaFailures,
  recordMfaAttempt,
  verifyTotpCode,
  verifyAndConsumeRecoveryCode,
  MAX_MFA_FAILURES
} = require('./mfa');

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_WINDOW_MINUTES = 15;

/**
 * Validates basic email structure.
 * @param {string} email
 * @returns {boolean}
 */
function isValidEmail(email) {
  if (typeof email !== 'string') return false;
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email.trim()) && email.length <= 254;
}

/**
 * Calculates recent consecutive failed login attempts for an email within the lockout window.
 * @param {string} email
 * @param {number} [windowMinutes=15]
 * @returns {number}
 */
function getRecentFailedAttempts(email, windowMinutes = LOCKOUT_WINDOW_MINUTES) {
  const db = getDatabase();
  const windowStart = new Date(Date.now() - windowMinutes * 60 * 1000).toISOString();

  // Find the timestamp of the most recent successful login within the window, if any
  const lastSuccess = db.prepare(`
    SELECT attempted_at FROM login_attempts 
    WHERE email = ? AND success = 1 AND attempted_at >= ?
    ORDER BY attempted_at DESC LIMIT 1
  `).get(email.toLowerCase(), windowStart);

  const afterTime = lastSuccess ? lastSuccess.attempted_at : windowStart;

  const row = db.prepare(`
    SELECT COUNT(*) as failedCount FROM login_attempts
    WHERE email = ? AND success = 0 AND attempted_at >= ?
  `).get(email.toLowerCase(), afterTime);

  return row ? row.failedCount : 0;
}

/**
 * Records a login attempt.
 * @param {string} email
 * @param {boolean} success
 * @param {string|null} ipAddress
 */
function recordLoginAttempt(email, success, ipAddress = null) {
  const db = getDatabase();
  const stmt = db.prepare(`
    INSERT INTO login_attempts (id, email, ip_address, attempted_at, success)
    VALUES (?, ?, ?, ?, ?)
  `);
  stmt.run(
    crypto.randomUUID(),
    email.toLowerCase().trim(),
    ipAddress || null,
    new Date().toISOString(),
    success ? 1 : 0
  );
}

/**
 * Registers a new user with Argon2id password hashing.
 * @param {object} params
 * @param {string} params.email
 * @param {string} params.password
 * @returns {Promise<{ id: string, email: string, createdAt: string }>}
 */
async function registerUser({ email, password }) {
  if (!isValidEmail(email)) {
    const error = new Error('Invalid email address format.');
    error.statusCode = 400;
    throw error;
  }

  const strength = validatePasswordStrength(password);
  if (!strength.valid) {
    const error = new Error(strength.message || 'Password does not meet complexity requirements.');
    error.statusCode = 400;
    throw error;
  }

  const normalizedEmail = email.toLowerCase().trim();
  const db = getDatabase();

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(normalizedEmail);
  if (existing) {
    const error = new Error('An account with this email already exists.');
    error.statusCode = 409;
    throw error;
  }

  const passwordHash = await hashPassword(password);
  const now = new Date().toISOString();
  const userId = crypto.randomUUID();

  db.prepare(`
    INSERT INTO users (id, email, password_hash, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(userId, normalizedEmail, passwordHash, now, now);

  return {
    id: userId,
    email: normalizedEmail,
    createdAt: now
  };
}

/**
 * Authenticates user credentials, tracks login attempts, enforces generic auth errors,
 * and creates a session with access and rotating refresh tokens.
 * @param {object} params
 * @param {string} params.email
 * @param {string} params.password
 * @param {string} [params.ipAddress]
 * @param {string} [params.userAgent]
 * @returns {Promise<{ accessToken: string, refreshToken: string, user: { id: string, email: string } }>}
 */
async function loginUser({ email, password, ipAddress = null, userAgent = null }) {
  const normalizedEmail = (email || '').toLowerCase().trim();

  // Check login attempts / rate-limit lockout
  const failedAttempts = getRecentFailedAttempts(normalizedEmail);
  if (failedAttempts >= MAX_FAILED_ATTEMPTS) {
    recordLoginAttempt(normalizedEmail, false, ipAddress);
    const error = new Error('Too many failed login attempts. Please try again later.');
    error.statusCode = 429;
    throw error;
  }

  const db = getDatabase();
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(normalizedEmail);

  if (!user) {
    // Timing attack mitigation: compute dummy verify
    await dummyVerify(password || '');
    recordLoginAttempt(normalizedEmail, false, ipAddress);
    const error = new Error('Invalid email or password.');
    error.statusCode = 401;
    throw error;
  }

  const isValidPassword = await verifyPassword(user.password_hash, password || '');
  if (!isValidPassword) {
    recordLoginAttempt(normalizedEmail, false, ipAddress);
    const error = new Error('Invalid email or password.');
    error.statusCode = 401;
    throw error;
  }

  // Record successful password authentication
  recordLoginAttempt(normalizedEmail, true, ipAddress);

  // If user has 2FA / MFA enabled, require MFA step
  if (user.mfa_enabled === 1) {
    const mfaToken = generateMfaPendingToken({ id: user.id, email: user.email });
    return {
      mfaRequired: true,
      mfaToken,
      user: {
        id: user.id,
        email: user.email
      }
    };
  }

  // Generate tokens & session
  const sessionId = crypto.randomUUID();
  const refreshToken = generateRefreshToken();
  const tokenHash = hashToken(refreshToken);
  const expiresAt = getRefreshTokenExpiresAt();
  const now = new Date().toISOString();

  db.prepare(`
    INSERT INTO sessions (id, user_id, refresh_token_hash, user_agent, ip_address, expires_at, created_at, last_used_at, is_revoked)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
  `).run(sessionId, user.id, tokenHash, userAgent, ipAddress, expiresAt, now, now);

  const accessToken = generateAccessToken({ id: user.id, email: user.email });

  return {
    mfaRequired: false,
    accessToken,
    refreshToken,
    user: {
      id: user.id,
      email: user.email
    }
  };
}

/**
 * Completes MFA authentication step for users with 2FA enabled.
 * Enforces MFA attempt limits and supports both TOTP and recovery codes.
 * @param {object} params
 * @param {string} params.mfaToken
 * @param {string} [params.code]
 * @param {string} [params.recoveryCode]
 * @param {string} [params.ipAddress]
 * @param {string} [params.userAgent]
 * @returns {Promise<{ accessToken: string, refreshToken: string, user: { id: string, email: string } }>}
 */
async function verifyMfaLogin({ mfaToken, code, recoveryCode, ipAddress = null, userAgent = null }) {
  const pendingUser = verifyMfaPendingToken(mfaToken);

  // Check MFA attempt limits
  const failures = getRecentMfaFailures(pendingUser.id);
  if (failures >= MAX_MFA_FAILURES) {
    recordMfaAttempt(pendingUser.id, false);
    const error = new Error('Too many failed MFA attempts. Please try again later.');
    error.statusCode = 429;
    throw error;
  }

  const db = getDatabase();
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(pendingUser.id);
  if (!user || user.mfa_enabled !== 1) {
    const error = new Error('Invalid MFA state.');
    error.statusCode = 400;
    throw error;
  }

  let verified = false;

  if (recoveryCode) {
    // Attempt recovery code verification
    verified = verifyAndConsumeRecoveryCode(user.id, recoveryCode);
  } else if (code) {
    // Attempt TOTP code verification
    verified = await verifyTotpCode(user.mfa_secret, code);
  }

  if (!verified) {
    recordMfaAttempt(user.id, false);
    const error = new Error('Invalid authentication code.');
    error.statusCode = 401;
    throw error;
  }

  // Record successful MFA verification
  recordMfaAttempt(user.id, true);

  // Issue full session & tokens
  const sessionId = crypto.randomUUID();
  const refreshToken = generateRefreshToken();
  const tokenHash = hashToken(refreshToken);
  const expiresAt = getRefreshTokenExpiresAt();
  const now = new Date().toISOString();

  db.prepare(`
    INSERT INTO sessions (id, user_id, refresh_token_hash, user_agent, ip_address, expires_at, created_at, last_used_at, is_revoked)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
  `).run(sessionId, user.id, tokenHash, userAgent, ipAddress, expiresAt, now, now);

  const accessToken = generateAccessToken({ id: user.id, email: user.email });

  return {
    accessToken,
    refreshToken,
    user: {
      id: user.id,
      email: user.email,
      mfaEnabled: true
    }
  };
}

/**
 * Rotates refresh token and issues a new access token.
 * Detects refresh token reuse and revokes compromised sessions immediately.
 * @param {object} params
 * @param {string} params.refreshToken
 * @param {string} [params.ipAddress]
 * @param {string} [params.userAgent]
 * @returns {Promise<{ accessToken: string, refreshToken: string }>}
 */
async function refreshSession({ refreshToken, ipAddress = null, userAgent = null }) {
  if (!refreshToken || typeof refreshToken !== 'string') {
    const error = new Error('Refresh token is required.');
    error.statusCode = 401;
    throw error;
  }

  const tokenHash = hashToken(refreshToken);
  const db = getDatabase();

  // 1. REUSE DETECTION: Check if token has already been consumed
  const consumed = db.prepare('SELECT session_id FROM consumed_tokens WHERE token_hash = ?').get(tokenHash);
  if (consumed) {
    // CRITICAL: Token reuse detected! Revoke the whole compromised session family immediately
    db.prepare('UPDATE sessions SET is_revoked = 1 WHERE id = ?').run(consumed.session_id);
    const error = new Error('Invalid or compromised session. Please sign in again.');
    error.statusCode = 401;
    error.code = 'TOKEN_REUSE_DETECTED';
    throw error;
  }

  // 2. Locate active session by current refresh_token_hash
  const session = db.prepare('SELECT * FROM sessions WHERE refresh_token_hash = ?').get(tokenHash);
  if (!session) {
    const error = new Error('Invalid or expired session.');
    error.statusCode = 401;
    throw error;
  }

  if (session.is_revoked === 1) {
    const error = new Error('Session has been revoked.');
    error.statusCode = 401;
    throw error;
  }

  if (new Date(session.expires_at) < new Date()) {
    db.prepare('UPDATE sessions SET is_revoked = 1 WHERE id = ?').run(session.id);
    const error = new Error('Session has expired.');
    error.statusCode = 401;
    throw error;
  }

  const user = db.prepare('SELECT id, email FROM users WHERE id = ?').get(session.user_id);
  if (!user) {
    const error = new Error('User no longer exists.');
    error.statusCode = 401;
    throw error;
  }

  // 3. Token Rotation
  // Add old token to consumed_tokens list
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO consumed_tokens (id, session_id, token_hash, consumed_at)
    VALUES (?, ?, ?, ?)
  `).run(crypto.randomUUID(), session.id, tokenHash, now);

  // Generate new refresh token and new expiration
  const newRefreshToken = generateRefreshToken();
  const newHash = hashToken(newRefreshToken);
  const newExpiresAt = getRefreshTokenExpiresAt();

  db.prepare(`
    UPDATE sessions 
    SET refresh_token_hash = ?, last_used_at = ?, expires_at = ?, ip_address = COALESCE(?, ip_address), user_agent = COALESCE(?, user_agent)
    WHERE id = ?
  `).run(newHash, now, newExpiresAt, ipAddress, userAgent, session.id);

  const accessToken = generateAccessToken(user);

  return {
    accessToken,
    refreshToken: newRefreshToken
  };
}

/**
 * Logs out the session by revoking the refresh token.
 * @param {string} refreshToken
 * @returns {Promise<{ success: boolean }>}
 */
async function logoutSession(refreshToken) {
  if (!refreshToken || typeof refreshToken !== 'string') {
    return { success: true };
  }

  const tokenHash = hashToken(refreshToken);
  const db = getDatabase();

  db.prepare('UPDATE sessions SET is_revoked = 1 WHERE refresh_token_hash = ?').run(tokenHash);

  return { success: true };
}

/**
 * Retrieves a user by their ID.
 * @param {string} userId
 * @returns {object|null}
 */
function getUserById(userId) {
  const db = getDatabase();
  const row = db.prepare('SELECT id, email, mfa_enabled, created_at FROM users WHERE id = ?').get(userId);
  if (!row) return null;
  return {
    id: row.id,
    email: row.email,
    mfaEnabled: Boolean(row.mfa_enabled),
    created_at: row.created_at
  };
}

module.exports = {
  MAX_FAILED_ATTEMPTS,
  LOCKOUT_WINDOW_MINUTES,
  isValidEmail,
  getRecentFailedAttempts,
  registerUser,
  loginUser,
  verifyMfaLogin,
  refreshSession,
  logoutSession,
  getUserById
};
