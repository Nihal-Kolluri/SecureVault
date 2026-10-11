const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// Default fallback secret for development/tests only (never used with real secrets)
const JWT_SECRET = process.env.JWT_SECRET || 'securevault_dev_jwt_secret_key_minimum_32_bytes_long!!';
const ACCESS_TOKEN_EXPIRATION_SECONDS = 15 * 60; // Exactly 15 minutes (900 seconds)
const REFRESH_TOKEN_EXPIRATION_DAYS = 7;

/**
 * Generates a short-lived 15-minute access JWT.
 * @param {{ id: string, email: string }} user
 * @returns {string} Signed JWT
 */
function generateAccessToken(user) {
  const payload = {
    sub: user.id,
    email: user.email,
    role: user.role || 'user',
    jti: crypto.randomUUID()
  };

  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: ACCESS_TOKEN_EXPIRATION_SECONDS
  });
}

/**
 * Verifies and decodes an access JWT.
 * @param {string} token
 * @returns {object} Decoded JWT payload
 */
function verifyAccessToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

/**
 * Generates a secure, high-entropy random refresh token.
 * @returns {string} 64-character hex string
 */
function generateRefreshToken() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Computes a SHA-256 hash of a token for secure database storage.
 * @param {string} token
 * @returns {string} SHA-256 hex digest
 */
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/**
 * Computes expiration timestamp for a new refresh token.
 * @returns {string} ISO-8601 string
 */
function getRefreshTokenExpiresAt() {
  const expires = new Date();
  expires.setDate(expires.getDate() + REFRESH_TOKEN_EXPIRATION_DAYS);
  return expires.toISOString();
}

module.exports = {
  ACCESS_TOKEN_EXPIRATION_SECONDS,
  generateAccessToken,
  verifyAccessToken,
  generateRefreshToken,
  hashToken,
  getRefreshTokenExpiresAt
};
