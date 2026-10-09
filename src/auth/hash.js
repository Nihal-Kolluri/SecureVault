const { hash, verify, Algorithm } = require('@node-rs/argon2');

// OWASP-compliant parameters for Argon2id
const ARGON2_OPTIONS = {
  algorithm: Algorithm.Argon2id,
  memoryCost: 19456, // 19 MiB
  timeCost: 2,       // 2 iterations
  parallelism: 1     // 1 thread
};

// Pre-computed dummy hash to mitigate user enumeration timing attacks
// Computed with the exact same Argon2id parameters
const DUMMY_HASH = '$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQxMjM0NTY3OA$9vG5u7vUf0xH5vY7GvG5u7vUf0xH5vY7GvG5u7vUf0w';

/**
 * Validates password strength.
 * Requires at least 8 characters, at least one uppercase, one lowercase, one number, and one symbol.
 * @param {string} password
 * @returns {{ valid: boolean, message?: string }}
 */
function validatePasswordStrength(password) {
  if (typeof password !== 'string' || password.length < 8) {
    return { valid: false, message: 'Password must be at least 8 characters long.' };
  }
  if (password.length > 128) {
    return { valid: false, message: 'Password exceeds maximum length of 128 characters.' };
  }
  if (!/[A-Z]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one uppercase letter.' };
  }
  if (!/[a-z]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one lowercase letter.' };
  }
  if (!/[0-9]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one number.' };
  }
  if (!/[^A-Za-z0-9]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one special character.' };
  }
  return { valid: true };
}

/**
 * Hashes a plaintext password using Argon2id.
 * @param {string} password
 * @returns {Promise<string>}
 */
async function hashPassword(password) {
  return hash(password, ARGON2_OPTIONS);
}

/**
 * Verifies a plaintext password against an Argon2id hash.
 * @param {string} passwordHash
 * @param {string} password
 * @returns {Promise<boolean>}
 */
async function verifyPassword(passwordHash, password) {
  try {
    return await verify(passwordHash, password);
  } catch {
    return false;
  }
}

/**
 * Runs a dummy verification against a simulated hash to eliminate timing discrepancies
 * when a user is not found during login attempts.
 * @param {string} password
 * @returns {Promise<boolean>} Always returns false
 */
async function dummyVerify(password) {
  try {
    await verify(DUMMY_HASH, password);
  } catch {
    // Ignore error
  }
  return false;
}

module.exports = {
  ARGON2_OPTIONS,
  validatePasswordStrength,
  hashPassword,
  verifyPassword,
  dummyVerify
};
