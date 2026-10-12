const crypto = require('crypto');
const { wrapDek, unwrapDek, getActiveKek } = require('./key-manager');

/**
 * Envelope Encryption Module
 * 
 * Cryptographic Specifications:
 * - Data Encryption Algorithm: AES-256-GCM (NIST SP 800-38D)
 * - DEK Size: 256 bits (32 bytes cryptographically secure random)
 * - IV / Nonce Size: 96 bits (12 bytes cryptographically secure random per encryption)
 * - Authentication Tag: 128 bits (16 bytes)
 * - Additional Authenticated Data (AAD): Cryptographically binds context (e.g. itemId/version) to ciphertext
 * - Key Encryption: DEKs are wrapped using AES-256-GCM under versioned KEKs
 */

const ALGORITHM = 'aes-256-gcm';

/**
 * Encrypts a plaintext payload using envelope encryption.
 * 
 * 1. Generates a unique 256-bit DEK.
 * 2. Encrypts payload with AES-256-GCM using the DEK and a 96-bit IV.
 * 3. Binds optional AAD (Additional Authenticated Data).
 * 4. Wraps the DEK under the active (or requested) KEK.
 * 5. Returns a structured envelope containing ciphertext and wrapped DEK.
 * 
 * @param {string|Buffer} plaintext
 * @param {object} [options]
 * @param {string} [options.aad] - Additional Authenticated Data to bind
 * @param {string} [options.kekVersion] - Target KEK version (defaults to active)
 * @returns {{
 *   ciphertext: string,
 *   iv: string,
 *   tag: string,
 *   wrappedDek: string,
 *   dekIv: string,
 *   dekTag: string,
 *   kekVersion: string,
 *   algorithm: string,
 *   aad: string|null
 * }}
 */
function encryptEnvelope(plaintext, options = {}) {
  if (plaintext === undefined || plaintext === null) {
    throw new Error('Plaintext payload is required for encryption.');
  }

  const payloadBuffer = Buffer.isBuffer(plaintext)
    ? plaintext
    : Buffer.from(String(plaintext), 'utf8');

  // 1. Generate unique 256-bit DEK & 96-bit IV
  const dek = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);

  // 2. Encrypt payload with AES-256-GCM
  const cipher = crypto.createCipheriv(ALGORITHM, dek, iv);

  const aad = options.aad || null;
  if (aad) {
    cipher.setAAD(Buffer.from(String(aad), 'utf8'));
  }

  const ciphertext = Buffer.concat([cipher.update(payloadBuffer), cipher.final()]);
  const tag = cipher.getAuthTag();

  // 3. Wrap DEK under KEK
  const targetKekVersion = options.kekVersion || getActiveKek().version;
  const wrapped = wrapDek(dek, targetKekVersion);

  return {
    ciphertext: ciphertext.toString('hex'),
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
    wrappedDek: wrapped.wrappedDek,
    dekIv: wrapped.dekIv,
    dekTag: wrapped.dekTag,
    kekVersion: wrapped.kekVersion,
    algorithm: ALGORITHM,
    aad: aad ? String(aad) : null
  };
}

/**
 * Decrypts an envelope-encrypted payload.
 * 
 * 1. Unwraps the DEK using the KEK indicated by envelope.kekVersion.
 * 2. Authenticates and decrypts the payload with AES-256-GCM.
 * 3. Verifies 128-bit authentication tag and AAD.
 * 
 * Throws a tamper error if tag verification or unwrap fails.
 * 
 * @param {object} envelope
 * @param {string} envelope.ciphertext
 * @param {string} envelope.iv
 * @param {string} envelope.tag
 * @param {string} envelope.wrappedDek
 * @param {string} envelope.dekIv
 * @param {string} envelope.dekTag
 * @param {string} envelope.kekVersion
 * @param {string} [envelope.aad]
 * @param {object} [options]
 * @param {string} [options.aad] - Expected AAD (overrides envelope.aad if provided)
 * @returns {string} Decrypted plaintext string (utf8)
 */
function decryptEnvelope(envelope, options = {}) {
  if (!envelope || !envelope.ciphertext || !envelope.iv || !envelope.tag) {
    throw new Error('Malformed envelope: missing required ciphertext, iv, or tag fields.');
  }

  // 1. Unwrap DEK
  const dek = unwrapDek({
    wrappedDek: envelope.wrappedDek,
    dekIv: envelope.dekIv,
    dekTag: envelope.dekTag,
    kekVersion: envelope.kekVersion
  });

  const iv = Buffer.from(envelope.iv, 'hex');
  const tag = Buffer.from(envelope.tag, 'hex');
  const ciphertextBuffer = Buffer.from(envelope.ciphertext, 'hex');

  const decipher = crypto.createDecipheriv(ALGORITHM, dek, iv);
  decipher.setAuthTag(tag);

  const aad = options.aad !== undefined ? options.aad : envelope.aad;
  if (aad) {
    decipher.setAAD(Buffer.from(String(aad), 'utf8'));
  }

  try {
    const decrypted = Buffer.concat([
      decipher.update(ciphertextBuffer),
      decipher.final()
    ]);
    return decrypted.toString('utf8');
  } catch (err) {
    const error = new Error('Cryptographic tamper detected: payload authentication tag mismatch or corrupted ciphertext.');
    error.code = 'ERR_CIPHERTEXT_TAMPER';
    error.statusCode = 400;
    throw error;
  }
}

/**
 * Re-wraps an existing envelope under a new KEK version without decrypting the payload.
 * 
 * @param {object} envelope
 * @param {string} newKekVersion
 * @returns {object} Updated envelope object
 */
function rewrapEnvelope(envelope, newKekVersion) {
  // 1. Unwrap the DEK using existing KEK version
  const dek = unwrapDek({
    wrappedDek: envelope.wrappedDek,
    dekIv: envelope.dekIv,
    dekTag: envelope.dekTag,
    kekVersion: envelope.kekVersion
  });

  // 2. Wrap DEK under the new KEK version
  const rewrapped = wrapDek(dek, newKekVersion);

  return {
    ...envelope,
    wrappedDek: rewrapped.wrappedDek,
    dekIv: rewrapped.dekIv,
    dekTag: rewrapped.dekTag,
    kekVersion: rewrapped.kekVersion
  };
}

module.exports = {
  ALGORITHM,
  encryptEnvelope,
  decryptEnvelope,
  rewrapEnvelope
};
