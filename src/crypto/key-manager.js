const crypto = require('crypto');

/**
 * Key Management Module (KMS / KEK Management)
 * 
 * Manages Key Encryption Keys (KEKs) used to wrap Data Encryption Keys (DEKs).
 * Supports:
 * - Versioned KEKs (e.g. 'kek_v1', 'kek_v2')
 * - Dynamic key rotation without service downtime
 * - Master key loading from environment or secure generator
 * - AES-256-GCM wrapping and unwrapping of DEKs
 */

// In-memory registry of versioned KEKs
const kekRegistry = new Map();
let activeKekVersion = 'kek_v1';

/**
 * Normalizes a key input (Buffer, hex string, base64 string, or UTF-8 passphrase) to a 32-byte Buffer.
 * @param {Buffer|string} keyInput
 * @returns {Buffer} 32-byte Buffer
 */
function normalizeKey(keyInput) {
  if (Buffer.isBuffer(keyInput)) {
    if (keyInput.length === 32) return keyInput;
    // Derive 32-byte key using SHA-256 if length is not exactly 32
    return crypto.createHash('sha256').update(keyInput).digest();
  }

  if (typeof keyInput === 'string') {
    const trimmed = keyInput.trim();
    // Hex string (64 chars)
    if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
      return Buffer.from(trimmed, 'hex');
    }
    // Base64 string (44 chars with =)
    if (/^[A-Za-z0-9+/]{43}=$/.test(trimmed)) {
      const buf = Buffer.from(trimmed, 'base64');
      if (buf.length === 32) return buf;
    }
    // Otherwise derive 32-byte key using SHA-256
    return crypto.createHash('sha256').update(trimmed).digest();
  }

  throw new Error('Invalid key input: must be a Buffer or string.');
}

/**
 * Generates a cryptographically secure 256-bit (32-byte) key.
 * @returns {Buffer}
 */
function generateKey() {
  return crypto.randomBytes(32);
}

/**
 * Initializes the default master KEK.
 */
function initDefaultKek() {
  const envKey = process.env.MASTER_KEY || process.env.KEK_V1;
  const initialKey = envKey 
    ? normalizeKey(envKey) 
    : normalizeKey('securevault-default-master-key-kek-v1-dev');

  kekRegistry.set('kek_v1', initialKey);
  activeKekVersion = 'kek_v1';
}

// Initialize on module load
initDefaultKek();

/**
 * Registers a KEK under a specific version name.
 * @param {string} version
 * @param {Buffer|string} key
 */
function registerKek(version, key) {
  if (!version || typeof version !== 'string') {
    throw new Error('KEK version must be a non-empty string.');
  }
  const keyBuffer = normalizeKey(key);
  kekRegistry.set(version, keyBuffer);
}

/**
 * Gets the active KEK version and key buffer.
 * @returns {{ version: string, key: Buffer }}
 */
function getActiveKek() {
  const key = kekRegistry.get(activeKekVersion);
  if (!key) {
    throw new Error(`Active KEK '${activeKekVersion}' not found in registry.`);
  }
  return { version: activeKekVersion, key };
}

/**
 * Gets a KEK by its version identifier.
 * @param {string} version
 * @returns {Buffer}
 */
function getKekByVersion(version) {
  const key = kekRegistry.get(version);
  if (!key) {
    throw new Error(`KEK with version '${version}' is not registered in Key Manager.`);
  }
  return key;
}

/**
 * Sets the active KEK version.
 * @param {string} version
 */
function setActiveKekVersion(version) {
  if (!kekRegistry.has(version)) {
    throw new Error(`Cannot set active KEK: version '${version}' does not exist.`);
  }
  activeKekVersion = version;
}

/**
 * Rotates the active KEK by registering a new version and making it active.
 * @param {string} newVersion - e.g. 'kek_v2'
 * @param {Buffer|string} [newKey] - Optional new key buffer; generates random 256-bit key if omitted
 * @returns {{ version: string, key: Buffer }}
 */
function rotateActiveKek(newVersion, newKey = null) {
  const key = newKey ? normalizeKey(newKey) : generateKey();
  registerKek(newVersion, key);
  setActiveKekVersion(newVersion);
  return { version: newVersion, key };
}

/**
 * Resets the key manager registry to default state (useful for tests).
 */
function resetKeyManager() {
  kekRegistry.clear();
  initDefaultKek();
}

/**
 * Wraps a Data Encryption Key (DEK) using AES-256-GCM under the specified KEK (or active KEK).
 * @param {Buffer} dek - 32-byte DEK
 * @param {string} [targetKekVersion] - Optional specific KEK version
 * @returns {{ wrappedDek: string, dekIv: string, dekTag: string, kekVersion: string }}
 */
function wrapDek(dek, targetKekVersion = null) {
  const kekVersion = targetKekVersion || activeKekVersion;
  const kek = getKekByVersion(kekVersion);

  const iv = crypto.randomBytes(12); // 96-bit IV
  const cipher = crypto.createCipheriv('aes-256-gcm', kek, iv);
  
  // AAD binds the KEK version string to the wrapped DEK
  cipher.setAAD(Buffer.from(`kek-version:${kekVersion}`));

  const wrapped = Buffer.concat([cipher.update(dek), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    wrappedDek: wrapped.toString('hex'),
    dekIv: iv.toString('hex'),
    dekTag: tag.toString('hex'),
    kekVersion
  };
}

/**
 * Unwraps a Data Encryption Key (DEK) using AES-256-GCM.
 * Throws a tamper error if tag verification fails.
 * @param {object} params
 * @param {string} params.wrappedDek - Hex string
 * @param {string} params.dekIv - Hex string
 * @param {string} params.dekTag - Hex string
 * @param {string} params.kekVersion - KEK version identifier
 * @returns {Buffer} 32-byte DEK buffer
 */
function unwrapDek({ wrappedDek, dekIv, dekTag, kekVersion }) {
  const kek = getKekByVersion(kekVersion);
  const iv = Buffer.from(dekIv, 'hex');
  const tag = Buffer.from(dekTag, 'hex');
  const encrypted = Buffer.from(wrappedDek, 'hex');

  const decipher = crypto.createDecipheriv('aes-256-gcm', kek, iv);
  decipher.setAuthTag(tag);
  decipher.setAAD(Buffer.from(`kek-version:${kekVersion}`));

  try {
    const dek = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return dek;
  } catch (err) {
    const error = new Error('Cryptographic tamper detected: unable to unwrap DEK (authentication tag mismatch).');
    error.code = 'ERR_DEK_TAMPER';
    error.statusCode = 400;
    throw error;
  }
}

module.exports = {
  normalizeKey,
  generateKey,
  registerKek,
  getActiveKek,
  getKekByVersion,
  setActiveKekVersion,
  rotateActiveKek,
  resetKeyManager,
  wrapDek,
  unwrapDek
};
