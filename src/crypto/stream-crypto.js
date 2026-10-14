const crypto = require('crypto');
const { Transform } = require('stream');
const { wrapDek, unwrapDek, getActiveKek } = require('./key-manager');

const ALGORITHM = 'aes-256-gcm';

/**
 * Streaming AES-256-GCM Encryption Pipeline.
 * Transforms plaintext stream into AES-256-GCM ciphertext chunks while computing
 * SHA-256 checksum and enforcing maximum size limits in real-time.
 */
class FileEncryptionPipeline extends Transform {
  /**
   * @param {object} options
   * @param {Buffer} options.dek - 256-bit Data Encryption Key
   * @param {Buffer} options.iv - 96-bit Initialization Vector
   * @param {string} [options.aad] - Additional Authenticated Data
   * @param {number} [options.maxSizeBytes] - Enforced size limit
   */
  constructor({ dek, iv, aad, maxSizeBytes } = {}) {
    super();

    if (!dek || !iv) {
      throw new Error('DEK and IV are required for FileEncryptionPipeline.');
    }

    this.dek = dek;
    this.iv = iv;
    this.aad = aad || null;
    this.maxSizeBytes = maxSizeBytes || null;

    this.hasher = crypto.createHash('sha256');
    this.cipher = crypto.createCipheriv(ALGORITHM, this.dek, this.iv);

    if (this.aad) {
      this.cipher.setAAD(Buffer.from(String(this.aad), 'utf8'));
    }

    this.plaintextSize = 0;
    this.ciphertextSize = 0;
    this.authTag = null;
    this.sha256Checksum = null;
  }

  _transform(chunk, encoding, callback) {
    const bufferChunk = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding);
    this.plaintextSize += bufferChunk.length;

    if (this.maxSizeBytes && this.plaintextSize > this.maxSizeBytes) {
      const limitErr = new Error(`File size exceeds maximum allowed limit of ${this.maxSizeBytes} bytes.`);
      limitErr.code = 'LIMIT_FILE_SIZE';
      limitErr.maxSizeBytes = this.maxSizeBytes;
      return callback(limitErr);
    }

    this.hasher.update(bufferChunk);

    try {
      const encryptedChunk = this.cipher.update(bufferChunk);
      if (encryptedChunk && encryptedChunk.length > 0) {
        this.ciphertextSize += encryptedChunk.length;
        this.push(encryptedChunk);
      }
      callback();
    } catch (err) {
      callback(err);
    }
  }

  _flush(callback) {
    try {
      const finalChunk = this.cipher.final();
      if (finalChunk && finalChunk.length > 0) {
        this.ciphertextSize += finalChunk.length;
        this.push(finalChunk);
      }
      this.authTag = this.cipher.getAuthTag();
      this.sha256Checksum = this.hasher.digest('hex');
      callback();
    } catch (err) {
      callback(err);
    }
  }
}

/**
 * Streaming AES-256-GCM Decryption Pipeline.
 * Transforms AES-256-GCM ciphertext stream back to plaintext while verifying
 * authentication tag and SHA-256 checksum.
 */
class FileDecryptionPipeline extends Transform {
  /**
   * @param {object} options
   * @param {Buffer} options.dek - 256-bit Data Encryption Key
   * @param {Buffer} options.iv - 96-bit Initialization Vector
   * @param {Buffer} options.tag - 128-bit Authentication Tag
   * @param {string} [options.aad] - Additional Authenticated Data
   * @param {string} [options.expectedChecksum] - Expected SHA-256 checksum
   */
  constructor({ dek, iv, tag, aad, expectedChecksum } = {}) {
    super();

    if (!dek || !iv || !tag) {
      throw new Error('DEK, IV, and auth tag are required for FileDecryptionPipeline.');
    }

    this.dek = dek;
    this.iv = iv;
    this.tag = tag;
    this.aad = aad || null;
    this.expectedChecksum = expectedChecksum || null;

    this.hasher = crypto.createHash('sha256');
    this.decipher = crypto.createDecipheriv(ALGORITHM, this.dek, this.iv);

    if (this.aad) {
      this.decipher.setAAD(Buffer.from(String(this.aad), 'utf8'));
    }
    this.decipher.setAuthTag(this.tag);

    this.decryptedSize = 0;
    this.computedChecksum = null;
    this.isVerified = false;
  }

  _transform(chunk, encoding, callback) {
    const bufferChunk = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding);

    try {
      const decryptedChunk = this.decipher.update(bufferChunk);
      if (decryptedChunk && decryptedChunk.length > 0) {
        this.decryptedSize += decryptedChunk.length;
        this.hasher.update(decryptedChunk);
        this.push(decryptedChunk);
      }
      callback();
    } catch (err) {
      const tamperErr = new Error('Cryptographic tamper detected: authentication tag verification failed.');
      tamperErr.code = 'ERR_CIPHERTEXT_TAMPER';
      callback(tamperErr);
    }
  }

  _flush(callback) {
    try {
      const finalChunk = this.decipher.final();
      if (finalChunk && finalChunk.length > 0) {
        this.decryptedSize += finalChunk.length;
        this.hasher.update(finalChunk);
        this.push(finalChunk);
      }
      this.computedChecksum = this.hasher.digest('hex');

      if (this.expectedChecksum && this.computedChecksum !== this.expectedChecksum) {
        const checksumErr = new Error(
          `Checksum mismatch: expected ${this.expectedChecksum}, computed ${this.computedChecksum}`
        );
        checksumErr.code = 'ERR_CHECKSUM_MISMATCH';
        return callback(checksumErr);
      }

      this.isVerified = true;
      callback();
    } catch (err) {
      const tamperErr = new Error('Cryptographic tamper detected: authentication tag verification failed.');
      tamperErr.code = 'ERR_CIPHERTEXT_TAMPER';
      callback(tamperErr);
    }
  }
}

/**
 * Initializes a new envelope key context for file encryption.
 * Generates random 256-bit DEK, 96-bit IV, and wraps DEK under active KEK.
 * @param {object} [options]
 * @param {string} [options.kekVersion]
 * @returns {{
 *   dek: Buffer,
 *   iv: Buffer,
 *   wrappedDek: string,
 *   dekIv: string,
 *   dekTag: string,
 *   kekVersion: string,
 *   algorithm: string
 * }}
 */
function createFileEnvelope(options = {}) {
  const dek = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const targetKekVersion = options.kekVersion || getActiveKek().version;
  const wrapped = wrapDek(dek, targetKekVersion);

  return {
    dek,
    iv,
    wrappedDek: wrapped.wrappedDek,
    dekIv: wrapped.dekIv,
    dekTag: wrapped.dekTag,
    kekVersion: wrapped.kekVersion,
    algorithm: ALGORITHM
  };
}

/**
 * Unwraps the DEK for a file from its stored envelope.
 * @param {object} fileRecord
 * @param {string} fileRecord.encrypted_dek
 * @param {string} fileRecord.dek_iv
 * @param {string} fileRecord.dek_tag
 * @param {string} fileRecord.kek_version
 * @returns {Buffer}
 */
function unwrapFileDek(fileRecord) {
  return unwrapDek({
    wrappedDek: fileRecord.encrypted_dek,
    dekIv: fileRecord.dek_iv,
    dekTag: fileRecord.dek_tag,
    kekVersion: fileRecord.kek_version
  });
}

/**
 * Verifies the integrity of a stored ciphertext stream by executing streaming decryption
 * and checksum verification without storing the plaintext.
 * @param {import('stream').Readable} ciphertextStream
 * @param {object} params
 * @param {Buffer} params.dek
 * @param {Buffer} params.iv
 * @param {Buffer} params.tag
 * @param {string} [params.aad]
 * @param {string} [params.expectedChecksum]
 * @returns {Promise<{ verified: boolean, checksum: string, size: number }>}
 */
async function verifyCiphertextStream(ciphertextStream, params) {
  const pipeline = new FileDecryptionPipeline(params);

  return new Promise((resolve, reject) => {
    ciphertextStream.on('error', reject);
    pipeline.on('error', reject);

    // Consume the decrypted output without storing in memory
    pipeline.on('data', () => {});

    pipeline.on('end', () => {
      resolve({
        verified: pipeline.isVerified,
        checksum: pipeline.computedChecksum,
        size: pipeline.decryptedSize
      });
    });

    ciphertextStream.pipe(pipeline);
  });
}

module.exports = {
  FileEncryptionPipeline,
  FileDecryptionPipeline,
  createFileEnvelope,
  unwrapFileDek,
  verifyCiphertextStream,
  ALGORITHM
};
