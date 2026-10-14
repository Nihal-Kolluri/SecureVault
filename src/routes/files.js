const express = require('express');
const crypto = require('crypto');
const path = require('path');
const busboy = require('busboy');
const { getDatabase } = require('../db/database');
const { requireAuth } = require('../middleware/auth');
const {
  FileEncryptionPipeline,
  FileDecryptionPipeline,
  createFileEnvelope,
  unwrapFileDek,
  verifyCiphertextStream
} = require('../crypto/stream-crypto');
const {
  getBucketName,
  putObjectStream,
  getObjectStream,
  deleteObject
} = require('../storage/minio');

const router = express.Router();

// Configuration limits
const DEFAULT_MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB
const BLOCKED_EXTENSIONS = new Set([
  '.exe', '.bat', '.cmd', '.sh', '.ps1', '.vbs', '.msi', '.dll', '.com', '.scr', '.pif', '.jar'
]);

/**
 * Gets configured maximum file size in bytes.
 * @returns {number}
 */
function getMaxFileSize() {
  const envLimit = process.env.MAX_FILE_SIZE_BYTES;
  if (envLimit && !isNaN(parseInt(envLimit, 10))) {
    return parseInt(envLimit, 10);
  }
  return DEFAULT_MAX_FILE_SIZE;
}

/**
 * Sanitizes a filename to prevent path traversal and null byte injections.
 * @param {string} rawName
 * @returns {string}
 */
function sanitizeFilename(rawName) {
  if (!rawName || typeof rawName !== 'string') {
    return 'unnamed_file';
  }
  // Remove null bytes and path traversal
  const base = path.basename(rawName).replace(/\0/g, '').trim();
  // Strip non-printable / control characters
  const clean = base.replace(/[^\x20-\x7E]/g, '_');
  return clean.slice(0, 255) || 'unnamed_file';
}

/**
 * Checks if a filename has a disallowed executable extension.
 * @param {string} filename
 * @returns {boolean}
 */
function isDisallowedExtension(filename) {
  const ext = path.extname(filename).toLowerCase();
  return BLOCKED_EXTENSIONS.has(ext);
}

/**
 * POST /api/files/upload
 * Streaming encrypted file upload via MinIO S3 object storage with SHA-256 checksum and size limits.
 */
router.post('/upload', requireAuth, (req, res) => {
  const contentType = req.headers['content-type'] || '';
  if (!contentType.includes('multipart/form-data')) {
    return res.status(400).json({ error: 'Content-Type must be multipart/form-data' });
  }

  const maxFileSize = getMaxFileSize();
  let expectedChecksum = req.headers['x-checksum-sha256'] || req.headers['x-sha256'] || null;
  if (expectedChecksum) {
    expectedChecksum = String(expectedChecksum).toLowerCase().trim();
  }

  let bb;
  try {
    bb = busboy({
      headers: req.headers,
      limits: {
        fileSize: maxFileSize,
        files: 1
      }
    });
  } catch (err) {
    return res.status(400).json({ error: 'Invalid multipart request', details: err.message });
  }

  let fileHandled = false;
  let uploadAborted = false;
  let uploadPromise = null;

  bb.on('field', (name, val) => {
    if (name === 'checksum' || name === 'sha256') {
      expectedChecksum = String(val).toLowerCase().trim();
    }
  });

  bb.on('file', (name, fileStream, info) => {
    if (fileHandled) {
      fileStream.resume();
      return;
    }
    fileHandled = true;

    const rawFilename = info.filename || 'unnamed_file';
    const filename = sanitizeFilename(rawFilename);
    const mimeType = info.mimeType || 'application/octet-stream';

    // Extension validation
    if (isDisallowedExtension(filename)) {
      uploadAborted = true;
      fileStream.resume();
      return res.status(400).json({
        error: `Executable files with extension '${path.extname(filename)}' are disallowed for security.`
      });
    }

    const fileId = crypto.randomUUID();
    const userId = req.user.id;
    const bucket = getBucketName();
    const storageKey = `${userId}/${fileId}.enc`;

    // Initialize envelope keying
    const envelope = createFileEnvelope();
    const aad = `file:${fileId}:${userId}:${filename}`;

    const encryptionPipeline = new FileEncryptionPipeline({
      dek: envelope.dek,
      iv: envelope.iv,
      aad,
      maxSizeBytes: maxFileSize
    });

    fileStream.on('limit', () => {
      uploadAborted = true;
      const limitErr = new Error(`File size exceeds maximum allowed limit of ${maxFileSize} bytes.`);
      limitErr.code = 'LIMIT_FILE_SIZE';
      encryptionPipeline.destroy(limitErr);
    });

    encryptionPipeline.on('error', (err) => {
      uploadAborted = true;
      if (err.code === 'LIMIT_FILE_SIZE' || (err.message && err.message.includes('limit'))) {
        if (!res.headersSent) {
          return res.status(413).json({
            error: `File size exceeds maximum allowed limit of ${maxFileSize} bytes.`,
            limit: maxFileSize
          });
        }
      } else if (!res.headersSent) {
        return res.status(500).json({ error: 'Encryption streaming error', details: err.message });
      }
    });

    // Pipe file into encryption pipeline, and pipe ciphertext into MinIO storage
    const encryptedStream = fileStream.pipe(encryptionPipeline);

    uploadPromise = (async () => {
      try {
        await putObjectStream(bucket, storageKey, encryptedStream, undefined, {
          'Content-Type': 'application/octet-stream',
          'X-Amz-Meta-File-Id': fileId,
          'X-Amz-Meta-Original-Name': encodeURIComponent(filename)
        });

        if (uploadAborted) {
          await deleteObject(bucket, storageKey).catch(() => {});
          return;
        }

        const sha256Checksum = encryptionPipeline.sha256Checksum;
        const authTag = encryptionPipeline.authTag;
        const plaintextSize = encryptionPipeline.plaintextSize;
        const ciphertextSize = encryptionPipeline.ciphertextSize;

        // Verify client-provided checksum if present
        if (expectedChecksum && sha256Checksum !== expectedChecksum) {
          await deleteObject(bucket, storageKey).catch(() => {});
          if (!res.headersSent) {
            return res.status(400).json({
              error: 'Checksum mismatch: uploaded file checksum does not match expected value.',
              expected: expectedChecksum,
              computed: sha256Checksum
            });
          }
          return;
        }

        // Store file record in database
        const db = getDatabase();
        const now = new Date().toISOString();

        db.prepare(`
          INSERT INTO vault_files (
            id, user_id, filename, original_filename, mime_type,
            size_bytes, encrypted_size_bytes, storage_bucket, storage_key,
            sha256_checksum, encrypted_dek, dek_iv, dek_tag, kek_version,
            iv, tag, algorithm, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          fileId,
          userId,
          filename,
          rawFilename,
          mimeType,
          plaintextSize,
          ciphertextSize,
          bucket,
          storageKey,
          sha256Checksum,
          envelope.wrappedDek,
          envelope.dekIv,
          envelope.dekTag,
          envelope.kekVersion,
          envelope.iv.toString('hex'),
          authTag.toString('hex'),
          envelope.algorithm,
          now,
          now
        );

        const createdRecord = db.prepare(`
          SELECT id, filename, mime_type, size_bytes, encrypted_size_bytes,
                 sha256_checksum, kek_version, algorithm, created_at
          FROM vault_files
          WHERE id = ?
        `).get(fileId);

        if (!res.headersSent) {
          return res.status(201).json({
            message: 'File encrypted and stored successfully.',
            file: {
              id: createdRecord.id,
              filename: createdRecord.filename,
              mimeType: createdRecord.mime_type,
              sizeBytes: createdRecord.size_bytes,
              encryptedSizeBytes: createdRecord.encrypted_size_bytes,
              sha256Checksum: createdRecord.sha256_checksum,
              kekVersion: createdRecord.kek_version,
              algorithm: createdRecord.algorithm,
              createdAt: createdRecord.created_at
            }
          });
        }
      } catch (err) {
        await deleteObject(bucket, storageKey).catch(() => {});
        if (!res.headersSent) {
          if (err.code === 'LIMIT_FILE_SIZE' || (err.message && err.message.includes('limit'))) {
            return res.status(413).json({
              error: `File size exceeds maximum allowed limit of ${maxFileSize} bytes.`
            });
          }
          return res.status(500).json({ error: 'Failed to upload encrypted file', details: err.message });
        }
      }
    })();
  });

  bb.on('error', (err) => {
    if (!res.headersSent) {
      res.status(400).json({ error: 'Malformed upload stream', details: err.message });
    }
  });

  bb.on('finish', () => {
    if (!fileHandled && !res.headersSent) {
      res.status(400).json({ error: 'No file found in multipart upload' });
    }
  });

  req.pipe(bb);
});

/**
 * GET /api/files
 * Lists all encrypted files owned by the authenticated user.
 */
router.get('/', requireAuth, (req, res) => {
  const db = getDatabase();
  const userId = req.user.id;

  const files = db.prepare(`
    SELECT id, filename, mime_type, size_bytes, encrypted_size_bytes,
           sha256_checksum, kek_version, algorithm, created_at, updated_at
    FROM vault_files
    WHERE user_id = ?
    ORDER BY created_at DESC
  `).all(userId);

  const formatted = files.map((f) => ({
    id: f.id,
    filename: f.filename,
    mimeType: f.mime_type,
    sizeBytes: f.size_bytes,
    encryptedSizeBytes: f.encrypted_size_bytes,
    sha256Checksum: f.sha256_checksum,
    kekVersion: f.kek_version,
    algorithm: f.algorithm,
    createdAt: f.created_at,
    updatedAt: f.updated_at
  }));

  return res.status(200).json({ files: formatted });
});

/**
 * GET /api/files/:id
 * Retrieve file metadata.
 */
router.get('/:id', requireAuth, (req, res) => {
  const db = getDatabase();
  const file = db.prepare('SELECT * FROM vault_files WHERE id = ?').get(req.params.id);

  if (!file) {
    return res.status(404).json({ error: 'File not found' });
  }

  // Ownership verification
  if (file.user_id !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied: not authorized to view this file' });
  }

  return res.status(200).json({
    file: {
      id: file.id,
      filename: file.filename,
      mimeType: file.mime_type,
      sizeBytes: file.size_bytes,
      encryptedSizeBytes: file.encrypted_size_bytes,
      sha256Checksum: file.sha256_checksum,
      kekVersion: file.kek_version,
      algorithm: file.algorithm,
      createdAt: file.created_at,
      updatedAt: file.updated_at
    }
  });
});

/**
 * GET /api/files/:id/download
 * Decrypts and streams the file payload from MinIO with checksum and tamper verification.
 */
router.get('/:id/download', requireAuth, async (req, res) => {
  const db = getDatabase();
  const file = db.prepare('SELECT * FROM vault_files WHERE id = ?').get(req.params.id);

  if (!file) {
    return res.status(404).json({ error: 'File not found' });
  }

  // Ownership check
  if (file.user_id !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied: not authorized to download this file' });
  }

  try {
    const dek = unwrapFileDek(file);
    const aad = `file:${file.id}:${file.user_id}:${file.filename}`;

    // Cryptographic pre-verification: Authenticate ciphertext and GCM tag before streaming plaintext
    // This prevents unauthenticated plaintext release vulnerabilities and enables returning clean 400 errors.
    const verifyStream = await getObjectStream(file.storage_bucket, file.storage_key);
    await verifyCiphertextStream(verifyStream, {
      dek,
      iv: Buffer.from(file.iv, 'hex'),
      tag: Buffer.from(file.tag, 'hex'),
      aad,
      expectedChecksum: file.sha256_checksum
    });

    const ciphertextStream = await getObjectStream(file.storage_bucket, file.storage_key);

    const decryptionPipeline = new FileDecryptionPipeline({
      dek,
      iv: Buffer.from(file.iv, 'hex'),
      tag: Buffer.from(file.tag, 'hex'),
      aad,
      expectedChecksum: file.sha256_checksum
    });

    // Set headers
    res.setHeader('Content-Type', file.mime_type || 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(file.filename)}"`);
    res.setHeader('Content-Length', file.size_bytes);
    res.setHeader('X-Checksum-SHA256', file.sha256_checksum);
    res.setHeader('ETag', `"${file.sha256_checksum}"`);

    decryptionPipeline.on('error', (err) => {
      if (!res.headersSent) {
        if (err.code === 'ERR_CIPHERTEXT_TAMPER') {
          return res.status(400).json({
            error: 'Cryptographic tamper detected: authentication tag verification failed.',
            code: 'ERR_CIPHERTEXT_TAMPER'
          });
        }
        if (err.code === 'ERR_CHECKSUM_MISMATCH') {
          return res.status(400).json({
            error: 'Integrity failure: calculated checksum does not match expected file checksum.',
            code: 'ERR_CHECKSUM_MISMATCH'
          });
        }
        return res.status(500).json({ error: 'Streaming decryption error', details: err.message });
      }
      res.destroy(err);
    });

    ciphertextStream.on('error', (err) => {
      if (!res.headersSent) {
        return res.status(500).json({ error: 'Storage retrieval error', details: err.message });
      }
      res.destroy(err);
    });

    ciphertextStream.pipe(decryptionPipeline).pipe(res);
  } catch (err) {
    if (err.code === 'ERR_CIPHERTEXT_TAMPER' || err.code === 'ERR_DEK_TAMPER') {
      return res.status(400).json({
        error: 'Cryptographic tamper detected: key or ciphertext verification failed.',
        code: err.code
      });
    }
    return res.status(500).json({ error: 'Failed to initiate file download', details: err.message });
  }
});

/**
 * GET /api/files/:id/verify
 * Verifies storage integrity and checksum of an encrypted file without downloading payload.
 */
router.get('/:id/verify', requireAuth, async (req, res) => {
  const db = getDatabase();
  const file = db.prepare('SELECT * FROM vault_files WHERE id = ?').get(req.params.id);

  if (!file) {
    return res.status(404).json({ error: 'File not found' });
  }

  if (file.user_id !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied: not authorized to verify this file' });
  }

  try {
    const dek = unwrapFileDek(file);
    const aad = `file:${file.id}:${file.user_id}:${file.filename}`;
    const ciphertextStream = await getObjectStream(file.storage_bucket, file.storage_key);

    const result = await verifyCiphertextStream(ciphertextStream, {
      dek,
      iv: Buffer.from(file.iv, 'hex'),
      tag: Buffer.from(file.tag, 'hex'),
      aad,
      expectedChecksum: file.sha256_checksum
    });

    return res.status(200).json({
      verified: true,
      fileId: file.id,
      filename: file.filename,
      sha256Checksum: result.checksum,
      sizeBytes: result.size,
      algorithm: file.algorithm,
      status: 'INTACT_AND_AUTHENTICATED'
    });
  } catch (err) {
    if (err.code === 'ERR_CIPHERTEXT_TAMPER' || err.code === 'ERR_DEK_TAMPER') {
      return res.status(400).json({
        verified: false,
        error: 'Cryptographic tamper detected: file content or authentication tag corrupted.',
        code: err.code
      });
    }
    if (err.code === 'ERR_CHECKSUM_MISMATCH') {
      return res.status(400).json({
        verified: false,
        error: 'Integrity check failed: checksum mismatch.',
        code: err.code
      });
    }
    return res.status(500).json({ error: 'Verification failed', details: err.message });
  }
});

/**
 * DELETE /api/files/:id
 * Deletes an encrypted file from MinIO storage and removes database record.
 */
router.delete('/:id', requireAuth, async (req, res) => {
  const db = getDatabase();
  const file = db.prepare('SELECT * FROM vault_files WHERE id = ?').get(req.params.id);

  if (!file) {
    return res.status(404).json({ error: 'File not found' });
  }

  if (file.user_id !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied: not authorized to delete this file' });
  }

  try {
    await deleteObject(file.storage_bucket, file.storage_key);
    db.prepare('DELETE FROM vault_files WHERE id = ?').run(file.id);

    return res.status(200).json({
      message: 'File deleted successfully',
      id: file.id
    });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to delete file', details: err.message });
  }
});

module.exports = router;
