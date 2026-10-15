const crypto = require('crypto');
const { getDatabase } = require('../db/database');

const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

/**
 * Deterministically serialize any object or value with sorted keys.
 * @param {*} obj
 * @returns {string}
 */
function canonicalStringify(obj) {
  if (obj === null || obj === undefined) return '';
  if (typeof obj !== 'object') return String(obj);
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalStringify).join(',') + ']';
  }
  const keys = Object.keys(obj).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalStringify(obj[k])).join(',') + '}';
}

/**
 * Calculates SHA-256 hash for a single audit log entry using canonical payload format.
 * @param {object} params
 * @param {number} params.sequence
 * @param {string} params.timestamp
 * @param {string} params.action
 * @param {string} [params.actorId]
 * @param {string} [params.actorEmail]
 * @param {string} [params.actorIp]
 * @param {string} [params.resourceType]
 * @param {string} [params.resourceId]
 * @param {object|string} [params.details]
 * @param {string} params.prevHash
 * @returns {string} 64-character hex SHA-256 hash
 */
function calculateEntryHash({
  sequence,
  timestamp,
  action,
  actorId = '',
  actorEmail = '',
  actorIp = '',
  resourceType = '',
  resourceId = '',
  details = '',
  prevHash
}) {
  let detailsStr = '';
  if (typeof details === 'object' && details !== null) {
    detailsStr = canonicalStringify(details);
  } else if (typeof details === 'string' && details.trim() !== '') {
    try {
      const parsed = JSON.parse(details);
      detailsStr = canonicalStringify(parsed);
    } catch {
      detailsStr = details;
    }
  }

  const payload = [
    Number(sequence),
    String(timestamp),
    String(action),
    actorId ? String(actorId) : '',
    actorEmail ? String(actorEmail) : '',
    actorIp ? String(actorIp) : '',
    resourceType ? String(resourceType) : '',
    resourceId ? String(resourceId) : '',
    detailsStr,
    String(prevHash)
  ].join('|');

  return crypto.createHash('sha256').update(payload, 'utf8').digest('hex');
}

/**
 * Sanitizes details metadata ensuring ZERO plaintext secrets, tokens, or passwords are logged.
 * @param {object|string} details
 * @returns {string}
 */
function sanitizeDetails(details) {
  if (!details) return '';
  if (typeof details === 'string') {
    try {
      details = JSON.parse(details);
    } catch {
      return details.slice(0, 2048);
    }
  }

  const sanitized = { ...details };
  const sensitiveKeys = [
    'password',
    'secret',
    'token',
    'refreshToken',
    'accessToken',
    'recoveryCode',
    'code',
    'mfaSecret',
    'key',
    'dek',
    'kek'
  ];

  for (const k of Object.keys(sanitized)) {
    const lower = k.toLowerCase();
    if (sensitiveKeys.some((s) => lower.includes(s))) {
      sanitized[k] = '[REDACTED]';
    }
  }

  return JSON.stringify(sanitized);
}

/**
 * Appends a new tamper-evident, hash-chained log entry to the audit log.
 * @param {object} params
 * @param {string} params.action - e.g., 'AUTH_LOGIN', 'VAULT_SECRET_CREATE', etc.
 * @param {string} [params.actorId]
 * @param {string} [params.actorEmail]
 * @param {string} [params.actorIp]
 * @param {string} [params.resourceType]
 * @param {string} [params.resourceId]
 * @param {object|string} [params.details]
 * @param {string} [params.timestamp]
 * @param {DatabaseSync} [db]
 * @returns {object} The persisted audit log entry
 */
function appendAuditEntry(
  {
    action,
    actorId = null,
    actorEmail = null,
    actorIp = null,
    resourceType = null,
    resourceId = null,
    details = null,
    timestamp = null
  },
  db = getDatabase()
) {
  if (!action || typeof action !== 'string') {
    throw new Error('Audit action string is required.');
  }

  const id = crypto.randomUUID();
  const entryTime = timestamp || new Date().toISOString();
  const detailsJson = sanitizeDetails(details);

  // Atomic sequence calculation and hash chaining
  const latest = db.prepare('SELECT sequence, entry_hash FROM audit_logs ORDER BY sequence DESC LIMIT 1').get();
  const sequence = latest ? latest.sequence + 1 : 1;
  const prevHash = latest ? latest.entry_hash : GENESIS_HASH;

  const entryHash = calculateEntryHash({
    sequence,
    timestamp: entryTime,
    action,
    actorId,
    actorEmail,
    actorIp,
    resourceType,
    resourceId,
    details: detailsJson,
    prevHash
  });

  db.prepare(`
    INSERT INTO audit_logs (
      id, sequence, timestamp, action,
      actor_id, actor_email, actor_ip,
      resource_type, resource_id, details,
      prev_hash, entry_hash
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    sequence,
    entryTime,
    action,
    actorId,
    actorEmail,
    actorIp,
    resourceType,
    resourceId,
    detailsJson,
    prevHash,
    entryHash
  );

  return {
    id,
    sequence,
    timestamp: entryTime,
    action,
    actorId,
    actorEmail,
    actorIp,
    resourceType,
    resourceId,
    details: detailsJson,
    prevHash,
    entryHash
  };
}

/**
 * Traverses the entire audit log from sequence 1 to HEAD, verifying
 * unbroken sequence numbers, hash pointers, and canonical content integrity.
 * @param {DatabaseSync} [db]
 * @returns {object} Verification report
 */
function verifyAuditChain(db = getDatabase()) {
  const rows = db.prepare('SELECT * FROM audit_logs ORDER BY sequence ASC').all();

  if (rows.length === 0) {
    return {
      verified: true,
      count: 0,
      status: 'EMPTY_CHAIN',
      headHash: GENESIS_HASH,
      genesisHash: GENESIS_HASH
    };
  }

  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    const expectedSequence = i + 1;

    // 1. Verify sequence monotonicity
    if (row.sequence !== expectedSequence) {
      return {
        verified: false,
        count: rows.length,
        status: 'TAMPER_DETECTED',
        brokenSequence: row.sequence,
        reason: `Sequence gap or ordering anomaly. Expected ${expectedSequence}, found ${row.sequence}`,
        expectedSequence,
        actualSequence: row.sequence
      };
    }

    // 2. Verify previous hash pointer
    const expectedPrevHash = i === 0 ? GENESIS_HASH : rows[i - 1].entry_hash;
    if (row.prev_hash !== expectedPrevHash) {
      return {
        verified: false,
        count: rows.length,
        status: 'TAMPER_DETECTED',
        brokenSequence: row.sequence,
        reason: 'Previous hash mismatch (broken chain link)',
        expectedPrevHash,
        actualPrevHash: row.prev_hash
      };
    }

    // 3. Verify entry hash integrity
    const expectedEntryHash = calculateEntryHash({
      sequence: row.sequence,
      timestamp: row.timestamp,
      action: row.action,
      actorId: row.actor_id,
      actorEmail: row.actor_email,
      actorIp: row.actor_ip,
      resourceType: row.resource_type,
      resourceId: row.resource_id,
      details: row.details,
      prevHash: row.prev_hash
    });

    if (row.entry_hash !== expectedEntryHash) {
      return {
        verified: false,
        count: rows.length,
        status: 'TAMPER_DETECTED',
        brokenSequence: row.sequence,
        reason: 'Entry hash mismatch (record payload altered)',
        expectedHash: expectedEntryHash,
        actualHash: row.entry_hash
      };
    }
  }

  return {
    verified: true,
    count: rows.length,
    status: 'CHAIN_INTACT',
    headHash: rows[rows.length - 1].entry_hash,
    genesisHash: rows[0].entry_hash
  };
}

module.exports = {
  GENESIS_HASH,
  calculateEntryHash,
  canonicalStringify,
  sanitizeDetails,
  appendAuditEntry,
  verifyAuditChain
};
