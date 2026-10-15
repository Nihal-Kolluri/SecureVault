const { getDatabase } = require('../db/database');
const { appendAuditEntry, verifyAuditChain } = require('./audit-chain');

/**
 * Standard Audit Action Constants
 */
const AUDIT_ACTIONS = {
  // Auth
  AUTH_REGISTER: 'AUTH_REGISTER',
  AUTH_LOGIN_SUCCESS: 'AUTH_LOGIN_SUCCESS',
  AUTH_LOGIN_FAILED: 'AUTH_LOGIN_FAILED',
  AUTH_LOGOUT: 'AUTH_LOGOUT',
  AUTH_TOKEN_REFRESH: 'AUTH_TOKEN_REFRESH',
  AUTH_TOKEN_REUSE: 'AUTH_TOKEN_REUSE',

  // Sessions
  SESSION_REVOKE: 'SESSION_REVOKE',
  SESSION_REVOKE_ALL: 'SESSION_REVOKE_ALL',

  // MFA
  MFA_SETUP_INIT: 'MFA_SETUP_INIT',
  MFA_ENABLE: 'MFA_ENABLE',
  MFA_DISABLE: 'MFA_DISABLE',
  MFA_RECOVERY_USED: 'MFA_RECOVERY_USED',
  MFA_FAILED: 'MFA_FAILED',

  // RBAC & Users
  USER_ROLE_CHANGE: 'USER_ROLE_CHANGE',

  // Vault Secrets
  VAULT_SECRET_CREATE: 'VAULT_SECRET_CREATE',
  VAULT_SECRET_READ: 'VAULT_SECRET_READ',
  VAULT_SECRET_UPDATE: 'VAULT_SECRET_UPDATE',
  VAULT_SECRET_DELETE: 'VAULT_SECRET_DELETE',
  VAULT_SECRET_SHARE: 'VAULT_SECRET_SHARE',
  VAULT_SECRET_UNSHARE: 'VAULT_SECRET_UNSHARE',
  KEK_ROTATE: 'KEK_ROTATE',

  // Encrypted Files (MinIO)
  FILE_UPLOAD: 'FILE_UPLOAD',
  FILE_DOWNLOAD: 'FILE_DOWNLOAD',
  FILE_VERIFY: 'FILE_VERIFY',
  FILE_DELETE: 'FILE_DELETE'
};

/**
 * Helper to record an audit log from an Express request context.
 * Safely swallows non-fatal logging exceptions so audit logging doesn't crash user flows,
 * but rethrows in test environment if needed.
 * @param {object} params
 * @param {string} params.action - One of AUDIT_ACTIONS
 * @param {express.Request} [params.req]
 * @param {string} [params.actorId]
 * @param {string} [params.actorEmail]
 * @param {string} [params.actorIp]
 * @param {string} [params.resourceType]
 * @param {string} [params.resourceId]
 * @param {object|string} [params.details]
 * @returns {object|null}
 */
function recordAudit({
  action,
  req = null,
  actorId = null,
  actorEmail = null,
  actorIp = null,
  resourceType = null,
  resourceId = null,
  details = null
}) {
  try {
    let finalActorId = actorId;
    let finalActorEmail = actorEmail;
    let finalActorIp = actorIp;

    if (req) {
      if (!finalActorIp) {
        finalActorIp = req.ip || (req.socket && req.socket.remoteAddress) || null;
      }
      if (req.user) {
        finalActorId = finalActorId || req.user.id;
        finalActorEmail = finalActorEmail || req.user.email;
      }
    }

    return appendAuditEntry({
      action,
      actorId: finalActorId,
      actorEmail: finalActorEmail,
      actorIp: finalActorIp,
      resourceType,
      resourceId,
      details
    });
  } catch (err) {
    if (process.env.NODE_ENV === 'test') {
      // Allow test assertions to surface if any
      throw err;
    }
    // In production, avoid taking down user request but log to console
    console.error('[AUDIT ERROR] Failed to append audit log:', err.message);
    return null;
  }
}

/**
 * Query audit logs with pagination and filtering.
 * @param {object} params
 * @param {number} [params.page=1]
 * @param {number} [params.limit=25]
 * @param {string} [params.action]
 * @param {string} [params.resourceType]
 * @param {string} [params.actorId]
 * @param {string} [params.search]
 * @returns {{ logs: object[], pagination: object, verification: object }}
 */
function queryAuditLogs({
  page = 1,
  limit = 25,
  action = null,
  resourceType = null,
  actorId = null,
  search = null
} = {}) {
  const db = getDatabase();
  const safePage = Math.max(1, parseInt(page, 10) || 1);
  const safeLimit = Math.min(100, Math.max(1, parseInt(limit, 10) || 25));
  const offset = (safePage - 1) * safeLimit;

  const conditions = [];
  const params = [];

  if (action) {
    conditions.push('action = ?');
    params.push(action);
  }

  if (resourceType) {
    conditions.push('resource_type = ?');
    params.push(resourceType);
  }

  if (actorId) {
    conditions.push('actor_id = ?');
    params.push(actorId);
  }

  if (search && search.trim()) {
    conditions.push('(actor_email LIKE ? OR actor_ip LIKE ? OR resource_id LIKE ? OR action LIKE ?)');
    const searchTerm = `%${search.trim()}%`;
    params.push(searchTerm, searchTerm, searchTerm, searchTerm);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  const countRow = db.prepare(`SELECT COUNT(*) as total FROM audit_logs ${whereClause}`).get(...params);
  const total = countRow ? countRow.total : 0;

  const logs = db.prepare(`
    SELECT 
      id, sequence, timestamp, action,
      actor_id, actor_email, actor_ip,
      resource_type, resource_id, details,
      prev_hash, entry_hash
    FROM audit_logs 
    ${whereClause}
    ORDER BY sequence DESC 
    LIMIT ? OFFSET ?
  `).all(...params, safeLimit, offset);

  const verification = verifyAuditChain(db);

  return {
    logs: logs.map((log) => ({
      ...log,
      details: log.details ? (function() {
        try { return JSON.parse(log.details); } catch { return log.details; }
      })() : null
    })),
    pagination: {
      page: safePage,
      limit: safeLimit,
      total,
      totalPages: Math.ceil(total / safeLimit) || 1
    },
    verification
  };
}

module.exports = {
  AUDIT_ACTIONS,
  recordAudit,
  queryAuditLogs,
  verifyAuditChain
};
