const express = require('express');
const { requireAuth } = require('../middleware/auth');
const { queryAuditLogs, verifyAuditChain } = require('../audit/service');

const router = express.Router();

// Require authentication for all audit endpoints
router.use(requireAuth);

/**
 * GET /api/audit/verify
 * Cryptographically verifies the full audit hash-chain from sequence 1 to HEAD.
 */
router.get('/verify', (req, res) => {
  try {
    const report = verifyAuditChain();
    const statusCode = report.verified ? 200 : 400;
    return res.status(statusCode).json(report);
  } catch (err) {
    return res.status(500).json({
      error: 'Failed to verify audit chain: ' + err.message
    });
  }
});

/**
 * GET /api/audit
 * Returns paginated, filterable audit log entries with live chain verification.
 * Non-admin users see logs relating to their own user account. Admins see all logs.
 */
router.get('/', (req, res) => {
  try {
    const { page, limit, action, resourceType, search } = req.query;
    const isAdmin = req.user.role === 'admin';

    // Non-admin can only inspect logs where they are the actor
    const actorId = isAdmin ? (req.query.actorId || null) : req.user.id;

    const result = queryAuditLogs({
      page,
      limit,
      action,
      resourceType,
      actorId,
      search
    });

    return res.status(200).json(result);
  } catch (err) {
    return res.status(500).json({
      error: 'Failed to retrieve audit trail: ' + err.message
    });
  }
});

module.exports = router;
