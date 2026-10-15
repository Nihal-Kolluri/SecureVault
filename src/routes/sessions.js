const express = require('express');
const { getDatabase } = require('../db/database');
const { requireAuth } = require('../middleware/auth');
const { recordAudit, AUDIT_ACTIONS } = require('../audit/service');

const router = express.Router();

router.use(requireAuth);

/**
 * GET /api/sessions
 * Lists all active and past sessions for current user.
 */
router.get('/', (req, res) => {
  try {
    const db = getDatabase();
    const rows = db.prepare(`
      SELECT id, user_agent, ip_address, expires_at, created_at, last_used_at, is_revoked
      FROM sessions
      WHERE user_id = ?
      ORDER BY last_used_at DESC, created_at DESC
    `).all(req.user.id);

    const currentSessionId = req.user.sessionId || null;

    const sessions = rows.map((s) => ({
      id: s.id,
      userAgent: s.user_agent || 'Unknown Device',
      ipAddress: s.ip_address || 'Unknown IP',
      createdAt: s.created_at,
      lastUsedAt: s.last_used_at,
      expiresAt: s.expires_at,
      isRevoked: Boolean(s.is_revoked),
      isCurrent: Boolean(currentSessionId && s.id === currentSessionId)
    }));

    return res.status(200).json({ sessions });
  } catch (err) {
    return res.status(500).json({
      error: 'Failed to retrieve user sessions: ' + err.message
    });
  }
});

/**
 * DELETE /api/sessions/:id
 * Revokes a specific session belonging to the user.
 */
router.delete('/:id', (req, res) => {
  try {
    const sessionId = req.params.id;
    const db = getDatabase();

    const session = db.prepare('SELECT id, user_id, is_revoked FROM sessions WHERE id = ?').get(sessionId);
    if (!session) {
      return res.status(404).json({ error: 'Session not found.' });
    }

    if (session.user_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden: Cannot revoke another user session.' });
    }

    db.prepare('UPDATE sessions SET is_revoked = 1 WHERE id = ?').run(sessionId);

    recordAudit({
      action: AUDIT_ACTIONS.SESSION_REVOKE,
      req,
      resourceType: 'session',
      resourceId: sessionId,
      details: {
        revokedSessionId: sessionId,
        targetUserId: session.user_id,
        isCurrent: Boolean(req.user.sessionId && req.user.sessionId === sessionId)
      }
    });

    const isCurrent = Boolean(req.user.sessionId && req.user.sessionId === sessionId);
    if (isCurrent) {
      res.clearCookie('accessToken');
      res.clearCookie('refreshToken', { path: '/api/auth' });
    }

    return res.status(200).json({
      message: 'Session revoked successfully.',
      isCurrent
    });
  } catch (err) {
    return res.status(500).json({
      error: 'Failed to revoke session: ' + err.message
    });
  }
});

/**
 * POST /api/sessions/revoke-others
 * Revokes all sessions belonging to the user except their current session.
 */
router.post('/revoke-others', (req, res) => {
  try {
    const currentSessionId = req.user.sessionId;
    const db = getDatabase();

    let result;
    if (currentSessionId) {
      result = db.prepare(`
        UPDATE sessions 
        SET is_revoked = 1 
        WHERE user_id = ? AND id != ? AND is_revoked = 0
      `).run(req.user.id, currentSessionId);
    } else {
      result = db.prepare(`
        UPDATE sessions 
        SET is_revoked = 1 
        WHERE user_id = ? AND is_revoked = 0
      `).run(req.user.id);
    }

    const revokedCount = result.changes || 0;

    recordAudit({
      action: AUDIT_ACTIONS.SESSION_REVOKE_ALL,
      req,
      resourceType: 'session',
      resourceId: currentSessionId || 'all',
      details: {
        preservedSessionId: currentSessionId || null,
        revokedCount
      }
    });

    return res.status(200).json({
      message: 'All other sessions have been revoked.',
      revokedCount
    });
  } catch (err) {
    return res.status(500).json({
      error: 'Failed to revoke other sessions: ' + err.message
    });
  }
});

module.exports = router;
