const express = require('express');
const { getDatabase } = require('../db/database');
const { requireAuth } = require('../middleware/auth');
const { requireRole, ROLES } = require('../gateway/rbac');
const { recordAudit, AUDIT_ACTIONS } = require('../audit/service');

const router = express.Router();

// All admin routes require authentication and ADMIN role
router.use(requireAuth);
router.use(requireRole(ROLES.ADMIN));

/**
 * GET /api/admin/users
 * Returns list of all registered users
 */
router.get('/users', (req, res) => {
  const db = getDatabase();
  const users = db.prepare('SELECT id, email, role, mfa_enabled, created_at, updated_at FROM users').all();
  return res.status(200).json({ users });
});

/**
 * PUT /api/admin/users/:id/role
 * Changes user role (admin, manager, user)
 */
router.put('/users/:id/role', (req, res) => {
  const { role } = req.body || {};
  if (!role || !Object.values(ROLES).includes(role)) {
    return res.status(400).json({ error: `Invalid role. Allowed roles: ${Object.values(ROLES).join(', ')}` });
  }

  const db = getDatabase();
  const user = db.prepare('SELECT id, email, role FROM users WHERE id = ?').get(req.params.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found.' });
  }

  const previousRole = user.role;
  const now = new Date().toISOString();
  db.prepare('UPDATE users SET role = ?, updated_at = ? WHERE id = ?').run(role, now, req.params.id);

  const updated = db.prepare('SELECT id, email, role FROM users WHERE id = ?').get(req.params.id);

  recordAudit({
    action: AUDIT_ACTIONS.USER_ROLE_CHANGE,
    req,
    resourceType: 'user',
    resourceId: req.params.id,
    details: {
      targetUserId: req.params.id,
      targetEmail: user.email,
      previousRole,
      newRole: role
    }
  });

  return res.status(200).json({ user: updated });
});

module.exports = router;
