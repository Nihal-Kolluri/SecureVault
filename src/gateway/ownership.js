const { getDatabase } = require('../db/database');

/**
 * Ownership and Share Authorization Middleware
 * 
 * Enforces resource-level access control:
 * - Owners have full read, write, share, and delete permissions.
 * - Shared users have either 'read' or 'write' permissions.
 * - Unauthorized users receive 403 Forbidden (or 404 if resource does not exist).
 * 
 * @param {string} [requiredPermission='read'] - 'read', 'write', or 'owner'
 * @param {string} [idParam='id'] - The request parameter name containing resource ID
 * @returns {import('express').RequestHandler}
 */
function requireOwnershipOrShare(requiredPermission = 'read', idParam = 'id') {
  return function ownershipMiddleware(req, res, next) {
    if (!req.user) {
      return res.status(401).json({
        error: 'Authentication required.'
      });
    }

    const itemId = req.params[idParam];
    if (!itemId) {
      return res.status(400).json({
        error: 'Resource identifier is required.'
      });
    }

    const db = getDatabase();
    const item = db.prepare('SELECT * FROM vault_items WHERE id = ?').get(itemId);

    if (!item) {
      return res.status(404).json({
        error: 'Vault item not found.'
      });
    }

    const userId = req.user.id;
    const isOwner = item.user_id === userId;

    // Check permissions
    if (isOwner) {
      req.item = item;
      req.resourceAccess = { isOwner: true, permission: 'owner' };
      return next();
    }

    // If strictly owner permission is required (e.g., deleting or managing shares)
    if (requiredPermission === 'owner') {
      return res.status(403).json({
        error: 'Forbidden: Only the resource owner can perform this action.'
      });
    }

    // Check shared permissions in item_shares
    const share = db.prepare(`
      SELECT permission FROM item_shares 
      WHERE item_id = ? AND shared_with_user_id = ?
    `).get(itemId, userId);

    if (!share) {
      return res.status(403).json({
        error: 'Access denied: You do not have permission to access this resource.'
      });
    }

    // If 'write' permission is required, user must have 'write' share
    if (requiredPermission === 'write' && share.permission !== 'write') {
      return res.status(403).json({
        error: 'Forbidden: Write permission required for this resource.'
      });
    }

    // Attach item and access metadata to request
    req.item = item;
    req.resourceAccess = { isOwner: false, permission: share.permission };
    next();
  };
}

module.exports = {
  requireOwnershipOrShare
};
