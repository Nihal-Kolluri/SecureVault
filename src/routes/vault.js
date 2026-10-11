const express = require('express');
const crypto = require('crypto');
const { getDatabase } = require('../db/database');
const { requireAuth } = require('../middleware/auth');
const { requireOwnershipOrShare } = require('../gateway/ownership');

const router = express.Router();

/**
 * POST /api/vault/items
 * Create a new encrypted vault item (caller becomes owner)
 */
router.post('/items', requireAuth, (req, res) => {
  const { title, encryptedData } = req.body || {};
  if (!title || typeof title !== 'string' || !encryptedData) {
    return res.status(400).json({ error: 'Title and encryptedData are required.' });
  }

  const db = getDatabase();
  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  db.prepare(`
    INSERT INTO vault_items (id, user_id, title, encrypted_data, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(id, req.user.id, title.trim(), String(encryptedData), now, now);

  const item = db.prepare('SELECT * FROM vault_items WHERE id = ?').get(id);
  return res.status(201).json({ item });
});

/**
 * GET /api/vault/items
 * Lists all items owned by or shared with current user
 */
router.get('/items', requireAuth, (req, res) => {
  const db = getDatabase();
  const userId = req.user.id;

  const owned = db.prepare(`
    SELECT id, user_id, title, encrypted_data, created_at, updated_at, 'owner' as access_level 
    FROM vault_items WHERE user_id = ?
  `).all(userId);

  const shared = db.prepare(`
    SELECT v.id, v.user_id, v.title, v.encrypted_data, v.created_at, v.updated_at, s.permission as access_level 
    FROM vault_items v
    INNER JOIN item_shares s ON v.id = s.item_id
    WHERE s.shared_with_user_id = ?
  `).all(userId);

  return res.status(200).json({
    items: [...owned, ...shared]
  });
});

/**
 * GET /api/vault/items/:id
 * Retrieve a single item (requires ownership or read/write share)
 */
router.get('/items/:id', requireAuth, requireOwnershipOrShare('read'), (req, res) => {
  return res.status(200).json({
    item: req.item,
    access: req.resourceAccess
  });
});

/**
 * PUT /api/vault/items/:id
 * Update an item (requires ownership or write share)
 */
router.put('/items/:id', requireAuth, requireOwnershipOrShare('write'), (req, res) => {
  const { title, encryptedData } = req.body || {};
  const db = getDatabase();
  const now = new Date().toISOString();

  const newTitle = title ? title.trim() : req.item.title;
  const newData = encryptedData ? String(encryptedData) : req.item.encrypted_data;

  db.prepare(`
    UPDATE vault_items 
    SET title = ?, encrypted_data = ?, updated_at = ?
    WHERE id = ?
  `).run(newTitle, newData, now, req.item.id);

  const updated = db.prepare('SELECT * FROM vault_items WHERE id = ?').get(req.item.id);
  return res.status(200).json({ item: updated });
});

/**
 * DELETE /api/vault/items/:id
 * Delete an item (strictly owner-only)
 */
router.delete('/items/:id', requireAuth, requireOwnershipOrShare('owner'), (req, res) => {
  const db = getDatabase();
  db.prepare('DELETE FROM vault_items WHERE id = ?').run(req.item.id);
  return res.status(200).json({ message: 'Vault item deleted successfully.' });
});

/**
 * POST /api/vault/items/:id/share
 * Share an item with another user (strictly owner-only)
 */
router.post('/items/:id/share', requireAuth, requireOwnershipOrShare('owner'), (req, res) => {
  const { sharedWithUserId, permission = 'read' } = req.body || {};

  if (!sharedWithUserId) {
    return res.status(400).json({ error: 'sharedWithUserId is required.' });
  }

  if (!['read', 'write'].includes(permission)) {
    return res.status(400).json({ error: 'Permission must be either "read" or "write".' });
  }

  const db = getDatabase();
  const targetUser = db.prepare('SELECT id FROM users WHERE id = ?').get(sharedWithUserId);
  if (!targetUser) {
    return res.status(404).json({ error: 'Target user not found.' });
  }

  const shareId = crypto.randomUUID();
  const now = new Date().toISOString();

  // Upsert share
  db.prepare(`
    INSERT INTO item_shares (id, item_id, shared_with_user_id, permission, created_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(item_id, shared_with_user_id) DO UPDATE SET permission = excluded.permission
  `).run(shareId, req.item.id, sharedWithUserId, permission, now);

  const share = db.prepare(`
    SELECT * FROM item_shares WHERE item_id = ? AND shared_with_user_id = ?
  `).get(req.item.id, sharedWithUserId);

  return res.status(201).json({ share });
});

/**
 * DELETE /api/vault/items/:id/share/:userId
 * Revoke a share (strictly owner-only)
 */
router.delete('/items/:id/share/:userId', requireAuth, requireOwnershipOrShare('owner'), (req, res) => {
  const db = getDatabase();
  db.prepare(`
    DELETE FROM item_shares WHERE item_id = ? AND shared_with_user_id = ?
  `).run(req.item.id, req.params.userId);

  return res.status(200).json({ message: 'Share revoked successfully.' });
});

module.exports = router;
