const express = require('express');
const crypto = require('crypto');
const { getDatabase } = require('../db/database');
const { requireAuth } = require('../middleware/auth');
const { requireOwnershipOrShare } = require('../gateway/ownership');
const { encryptEnvelope, decryptEnvelope, rewrapEnvelope } = require('../crypto/envelope');
const { rotateActiveKek, getActiveKek } = require('../crypto/key-manager');

const router = express.Router();

/**
 * POST /api/vault/items
 * Create a new encrypted vault item with envelope encryption (caller becomes owner)
 */
router.post('/items', requireAuth, (req, res) => {
  const { title, secret, encryptedData, category = 'secret' } = req.body || {};
  const payloadToEncrypt = secret !== undefined ? secret : encryptedData;

  if (!title || typeof title !== 'string' || payloadToEncrypt === undefined || payloadToEncrypt === null) {
    return res.status(400).json({ error: 'Title and secret (or payload) are required.' });
  }

  const db = getDatabase();
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  const initialVersion = 1;

  // Encrypt with envelope encryption and bind AAD (itemId:v1)
  const aad = `${id}:v${initialVersion}`;
  const envelope = encryptEnvelope(payloadToEncrypt, { aad });

  // 1. Insert into vault_items
  db.prepare(`
    INSERT INTO vault_items (
      id, user_id, title, category, current_version,
      encrypted_dek, dek_iv, dek_tag, kek_version,
      ciphertext, iv, tag, algorithm,
      created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    req.user.id,
    title.trim(),
    category,
    initialVersion,
    envelope.wrappedDek,
    envelope.dekIv,
    envelope.dekTag,
    envelope.kekVersion,
    envelope.ciphertext,
    envelope.iv,
    envelope.tag,
    envelope.algorithm,
    now,
    now
  );

  // 2. Record initial version in vault_item_versions
  const versionId = crypto.randomUUID();
  db.prepare(`
    INSERT INTO vault_item_versions (
      id, item_id, version,
      encrypted_dek, dek_iv, dek_tag, kek_version,
      ciphertext, iv, tag, algorithm,
      created_by_user_id, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    versionId,
    id,
    initialVersion,
    envelope.wrappedDek,
    envelope.dekIv,
    envelope.dekTag,
    envelope.kekVersion,
    envelope.ciphertext,
    envelope.iv,
    envelope.tag,
    envelope.algorithm,
    req.user.id,
    now
  );

  const item = db.prepare('SELECT * FROM vault_items WHERE id = ?').get(id);
  return res.status(201).json({ item });
});

/**
 * GET /api/vault/items
 * Lists all items owned by or shared with the current user.
 * Plaintext secrets are NOT decrypted in bulk to protect performance and memory.
 */
router.get('/items', requireAuth, (req, res) => {
  const db = getDatabase();
  const userId = req.user.id;

  const owned = db.prepare(`
    SELECT 
      id, user_id, title, category, current_version,
      kek_version, algorithm, created_at, updated_at,
      'owner' as access_level 
    FROM vault_items 
    WHERE user_id = ?
    ORDER BY updated_at DESC
  `).all(userId);

  const shared = db.prepare(`
    SELECT 
      v.id, v.user_id, v.title, v.category, v.current_version,
      v.kek_version, v.algorithm, v.created_at, v.updated_at,
      s.permission as access_level 
    FROM vault_items v
    INNER JOIN item_shares s ON v.id = s.item_id
    WHERE s.shared_with_user_id = ?
    ORDER BY v.updated_at DESC
  `).all(userId);

  return res.status(200).json({
    items: [...owned, ...shared]
  });
});

/**
 * GET /api/vault/items/:id
 * Retrieve and decrypt a single item (or specific historical version via ?version=N)
 * Requires ownership or read/write share permission.
 */
router.get('/items/:id', requireAuth, requireOwnershipOrShare('read'), (req, res) => {
  const db = getDatabase();
  const requestedVersion = req.query.version ? parseInt(req.query.version, 10) : null;

  let rowToDecrypt = req.item;
  let targetVersion = req.item.current_version;

  if (requestedVersion) {
    const historicalRow = db.prepare(`
      SELECT * FROM vault_item_versions 
      WHERE item_id = ? AND version = ?
    `).get(req.item.id, requestedVersion);

    if (!historicalRow) {
      return res.status(404).json({ error: `Version ${requestedVersion} not found for this vault item.` });
    }
    rowToDecrypt = historicalRow;
    targetVersion = requestedVersion;
  }

  try {
    let decryptedSecret = null;
    if (rowToDecrypt.ciphertext && rowToDecrypt.encrypted_dek) {
      const envelope = {
        ciphertext: rowToDecrypt.ciphertext,
        iv: rowToDecrypt.iv,
        tag: rowToDecrypt.tag,
        wrappedDek: rowToDecrypt.encrypted_dek,
        dekIv: rowToDecrypt.dekIv || rowToDecrypt.dek_iv,
        dekTag: rowToDecrypt.dekTag || rowToDecrypt.dek_tag,
        kekVersion: rowToDecrypt.kekVersion || rowToDecrypt.kek_version,
        algorithm: rowToDecrypt.algorithm
      };
      const aad = `${req.item.id}:v${targetVersion}`;
      decryptedSecret = decryptEnvelope(envelope, { aad });
    }

    return res.status(200).json({
      item: req.item,
      version: targetVersion,
      secret: decryptedSecret,
      access: req.resourceAccess
    });
  } catch (err) {
    if (err.code === 'ERR_CIPHERTEXT_TAMPER' || err.code === 'ERR_DEK_TAMPER') {
      return res.status(400).json({
        error: 'Cryptographic tamper detected: data integrity compromised.',
        code: err.code
      });
    }
    return res.status(500).json({ error: 'Failed to decrypt vault item.' });
  }
});

/**
 * PUT /api/vault/items/:id
 * Update an item (requires ownership or write share).
 * If a new secret is supplied, creates a new version in version history with a unique DEK!
 */
router.put('/items/:id', requireAuth, requireOwnershipOrShare('write'), (req, res) => {
  const { title, secret, encryptedData, category } = req.body || {};
  const payloadToEncrypt = secret !== undefined ? secret : encryptedData;

  const db = getDatabase();
  const now = new Date().toISOString();
  const newTitle = title ? title.trim() : req.item.title;
  const newCategory = category || req.item.category;

  if (payloadToEncrypt !== undefined && payloadToEncrypt !== null) {
    // Encrypting a new secret revision
    const nextVersion = (req.item.current_version || 1) + 1;
    const aad = `${req.item.id}:v${nextVersion}`;
    const envelope = encryptEnvelope(payloadToEncrypt, { aad });

    // Update active record in vault_items
    db.prepare(`
      UPDATE vault_items 
      SET 
        title = ?,
        category = ?,
        current_version = ?,
        encrypted_dek = ?,
        dek_iv = ?,
        dek_tag = ?,
        kek_version = ?,
        ciphertext = ?,
        iv = ?,
        tag = ?,
        algorithm = ?,
        updated_at = ?
      WHERE id = ?
    `).run(
      newTitle,
      newCategory,
      nextVersion,
      envelope.wrappedDek,
      envelope.dekIv,
      envelope.dekTag,
      envelope.kekVersion,
      envelope.ciphertext,
      envelope.iv,
      envelope.tag,
      envelope.algorithm,
      now,
      req.item.id
    );

    // Record new version in vault_item_versions
    const versionId = crypto.randomUUID();
    db.prepare(`
      INSERT INTO vault_item_versions (
        id, item_id, version,
        encrypted_dek, dek_iv, dek_tag, kek_version,
        ciphertext, iv, tag, algorithm,
        created_by_user_id, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      versionId,
      req.item.id,
      nextVersion,
      envelope.wrappedDek,
      envelope.dekIv,
      envelope.dekTag,
      envelope.kekVersion,
      envelope.ciphertext,
      envelope.iv,
      envelope.tag,
      envelope.algorithm,
      req.user.id,
      now
    );
  } else {
    // Updating metadata only (title, category)
    db.prepare(`
      UPDATE vault_items 
      SET title = ?, category = ?, updated_at = ?
      WHERE id = ?
    `).run(newTitle, newCategory, now, req.item.id);
  }

  const updated = db.prepare('SELECT * FROM vault_items WHERE id = ?').get(req.item.id);
  return res.status(200).json({ item: updated });
});

/**
 * DELETE /api/vault/items/:id
 * Delete an item and all its versions and shares (strictly owner-only)
 */
router.delete('/items/:id', requireAuth, requireOwnershipOrShare('owner'), (req, res) => {
  const db = getDatabase();
  db.prepare('DELETE FROM vault_items WHERE id = ?').run(req.item.id);
  return res.status(200).json({ message: 'Vault item deleted successfully.' });
});

/**
 * GET /api/vault/items/:id/versions
 * List all historical versions for an item
 */
router.get('/items/:id/versions', requireAuth, requireOwnershipOrShare('read'), (req, res) => {
  const db = getDatabase();
  const versions = db.prepare(`
    SELECT 
      v.id, v.item_id, v.version, v.kek_version, v.algorithm,
      v.created_by_user_id, v.created_at,
      u.email as created_by_email
    FROM vault_item_versions v
    LEFT JOIN users u ON v.created_by_user_id = u.id
    WHERE v.item_id = ?
    ORDER BY v.version DESC
  `).all(req.item.id);

  return res.status(200).json({ versions });
});

/**
 * POST /api/vault/rotate-keys
 * Rotates the active KEK and re-wraps all existing item and version DEKs without decrypting payloads.
 */
router.post('/rotate-keys', requireAuth, (req, res) => {
  const { newVersion = `kek_v${Date.now()}` } = req.body || {};

  // Rotate active KEK
  const { version: rotatedVersion } = rotateActiveKek(newVersion);
  const db = getDatabase();

  // 1. Re-wrap all vault_items
  const items = db.prepare('SELECT * FROM vault_items WHERE kek_version != ?').all(rotatedVersion);
  let itemsRotated = 0;

  for (const item of items) {
    if (item.encrypted_dek && item.dek_iv && item.dek_tag) {
      const envelope = {
        ciphertext: item.ciphertext,
        iv: item.iv,
        tag: item.tag,
        wrappedDek: item.encrypted_dek,
        dekIv: item.dek_iv,
        dekTag: item.dek_tag,
        kekVersion: item.kek_version
      };
      const rewrapped = rewrapEnvelope(envelope, rotatedVersion);

      db.prepare(`
        UPDATE vault_items 
        SET encrypted_dek = ?, dek_iv = ?, dek_tag = ?, kek_version = ?
        WHERE id = ?
      `).run(rewrapped.wrappedDek, rewrapped.dekIv, rewrapped.dekTag, rotatedVersion, item.id);

      itemsRotated++;
    }
  }

  // 2. Re-wrap all vault_item_versions
  const versions = db.prepare('SELECT * FROM vault_item_versions WHERE kek_version != ?').all(rotatedVersion);
  let versionsRotated = 0;

  for (const v of versions) {
    if (v.encrypted_dek && v.dek_iv && v.dek_tag) {
      const envelope = {
        ciphertext: v.ciphertext,
        iv: v.iv,
        tag: v.tag,
        wrappedDek: v.encrypted_dek,
        dekIv: v.dek_iv,
        dekTag: v.dek_tag,
        kekVersion: v.kek_version
      };
      const rewrapped = rewrapEnvelope(envelope, rotatedVersion);

      db.prepare(`
        UPDATE vault_item_versions 
        SET encrypted_dek = ?, dek_iv = ?, dek_tag = ?, kek_version = ?
        WHERE id = ?
      `).run(rewrapped.wrappedDek, rewrapped.dekIv, rewrapped.dekTag, rotatedVersion, v.id);

      versionsRotated++;
    }
  }

  return res.status(200).json({
    message: 'Key rotation complete. All DEKs successfully re-wrapped.',
    activeKekVersion: rotatedVersion,
    itemsRotated,
    versionsRotated
  });
});

/**
 * POST /api/vault/items/:id/share
 * Share an item with another user by ID or email (strictly owner-only)
 */
router.post('/items/:id/share', requireAuth, requireOwnershipOrShare('owner'), (req, res) => {
  const { sharedWithUserId, email, permission = 'read' } = req.body || {};

  if (!sharedWithUserId && !email) {
    return res.status(400).json({ error: 'sharedWithUserId or email is required.' });
  }

  if (!['read', 'write'].includes(permission)) {
    return res.status(400).json({ error: 'Permission must be either "read" or "write".' });
  }

  const db = getDatabase();
  let targetUser = null;

  if (sharedWithUserId) {
    targetUser = db.prepare('SELECT id, email FROM users WHERE id = ?').get(sharedWithUserId);
  } else if (email) {
    targetUser = db.prepare('SELECT id, email FROM users WHERE email = ?').get(email.toLowerCase().trim());
  }

  if (!targetUser) {
    return res.status(404).json({ error: 'Target user not found.' });
  }

  if (targetUser.id === req.user.id) {
    return res.status(400).json({ error: 'Cannot share item with yourself.' });
  }

  const shareId = crypto.randomUUID();
  const now = new Date().toISOString();

  // Upsert share
  db.prepare(`
    INSERT INTO item_shares (id, item_id, shared_with_user_id, permission, created_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(item_id, shared_with_user_id) DO UPDATE SET permission = excluded.permission
  `).run(shareId, req.item.id, targetUser.id, permission, now);

  const share = db.prepare(`
    SELECT s.*, u.email as shared_with_email 
    FROM item_shares s
    JOIN users u ON s.shared_with_user_id = u.id
    WHERE s.item_id = ? AND s.shared_with_user_id = ?
  `).get(req.item.id, targetUser.id);

  return res.status(201).json({ share });
});

/**
 * GET /api/vault/items/:id/shares
 * Lists all active shares for an item (strictly owner-only)
 */
router.get('/items/:id/shares', requireAuth, requireOwnershipOrShare('owner'), (req, res) => {
  const db = getDatabase();
  const shares = db.prepare(`
    SELECT s.id, s.item_id, s.shared_with_user_id, s.permission, s.created_at, u.email as shared_with_email
    FROM item_shares s
    JOIN users u ON s.shared_with_user_id = u.id
    WHERE s.item_id = ?
  `).all(req.item.id);

  return res.status(200).json({ shares });
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
