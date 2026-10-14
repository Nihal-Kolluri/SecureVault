const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const fs = require('fs');

let dbInstance = null;

/**
 * Initializes the SQLite database and executes migrations/schema creation.
 * @param {string} [dbPath] - File path or ':memory:' for tests
 * @returns {DatabaseSync}
 */
function initDatabase(dbPath = process.env.DATABASE_URL || ':memory:') {
  if (dbInstance) {
    return dbInstance;
  }

  let finalPath = dbPath;
  if (dbPath.startsWith('file:')) {
    finalPath = dbPath.slice(5);
  }

  if (finalPath !== ':memory:') {
    const dir = path.dirname(path.resolve(finalPath));
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  const db = new DatabaseSync(finalPath);

  // Enable foreign keys and WAL mode if on disk
  db.exec('PRAGMA foreign_keys = ON;');
  if (finalPath !== ':memory:') {
    db.exec('PRAGMA journal_mode = WAL;');
  }

  // Schema creation
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      mfa_enabled INTEGER NOT NULL DEFAULT 0,
      mfa_secret TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS login_attempts (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL COLLATE NOCASE,
      ip_address TEXT,
      attempted_at TEXT NOT NULL,
      success INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_login_attempts_email_time 
      ON login_attempts (email, attempted_at);

    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      refresh_token_hash TEXT NOT NULL,
      user_agent TEXT,
      ip_address TEXT,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL,
      last_used_at TEXT NOT NULL,
      is_revoked INTEGER NOT NULL DEFAULT 0,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions (refresh_token_hash);

    CREATE TABLE IF NOT EXISTS consumed_tokens (
      id TEXT PRIMARY KEY,
      session_id TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      consumed_at TEXT NOT NULL,
      FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_consumed_tokens_hash ON consumed_tokens (token_hash);

    CREATE TABLE IF NOT EXISTS recovery_codes (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      code_hash TEXT NOT NULL,
      used_at TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_recovery_codes_user ON recovery_codes (user_id);

    CREATE TABLE IF NOT EXISTS mfa_attempts (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      attempted_at TEXT NOT NULL,
      success INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_mfa_attempts_user_time ON mfa_attempts (user_id, attempted_at);

    CREATE TABLE IF NOT EXISTS vault_items (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      title TEXT NOT NULL,
      category TEXT NOT NULL DEFAULT 'secret',
      current_version INTEGER NOT NULL DEFAULT 1,
      encrypted_dek TEXT NOT NULL,
      dek_iv TEXT NOT NULL,
      dek_tag TEXT NOT NULL,
      kek_version TEXT NOT NULL,
      ciphertext TEXT NOT NULL,
      iv TEXT NOT NULL,
      tag TEXT NOT NULL,
      algorithm TEXT NOT NULL DEFAULT 'aes-256-gcm',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_vault_items_user ON vault_items (user_id);

    CREATE TABLE IF NOT EXISTS vault_item_versions (
      id TEXT PRIMARY KEY,
      item_id TEXT NOT NULL,
      version INTEGER NOT NULL,
      encrypted_dek TEXT NOT NULL,
      dek_iv TEXT NOT NULL,
      dek_tag TEXT NOT NULL,
      kek_version TEXT NOT NULL,
      ciphertext TEXT NOT NULL,
      iv TEXT NOT NULL,
      tag TEXT NOT NULL,
      algorithm TEXT NOT NULL DEFAULT 'aes-256-gcm',
      created_by_user_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (item_id) REFERENCES vault_items (id) ON DELETE CASCADE,
      FOREIGN KEY (created_by_user_id) REFERENCES users (id) ON DELETE CASCADE,
      UNIQUE (item_id, version)
    );

    CREATE INDEX IF NOT EXISTS idx_vault_versions_item ON vault_item_versions (item_id);

    CREATE TABLE IF NOT EXISTS item_shares (
      id TEXT PRIMARY KEY,
      item_id TEXT NOT NULL,
      shared_with_user_id TEXT NOT NULL,
      permission TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (item_id) REFERENCES vault_items (id) ON DELETE CASCADE,
      FOREIGN KEY (shared_with_user_id) REFERENCES users (id) ON DELETE CASCADE,
      UNIQUE (item_id, shared_with_user_id)
    );

    CREATE INDEX IF NOT EXISTS idx_item_shares_user ON item_shares (shared_with_user_id);
    CREATE INDEX IF NOT EXISTS idx_item_shares_item ON item_shares (item_id);

    CREATE TABLE IF NOT EXISTS vault_files (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      filename TEXT NOT NULL,
      original_filename TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      size_bytes INTEGER NOT NULL,
      encrypted_size_bytes INTEGER NOT NULL,
      storage_bucket TEXT NOT NULL,
      storage_key TEXT NOT NULL,
      sha256_checksum TEXT NOT NULL,
      encrypted_dek TEXT NOT NULL,
      dek_iv TEXT NOT NULL,
      dek_tag TEXT NOT NULL,
      kek_version TEXT NOT NULL,
      iv TEXT NOT NULL,
      tag TEXT NOT NULL,
      algorithm TEXT NOT NULL DEFAULT 'aes-256-gcm',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_vault_files_user ON vault_files (user_id);
    CREATE INDEX IF NOT EXISTS idx_vault_files_storage ON vault_files (storage_bucket, storage_key);
  `);

  // Migration helper: Ensure existing databases add missing columns if needed
  try {
    const columns = db.prepare('PRAGMA table_info(users)').all();
    const colNames = columns.map((c) => c.name);
    if (!colNames.includes('role')) {
      db.exec("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user';");
    }
    if (!colNames.includes('mfa_enabled')) {
      db.exec('ALTER TABLE users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0;');
    }
    if (!colNames.includes('mfa_secret')) {
      db.exec('ALTER TABLE users ADD COLUMN mfa_secret TEXT;');
    }

    const vColumns = db.prepare('PRAGMA table_info(vault_items)').all();
    const vNames = vColumns.map((c) => c.name);
    if (!vNames.includes('category')) db.exec("ALTER TABLE vault_items ADD COLUMN category TEXT NOT NULL DEFAULT 'secret';");
    if (!vNames.includes('current_version')) db.exec("ALTER TABLE vault_items ADD COLUMN current_version INTEGER NOT NULL DEFAULT 1;");
    if (!vNames.includes('encrypted_dek')) db.exec("ALTER TABLE vault_items ADD COLUMN encrypted_dek TEXT NOT NULL DEFAULT '';");
    if (!vNames.includes('dek_iv')) db.exec("ALTER TABLE vault_items ADD COLUMN dek_iv TEXT NOT NULL DEFAULT '';");
    if (!vNames.includes('dek_tag')) db.exec("ALTER TABLE vault_items ADD COLUMN dek_tag TEXT NOT NULL DEFAULT '';");
    if (!vNames.includes('kek_version')) db.exec("ALTER TABLE vault_items ADD COLUMN kek_version TEXT NOT NULL DEFAULT 'kek_v1';");
    if (!vNames.includes('ciphertext')) db.exec("ALTER TABLE vault_items ADD COLUMN ciphertext TEXT NOT NULL DEFAULT '';");
    if (!vNames.includes('iv')) db.exec("ALTER TABLE vault_items ADD COLUMN iv TEXT NOT NULL DEFAULT '';");
    if (!vNames.includes('tag')) db.exec("ALTER TABLE vault_items ADD COLUMN tag TEXT NOT NULL DEFAULT '';");
    if (!vNames.includes('algorithm')) db.exec("ALTER TABLE vault_items ADD COLUMN algorithm TEXT NOT NULL DEFAULT 'aes-256-gcm';");
  } catch {
    // Ignore migration error if already present
  }

  dbInstance = db;
  return dbInstance;
}

/**
 * Returns current database instance or initializes one.
 */
function getDatabase() {
  if (!dbInstance) {
    return initDatabase();
  }
  return dbInstance;
}

/**
 * Closes and resets the database instance (useful for clean test runs).
 */
function closeDatabase() {
  if (dbInstance) {
    try {
      dbInstance.close();
    } catch {
      // Ignore if already closed
    }
    dbInstance = null;
  }
}

module.exports = {
  initDatabase,
  getDatabase,
  closeDatabase
};
