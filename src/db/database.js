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
  `);

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
