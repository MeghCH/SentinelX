const Database = require('better-sqlite3')
const path = require('path')

// SENTINELX_DB_PATH lets test files (and any embedded run) point the app at
// an isolated database instead of the shared supportdesk.db working copy.
const db = new Database(process.env.SENTINELX_DB_PATH || path.join(__dirname, '..', 'supportdesk.db'))

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user'
  );

  CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    status TEXT DEFAULT 'open',
    priority TEXT DEFAULT 'medium',
    created_by INTEGER,
    assigned_to INTEGER,
    created_at TEXT,
    updated_at TEXT,
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (assigned_to) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id INTEGER,
    author_id INTEGER,
    content TEXT NOT NULL,
    created_at TEXT,
    FOREIGN KEY (ticket_id) REFERENCES tickets(id),
    FOREIGN KEY (author_id) REFERENCES users(id)
  );
`)

try { db.exec(`ALTER TABLE users ADD COLUMN display_name TEXT`) } catch (_) {}
try { db.exec(`ALTER TABLE users ADD COLUMN theme TEXT DEFAULT 'light'`) } catch (_) {}

module.exports = db
