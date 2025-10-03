const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');

const dbDir = path.join(__dirname);
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir);
const dbPath = path.join(dbDir, 'app.db');
if (fs.existsSync(dbPath)) {
  console.log('Database exists already at', dbPath);
  process.exit(0);
}

const db = new Database(dbPath);

db.exec(`
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  email TEXT UNIQUE,
  password TEXT,
  strand TEXT,
  year_level TEXT,
  is_admin INTEGER DEFAULT 0,
  points INTEGER DEFAULT 0,
  is_verified INTEGER DEFAULT 0,
  verification_token TEXT,
  token_expires TEXT,
  offense_count INTEGER DEFAULT 0,
  ban_until TEXT
);

CREATE TABLE questions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  title TEXT,
  body TEXT,
  subject TEXT,
  tags TEXT,
  votes INTEGER DEFAULT 0,
  created_at TEXT
);

CREATE TABLE answers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  question_id INTEGER,
  user_id INTEGER,
  body TEXT,
  votes INTEGER DEFAULT 0,
  created_at TEXT
);

CREATE TABLE resources (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  title TEXT,
  filename TEXT,
  filepath TEXT,
  created_at TEXT
);

CREATE TABLE posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  body TEXT,
  created_at TEXT
);
`);

(async () => {
  const adminEmail = process.env.ADMIN_EMAIL || 'admin@example.com';
  const adminPass = process.env.ADMIN_PASSWORD || 'adminpass123';
  const hash = await bcrypt.hash(adminPass, 10);
  db.prepare('INSERT INTO users (name,email,password,is_admin,is_verified,points) VALUES (?,?,?,?,?,?)').run('Admin', adminEmail, hash, 1, 1, 0);
  console.log('Database initialized. Admin created with email:', adminEmail, 'password:', adminPass);
  console.log('Please change admin password after first login.');
})();
