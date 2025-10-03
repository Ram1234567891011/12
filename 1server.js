const path = require('path');
const express = require('express');
const session = require('express-session');
const flash = require('connect-flash');
const bcrypt = require('bcrypt');
const multer = require('multer');
const fs = require('fs');
const methodOverride = require('method-override');
const sanitizeHtml = require('sanitize-html');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
require('dotenv').config();


// Database (better-sqlite3)
const Database = require('better-sqlite3');
const db = new Database(path.join(__dirname, 'db', 'app.db'));

const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(methodOverride('_method'));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: process.env.SESSION_SECRET || 'dev_secret_change_me',
  resave: false,
  saveUninitialized: false,
}));
app.use(flash());

// Make flash and user available in templates
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  res.locals.success = req.flash('success');
  res.locals.error = req.flash('error');
  next();
});

// Setup uploads
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, unique + '-' + file.originalname.replace(/[^a-zA-Z0-9.\- _]/g, ''));
  }
});
const upload = multer({ storage });

// --- Email (nodemailer) setup helper ---
function getMailer() {
  const host = process.env.SMTP_HOST;
  if (!host) return null;
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT) : 587,
    secure: false,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });
}

// --- Profanity / banned words setup ---
// The banned words list is in banned-words.txt (one per line). Admin can edit that file.
const bannedWordsFile = path.join(__dirname, 'banned-words.txt');
function loadBannedWords() {
  try {
    const txt = fs.readFileSync(bannedWordsFile, 'utf-8');
    return txt.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  } catch(e) {
    return [];
  }
}
function containsBanned(text) {
  if (!text) return null;
  const words = loadBannedWords();
  if (words.length === 0) return null;
  const lowered = text.toLowerCase();
  for (let w of words) {
    const wEsc = w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp('\\b' + wEsc + '\\b', 'i');
    if (re.test(lowered)) return w;
  }
  return null;
}

// Ban logic: increment offense_count in users table and set ban_until based on offense count
function applyBan(userId) {
  const u = db.prepare('SELECT offense_count FROM users WHERE id = ?').get(userId);
  const current = u ? (u.offense_count || 0) : 0;
  const newCount = current + 1;
  let banMinutes = 0;
  if (newCount === 1) banMinutes = 10;
  else if (newCount === 2) banMinutes = 60;
  else banMinutes = 60*24; // 1 day
  const until = new Date(Date.now() + banMinutes*60*1000).toISOString();
  db.prepare('UPDATE users SET offense_count = ?, ban_until = ? WHERE id = ?').run(newCount, until, userId);
  return { newCount, until };
}

function checkUserBanned(user) {
  if (!user) return false;
  if (!user.ban_until) return false;
  const until = new Date(user.ban_until);
  if (isNaN(until.getTime())) return false;
  return until > new Date();
}

// Middleware to block actions if banned
function requireNotBanned(req, res, next) {
  if (!req.session.user) return next();
  const u = db.prepare('SELECT id,name,ban_until FROM users WHERE id = ?').get(req.session.user.id);
  if (u && checkUserBanned(u)) {
    req.flash('error', 'You are temporarily banned until ' + u.ban_until);
    return res.redirect('back');
  }
  next();
}

// Middleware to scan text fields for banned words and apply ban if detected
function profanityGuard(fields) {
  return (req, res, next) => {
    // only for logged in users (we can still block anonymous posts by IP later)
    const user = req.session.user;
    const textToCheck = [];
    for (let f of fields) {
      if (req.body && req.body[f]) textToCheck.push(String(req.body[f]));
      if (req.query && req.query[f]) textToCheck.push(String(req.query[f]));
    }
    const combined = textToCheck.join('\n');
    const found = containsBanned(combined);
    if (found) {
      if (!user) {
        req.flash('error', 'Your content contains disallowed words and cannot be posted.');
        return res.redirect('back');
      }
      const result = applyBan(user.id);
      req.flash('error', `Your post contained a disallowed word (${found}). This is offense #${result.newCount}. You are banned until ${result.until}.`);
      return res.redirect('back');
    }
    next();
  };
}

// --- Helpers ---
function requireLogin(req, res, next){
  if (!req.session.user) {
    req.flash('error', 'Please log in first.');
    return res.redirect('/login');
  }
  next();
}
function requireAdmin(req, res, next){
  if (!req.session.user || !req.session.user.is_admin) {
    req.flash('error', 'Admin access required.');
    return res.redirect('/login');
  }
  next();
}

// --- Routes ---
app.get('/', (req, res) => {
  const featured = db.prepare('SELECT q.id, q.title, q.subject, q.votes, COUNT(a.id) AS answers FROM questions q LEFT JOIN answers a ON a.question_id=q.id GROUP BY q.id ORDER BY q.votes DESC LIMIT 5').all();
  res.render('home', { featured });
});

// --- Auth & Email Verification ---
app.get('/register', (req, res) => res.render('register'));

app.post('/register', profanityGuard(['name']), async (req, res) => {
  const { name, email, password, strand, year_level } = req.body;
  if (!email || !password || !name) {
    req.flash('error', 'Name, email and password required.');
    return res.redirect('/register');
  }
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) {
    req.flash('error', 'Email already registered.');
    return res.redirect('/register');
  }
  const hash = await bcrypt.hash(password, 10);
  const token = crypto.randomBytes(24).toString('hex');
  const tokenExpires = new Date(Date.now() + 24*60*60*1000).toISOString(); // 24h expiry
  const stmt = db.prepare('INSERT INTO users (name,email,password,strand,year_level,is_admin,points,is_verified,verification_token,token_expires) VALUES (?,?,?,?,?,0,0,0,?,?)');
  const info = stmt.run(name,email,hash,strand || '', year_level || '', token, tokenExpires);
  // send verification email (if SMTP configured)
  const mailer = getMailer();
  const base = process.env.BASE_URL || (req.protocol + '://' + req.get('host'));
  const verifyUrl = base + '/verify?token=' + token;
  if (mailer) {
    try {
      await mailer.sendMail({
        from: process.env.SMTP_USER,
        to: email,
        subject: 'Please verify your Student Forum account',
        text: `Hi ${name},\n\nClick the link to verify your account: ${verifyUrl}\n\nIf you didn't register, ignore.`
      });
      req.flash('success', 'Registered. Please check your email for verification link.');
    } catch (e) {
      console.error('Mail error', e);
      req.flash('success', 'Registered. (Failed to send email — check server logs) Use the verification link printed in server console.');
      console.log('Verification link:', verifyUrl);
    }
  } else {
    console.log('No SMTP configured. Verification link:', verifyUrl);
    req.flash('success', 'Registered. Verification link printed to server console (SMTP not configured).');
  }
  res.redirect('/login');
});

app.get('/verify', (req, res) => {
  const token = req.query.token;
  if (!token) {
    req.flash('error', 'Verification token missing.');
    return res.redirect('/');
  }
  const user = db.prepare('SELECT id, token_expires FROM users WHERE verification_token = ?').get(token);
  if (!user) {
    req.flash('error', 'Invalid token.');
    return res.redirect('/');
  }
  if (new Date(user.token_expires) < new Date()) {
    req.flash('error', 'Token expired. Contact admin.');
    return res.redirect('/');
  }
  db.prepare('UPDATE users SET is_verified = 1, verification_token = NULL, token_expires = NULL WHERE id = ?').run(user.id);
  req.flash('success', 'Email verified. Please log in.');
  res.redirect('/login');
});

app.get('/login', (req, res) => res.render('login'));

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT id,name,email,password,is_admin,points,strand,year_level,is_verified,ban_until FROM users WHERE email = ?').get(email);
  if (!user) {
    req.flash('error', 'Invalid email or password.');
    return res.redirect('/login');
  }
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) {
    req.flash('error', 'Invalid email or password.');
    return res.redirect('/login');
  }
  if (!user.is_verified) {
    req.flash('error', 'Please verify your email before logging in. Check your inbox.');
    return res.redirect('/login');
  }
  if (user.ban_until && new Date(user.ban_until) > new Date()) {
    req.flash('error', 'You are temporarily banned until ' + user.ban_until);
    return res.redirect('/login');
  }
  req.session.user = { id: user.id, name: user.name, email: user.email, is_admin: user.is_admin, points: user.points, strand: user.strand, year_level: user.year_level };
  req.flash('success', 'Logged in.');
  res.redirect('/');
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// --- Forum ---
app.get('/forum', (req, res) => {
  const questions = db.prepare('SELECT q.id, q.title, q.subject, q.votes, q.tags, u.name AS author, q.created_at, COUNT(a.id) AS answers FROM questions q LEFT JOIN answers a ON a.question_id=q.id LEFT JOIN users u ON u.id=q.user_id GROUP BY q.id ORDER BY q.created_at DESC').all();
  res.render('forum', { questions });
});

app.get('/questions/new', requireLogin, (req, res) => res.render('ask'));
app.post('/questions', requireLogin, requireNotBanned, profanityGuard(['title','body']), (req, res) => {
  let { title, body, subject, tags } = req.body;
  title = sanitizeHtml(title);
  body = sanitizeHtml(body);
  tags = tags || '';
  const stmt = db.prepare('INSERT INTO questions (user_id,title,body,subject,tags,votes,created_at) VALUES (?,?,?,?,?,0,datetime("now"))');
  const info = stmt.run(req.session.user.id, title, body, subject, tags);
  req.flash('success', 'Question posted.');
  res.redirect('/forum');
});

app.get('/questions/:id', (req, res) => {
  const q = db.prepare('SELECT q.*, u.name AS author FROM questions q LEFT JOIN users u ON u.id=q.user_id WHERE q.id = ?').get(req.params.id);
  if (!q) return res.status(404).send('Not found');
  const answers = db.prepare('SELECT a.*, u.name AS author FROM answers a LEFT JOIN users u ON u.id=a.user_id WHERE a.question_id = ? ORDER BY a.votes DESC').all(req.params.id);
  res.render('question', { q, answers });
});

app.post('/questions/:id/answers', requireLogin, requireNotBanned, profanityGuard(['body']), (req, res) => {
  const body = sanitizeHtml(req.body.body);
  db.prepare('INSERT INTO answers (question_id,user_id,body,votes,created_at) VALUES (?,?,?,?,datetime("now"))').run(req.params.id, req.session.user.id, body, 0);
  // add points
  db.prepare('UPDATE users SET points = points + 10 WHERE id = ?').run(req.session.user.id);
  req.flash('success', 'Answer posted.');
  res.redirect('/questions/' + req.params.id);
});

app.post('/questions/:id/vote', requireLogin, (req, res) => {
  const delta = parseInt(req.body.delta) || 0;
  db.prepare('UPDATE questions SET votes = votes + ? WHERE id = ?').run(delta, req.params.id);
  res.redirect('back');
});

app.post('/answers/:id/vote', requireLogin, (req, res) => {
  const delta = parseInt(req.body.delta) || 0;
  db.prepare('UPDATE answers SET votes = votes + ? WHERE id = ?').run(delta, req.params.id);
  res.redirect('back');
});

// --- Resources ---
app.get('/resources', (req, res) => {
  const files = db.prepare('SELECT * FROM resources ORDER BY created_at DESC').all();
  res.render('resources', { files });
});

app.post('/resources/upload', requireLogin, requireNotBanned, profanityGuard(['title']), upload.single('file'), (req, res) => {
  const title = sanitizeHtml(req.body.title || req.file.originalname);
  const pathOnDisk = path.relative(__dirname, req.file.path);
  db.prepare('INSERT INTO resources (user_id,title,filename,filepath,created_at) VALUES (?,?,?,?,datetime("now"))').run(req.session.user.id, title, req.file.filename, pathOnDisk);
  // reward uploader
  db.prepare('UPDATE users SET points = points + 20 WHERE id = ?').run(req.session.user.id);
  req.flash('success', 'Resource uploaded.');
  res.redirect('/resources');
});

app.get('/uploads/:file', (req, res) => {
  const f = db.prepare('SELECT * FROM resources WHERE filename = ?').get(req.params.file);
  if (!f) return res.status(404).send('File not found');
  res.sendFile(path.join(__dirname, 'uploads', f.filename));
});

// --- Community posts (simple) ---
app.get('/community', (req, res) => {
  const posts = db.prepare('SELECT p.*, u.name AS author FROM posts p LEFT JOIN users u ON u.id=p.user_id ORDER BY p.created_at DESC').all();
  res.render('community', { posts });
});

app.post('/community', requireLogin, requireNotBanned, profanityGuard(['body']), (req, res) => {
  const body = sanitizeHtml(req.body.body || '');
  db.prepare('INSERT INTO posts (user_id,body,created_at) VALUES (?,?,datetime("now"))').run(req.session.user.id, body);
  db.prepare('UPDATE users SET points = points + 5 WHERE id = ?').run(req.session.user.id);
  req.flash('success', 'Posted to community.');
  res.redirect('/community');
});

// --- Profile ---

//main
/*app.get('/profile/:id?', (req, res) => {
  const id = req.params.id || (req.session.user && req.session.user.id);
  if (!id) return res.redirect('/login');
  const user = db.prepare('SELECT id,name,email,strand,year_level,points,is_admin,offense_count,ban_until FROM users WHERE id = ?').get(id);
  const questions = db.prepare('SELECT * FROM questions WHERE user_id = ? ORDER BY created_at DESC').all(id);
  const answers = db.prepare('SELECT a.*, q.title FROM answers a LEFT JOIN questions q ON q.id=a.question_id WHERE a.user_id = ? ORDER BY a.created_at DESC').all(id);
  res.render('profile', { user, questions, answers });
});
//
*/

// Route kapag may ID sa URL
app.get('/profile/:id', (req, res) => {
  const id = req.params.id;
  if (!id) return res.redirect('/login');
  const user = db.prepare('SELECT id,name,email,strand,year_level,points,is_admin,offense_count,ban_until FROM users WHERE id = ?').get(id);
  const questions = db.prepare('SELECT * FROM questions WHERE user_id = ? ORDER BY created_at DESC').all(id);
  const answers = db.prepare('SELECT a.*, q.title FROM answers a LEFT JOIN questions q ON q.id=a.question_id WHERE a.user_id = ? ORDER BY a.created_at DESC').all(id);
  res.render('profile', { user, questions, answers });
});

// Route kapag walang ID (gagamitin yung session user)
app.get('/profile', (req, res) => {
  const id = req.session.user && req.session.user.id;
  if (!id) return res.redirect('/login');
  const user = db.prepare('SELECT id,name,email,strand,year_level,points,is_admin,offense_count,ban_until FROM users WHERE id = ?').get(id);
  const questions = db.prepare('SELECT * FROM questions WHERE user_id = ? ORDER BY created_at DESC').all(id);
  const answers = db.prepare('SELECT a.*, q.title FROM answers a LEFT JOIN questions q ON q.id=a.question_id WHERE a.user_id = ? ORDER BY a.created_at DESC').all(id);
  res.render('profile', { user, questions, answers });
});


// --- Admin Panel ---
app.get('/admin', requireAdmin, (req, res) => {
  const users = db.prepare('SELECT id,name,email,points,is_admin,offense_count,ban_until FROM users ORDER BY points DESC').all();
  const resources = db.prepare('SELECT * FROM resources ORDER BY created_at DESC').all();
  res.render('admin', { users, resources });
});

app.post('/admin/users/:id/promote', requireAdmin, (req, res) => {
  db.prepare('UPDATE users SET is_admin = 1 WHERE id = ?').run(req.params.id);
  req.flash('success', 'User promoted to admin.');
  res.redirect('/admin');
});

app.post('/admin/users/:id/demote', requireAdmin, (req, res) => {
  db.prepare('UPDATE users SET is_admin = 0 WHERE id = ?').run(req.params.id);
  req.flash('success', 'User demoted.');
  res.redirect('/admin');
});

app.post('/admin/resources/:id/delete', requireAdmin, (req, res) => {
  const r = db.prepare('SELECT * FROM resources WHERE id = ?').get(req.params.id);
  if (r) {
    try { fs.unlinkSync(path.join(__dirname, r.filepath)); } catch(e) {}
    db.prepare('DELETE FROM resources WHERE id = ?').run(req.params.id);
  }
  req.flash('success', 'Resource deleted.');
  res.redirect('/admin');
});

// --- Start ---
const PORT = process.env.PORT || 1000;
app.listen(PORT, () => console.log('Server started on port', PORT));
