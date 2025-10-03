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
const dbDir = path.join(__dirname, 'db');
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir);
const db = new Database(path.join(dbDir, 'app.db'));

// --- Auto-create tables ---
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    strand TEXT,
    year_level TEXT,
    points INTEGER DEFAULT 0,
    is_admin INTEGER DEFAULT 0,
    offense_count INTEGER DEFAULT 0,
    ban_until DATETIME,
    is_verified INTEGER DEFAULT 0,
    verification_token TEXT,
    token_expires DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS questions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    body TEXT,
    subject TEXT,
    tags TEXT,
    votes INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS answers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    question_id INTEGER NOT NULL,
    body TEXT NOT NULL,
    votes INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (question_id) REFERENCES questions(id)
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    filename TEXT NOT NULL,
    filepath TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    body TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS answer_votes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  answer_id INTEGER,
  user_id INTEGER,
  UNIQUE(answer_id, user_id)
  )
`).run();

// Ensure users table has ban fields
db.prepare(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  email TEXT UNIQUE,
  password TEXT,
  points INTEGER DEFAULT 0,
  offense_count INTEGER DEFAULT 0,
  ban_until TEXT,
  is_admin INTEGER DEFAULT 0,
  is_verified INTEGER DEFAULT 0
)`).run();


console.log("✅ Database and tables are ready!");


// --- Seed initial admin user ---
async function seedAdmin() {
  const adminEmail = process.env.ADMIN_EMAIL;
  const adminPass = process.env.ADMIN_PASSWORD;

  if (adminEmail && adminPass) {
    const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(adminEmail);
    if (!exists) {
      const hash = await bcrypt.hash(adminPass, 10);
      db.prepare(`INSERT INTO users (name, email, password, is_admin, is_verified) 
                  VALUES (?, ?, ?, 1, 1)`)
        .run("Administrator", adminEmail, hash);
      console.log(`✅ Admin account created: ${adminEmail}`);
    } else {
      console.log(`ℹ️ Admin already exists: ${adminEmail}`);
    }
  }
}
seedAdmin();


// --- Express app setup ---
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

app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  res.locals.success = req.flash('success');
  res.locals.error = req.flash('error');
  next();
});

// --- Uploads ---
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, unique + '-' + file.originalname.replace(/[^a-zA-Z0-9.\- _]/g, ''));
  }
});
const upload = multer({ storage });

// --- Email (nodemailer) setup ---
function getMailer() {
  if (!process.env.SMTP_HOST) return null;
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

// --- Profanity filter ---
const bannedWordsFile = path.join(__dirname, 'banned-words.txt');
function loadBannedWords() {
  try {
    const txt = fs.readFileSync(bannedWordsFile, 'utf-8');
    return txt.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  } catch { return []; }
}
function containsBanned(text) {
  if (!text) return null;
  const words = loadBannedWords();
  const lowered = text.toLowerCase();
  for (let w of words) {
    const re = new RegExp(`\\b${w}\\b`, 'i');
    if (re.test(lowered)) return w;
  }
  return null;
}
function applyBan(userId) {
  const u = db.prepare('SELECT offense_count FROM users WHERE id = ?').get(userId);
  const current = u ? u.offense_count : 0;
  const newCount = current + 1;
  let minutes = newCount === 1 ? 10 : newCount === 2 ? 60 : 60*24;
  const until = new Date(Date.now() + minutes*60000).toISOString();
  db.prepare('UPDATE users SET offense_count=?, ban_until=? WHERE id=?')
    .run(newCount, until, userId);
  return { newCount, until };
}
function checkUserBanned(user) {
  if (!user || !user.ban_until) return false;
  return new Date(user.ban_until) > new Date();
}
function requireNotBanned(req, res, next) {
  if (!req.session.user) return next();
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.session.user.id);
  if (u && checkUserBanned(u)) {
    req.flash('error', 'You are banned until ' + u.ban_until);
    return res.redirect('back');
  }
  next();
}
function profanityGuard(fields) {
  return (req, res, next) => {
    const user = req.session.user;
    const text = fields.map(f => req.body[f] || '').join(' ');
    const found = containsBanned(text);
    if (found) {
      if (user) {
        const r = applyBan(user.id);
        req.flash('error', `Banned word (${found}) detected. Offense #${r.newCount}. Banned until ${r.until}`);
      } else {
        req.flash('error', `Banned word detected: ${found}`);
      }
      return res.redirect('back');
    }
    next();
  };
}

// --- Helpers ---
function requireLogin(req, res, next) {
  if (!req.session.user) {
    req.flash('error', 'Please log in first.');
    return res.redirect('/login');
  }
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || !req.session.user.is_admin) {
    req.flash('error', 'Admin access required.');
    return res.redirect('/login');
  }
  next();
}

// --- Routes ---
// Home
app.get('/', (req, res) => {
  const featured = db.prepare(`
    SELECT q.id, q.title, COUNT(a.id) AS answers
    FROM questions q LEFT JOIN answers a ON a.question_id=q.id
    GROUP BY q.id ORDER BY q.votes DESC LIMIT 5
  `).all();
  res.render('home', { featured });
});

// Register / Verify / Login
app.get('/register', (req,res)=>res.render('register'));
app.post('/register', profanityGuard(['name']), async (req,res)=>{
  const {name,email,password,strand,year_level}=req.body;
  if (!name||!email||!password){ req.flash('error','Required fields missing'); return res.redirect('/register'); }
  if (db.prepare('SELECT id FROM users WHERE email=?').get(email)){ req.flash('error','Email already used'); return res.redirect('/register'); }
  const hash = await bcrypt.hash(password,10);
  const token=crypto.randomBytes(24).toString('hex');
  const expires=new Date(Date.now()+86400000).toISOString();
  db.prepare('INSERT INTO users(name,email,password,strand,year_level,verification_token,token_expires) VALUES (?,?,?,?,?,?,?)')
    .run(name,email,hash,strand||'',year_level||'',token,expires);
  const base=process.env.BASE_URL||(`${req.protocol}://${req.get('host')}`);
  const link=base+'/verify?token='+token;
  const mailer=getMailer();
  if(mailer){
    try{await mailer.sendMail({from:process.env.SMTP_USER,to:email,subject:'Verify your account',text:`Hi ${name}, click to verify: ${link}`});}
    catch{console.log('Verification link:',link);}
  } else console.log('Verification link:',link);
  req.flash('success','Registered! Check email for verification link.');
  res.redirect('/login');
});
app.get('/verify',(req,res)=>{
  const {token}=req.query;
  const user=db.prepare('SELECT * FROM users WHERE verification_token=?').get(token);
  if(!user){req.flash('error','Invalid token');return res.redirect('/');}
  if(new Date(user.token_expires)<new Date()){req.flash('error','Token expired');return res.redirect('/');}
  db.prepare('UPDATE users SET is_verified=1,verification_token=NULL,token_expires=NULL WHERE id=?').run(user.id);
  req.flash('success','Verified! Please log in.');
  res.redirect('/login');
});
app.get('/login',(req,res)=>res.render('login'));
app.post('/login',async (req,res)=>{
  const {email,password}=req.body;
  const u=db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if(!u||!(await bcrypt.compare(password,u.password))){req.flash('error','Invalid login');return res.redirect('/login');}
  if(!u.is_verified){req.flash('error','Verify email first');return res.redirect('/login');}
  if(u.ban_until&&new Date(u.ban_until)>new Date()){req.flash('error','Banned until '+u.ban_until);return res.redirect('/login');}
  req.session.user={id:u.id,name:u.name,email:u.email,is_admin:u.is_admin,points:u.points,strand:u.strand,year_level:u.year_level};
  req.flash('success','Logged in');res.redirect('/');
});
app.post('/logout',(req,res)=>{req.session.destroy(()=>res.redirect('/'));});

// Forum
app.get('/forum',(req,res)=>{
  const qs=db.prepare(`
    SELECT q.*, u.name AS author, COUNT(a.id) AS answers
    FROM questions q
    LEFT JOIN users u ON u.id=q.user_id
    LEFT JOIN answers a ON a.question_id=q.id
    GROUP BY q.id ORDER BY q.created_at DESC
  `).all();
  res.render('forum',{questions:qs});
});
app.get('/questions/new',requireLogin,(req,res)=>res.render('ask'));
app.post('/questions',requireLogin,requireNotBanned,profanityGuard(['title','body']),(req,res)=>{
  const {title,body,subject,tags}=req.body;
  db.prepare('INSERT INTO questions(user_id,title,body,subject,tags) VALUES (?,?,?,?,?)')
    .run(req.session.user.id,sanitizeHtml(title),sanitizeHtml(body),subject||'',tags||'');
  req.flash('success','Question posted');res.redirect('/forum');
});
app.get('/questions/:id',(req,res)=>{
  const q=db.prepare('SELECT q.*,u.name AS author FROM questions q LEFT JOIN users u ON u.id=q.user_id WHERE q.id=?').get(req.params.id);
  if(!q)return res.status(404).send('Not found');
  const ans=db.prepare('SELECT a.*,u.name AS author FROM answers a LEFT JOIN users u ON u.id=a.user_id WHERE a.question_id=?').all(req.params.id);
  res.render('question',{q,answers:ans});
});
app.post('/questions/:id/answers',requireLogin,requireNotBanned,profanityGuard(['body']),(req,res)=>{
  db.prepare('INSERT INTO answers(question_id,user_id,body) VALUES (?,?,?)')
    .run(req.params.id,req.session.user.id,sanitizeHtml(req.body.body));
  db.prepare('UPDATE users SET points=points+10 WHERE id=?').run(req.session.user.id);
  res.redirect('/questions/'+req.params.id);
});

// Resources
app.get('/resources',(req,res)=>{
  const files=db.prepare('SELECT * FROM resources ORDER BY created_at DESC').all();
  res.render('resources',{files});
});
app.post('/resources/upload',requireLogin,requireNotBanned,upload.single('file'),(req,res)=>{
  const title=sanitizeHtml(req.body.title||req.file.originalname);
  const filepath=path.relative(__dirname,req.file.path);
  db.prepare('INSERT INTO resources(user_id,title,filename,filepath) VALUES (?,?,?,?)')
    .run(req.session.user.id,title,req.file.filename,filepath);
  db.prepare('UPDATE users SET points=points+20 WHERE id=?').run(req.session.user.id);
  res.redirect('/resources');
});
app.get('/uploads/:file',(req,res)=>{
  const f=db.prepare('SELECT * FROM resources WHERE filename=?').get(req.params.file);
  if(!f)return res.status(404).send('Not found');
  res.sendFile(path.join(__dirname,'uploads',f.filename));
});

// Community
app.get('/community',(req,res)=>{
  const posts=db.prepare('SELECT p.*,u.name AS author FROM posts p LEFT JOIN users u ON u.id=p.user_id ORDER BY p.created_at DESC').all();
  res.render('community',{posts});
});
app.post('/community',requireLogin,requireNotBanned,profanityGuard(['body']),(req,res)=>{
  db.prepare('INSERT INTO posts(user_id,body) VALUES (?,?)')
    .run(req.session.user.id,sanitizeHtml(req.body.body||''));
  db.prepare('UPDATE users SET points=points+5 WHERE id=?').run(req.session.user.id);
  res.redirect('/community');
});

// Profile
app.get('/profile/:id',(req,res)=>{
  const u=db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);
  if(!u)return res.redirect('/login');
  const qs=db.prepare('SELECT * FROM questions WHERE user_id=?').all(u.id);
  const ans=db.prepare('SELECT a.*,q.title FROM answers a LEFT JOIN questions q ON q.id=a.question_id WHERE a.user_id=?').all(u.id);
  res.render('profile',{user:u,questions:qs,answers:ans});
});
app.get('/profile',(req,res)=>{
  if(!req.session.user)return res.redirect('/login');
  res.redirect('/profile/'+req.session.user.id);
});

// Admin
app.get('/admin',requireAdmin,(req,res)=>{
  const users=db.prepare('SELECT * FROM users ORDER BY points DESC').all();
  const resources=db.prepare('SELECT * FROM resources ORDER BY created_at DESC').all();
  res.render('admin',{users,resources});
});
app.post('/admin/users/:id/promote',requireAdmin,(req,res)=>{
  db.prepare('UPDATE users SET is_admin=1 WHERE id=?').run(req.params.id);
  res.redirect('/admin');
});
app.post('/admin/users/:id/demote',requireAdmin,(req,res)=>{
  db.prepare('UPDATE users SET is_admin=0 WHERE id=?').run(req.params.id);
  res.redirect('/admin');
});
app.post('/admin/resources/:id/delete',requireAdmin,(req,res)=>{
  const r=db.prepare('SELECT * FROM resources WHERE id=?').get(req.params.id);
  if(r) {
    try{fs.unlinkSync(path.join(__dirname,r.filepath));}catch{}
    db.prepare('DELETE FROM resources WHERE id=?').run(req.params.id);
  }
  res.redirect('/admin');
});


// Ban user (Admin only)
app.post('/admin/users/:id/ban', requireAdmin, (req, res) => {
  const id = req.params.id;
  const duration = req.body.duration || 60; // minutes (default: 60 mins)

  const banUntil = new Date(Date.now() + duration * 60000).toISOString();

  db.prepare('UPDATE users SET ban_until = ?, offense_count = offense_count + 1 WHERE id = ?')
    .run(banUntil, id);

  req.flash('success', `User banned for ${duration} minutes.`);
  res.redirect('/admin');
});

// Unban user (Admin only)
app.post('/admin/users/:id/unban', requireAdmin, (req, res) => {
  const id = req.params.id;
  db.prepare('UPDATE users SET ban_until = NULL WHERE id = ?').run(id);
  req.flash('success', 'User unbanned.');
  res.redirect('/admin');
});



// Delete user (Admin only)
app.post('/admin/users/:id/delete', requireAdmin, (req, res) => {
  const id = req.params.id;
  
  // una i-delete yung answers, questions, posts niya para clean
  db.prepare('DELETE FROM answers WHERE user_id = ?').run(id);
  db.prepare('DELETE FROM questions WHERE user_id = ?').run(id);
  db.prepare('DELETE FROM posts WHERE user_id = ?').run(id);
  db.prepare('DELETE FROM resources WHERE user_id = ?').run(id);

  // tapos i-delete na yung user
  db.prepare('DELETE FROM users WHERE id = ?').run(id);

  req.flash('success', 'User deleted successfully.');
  res.redirect('/admin');
});


// ✅ Vote on an answer
app.post('/answers/:id/vote', requireLogin, (req, res) => {
  const answerId = req.params.id;
  const userId = req.session.user.id;

  // Check if user already voted
  const existing = db.prepare(
    'SELECT * FROM answer_votes WHERE answer_id = ? AND user_id = ?'
  ).get(answerId, userId);

  if (existing) {
    req.flash('error', 'You already voted on this answer.');
    return res.redirect('back');
  }

  // Add vote
  db.prepare(
    'INSERT INTO answer_votes (answer_id, user_id) VALUES (?, ?)'
  ).run(answerId, userId);

  // Update answer points
  db.prepare(
    'UPDATE answers SET votes = votes + 1 WHERE id = ?'
  ).run(answerId);

  req.flash('success', 'Vote added!');
  res.redirect('back');
});



// --- Start server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=>console.log(`🚀 Server started on http://localhost:${PORT}`));
