/* ============================================================
   ANMOL PORTAL — COMPLETE BACKEND (Express + MySQL + Cloud Run)
   ============================================================
   Yeh file un SAARE routes ko implement karti hai jo aapki 6
   frontend files (Admin Panel, Agent Login, HRMS, Student
   Attendance, Material Entry, index.html) call karti hain.

   ⚠️ IMPORTANT NOTE:
   Kuch financial/wallet routes (withdraw, razorpay, salary-claims)
   ka EXACT business-logic (jaise interest calculation, min balance
   rules, etc.) sirf frontend code dekh kar 100% guess nahi ho
   sakta — maine reasonable/safe defaults likhe hain jo kaam
   karenge, lekin agar aapke paas koi purana/dusra backend hai
   jisme yeh logic pehle se tha, use zaroor cross-check kar lein.
   ============================================================ */

const express = require('express');
const mysql   = require('mysql2/promise');
const cors    = require('cors');
const jwt     = require('jsonwebtoken');
const multer  = require('multer');
const path    = require('path');
const fs      = require('fs');

const app = express();

/* ---------------------------------------------------------
   1) CORS — sabse pehle, saare routes se upar
   --------------------------------------------------------- */
app.use(cors({
  origin: '*',   // production me chahen to apni exact Netlify URL daal dein
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '25mb' }));
app.use(express.static('.'));

/* ---------------------------------------------------------
   2) Database connection
   --------------------------------------------------------- */
const db = mysql.createPool({
  host: process.env.DB_HOST || '34.93.x.x',        // <-- apna Cloud SQL IP daalein
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'YOUR_PASSWORD',  // <-- apna password daalein
  database: process.env.DB_NAME || 'anmol_portal_ab',
  waitForConnections: true,
  connectionLimit: 10
});

const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';

/* ---------------------------------------------------------
   3) Tables (agar exist nahi karti to khud ban jaayengi)
   --------------------------------------------------------- */
async function initTables() {
  const stmts = [
    `CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      role VARCHAR(30) NOT NULL,
      username VARCHAR(120) NOT NULL,
      password VARCHAR(255) NOT NULL,
      name VARCHAR(150),
      extra JSON,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY uniq_role_username (role, username)
    )`,
    `CREATE TABLE IF NOT EXISTS entities (
      entity_key VARCHAR(60) PRIMARY KEY,
      data JSON,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS blobs (
      blob_key VARCHAR(60) PRIMARY KEY,
      data JSON,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS site_data (
      data_key VARCHAR(80) PRIMARY KEY,
      value JSON,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS material_users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id VARCHAR(40) UNIQUE,
      name VARCHAR(150), village VARCHAR(150), address VARCHAR(255),
      email VARCHAR(150), mobile VARCHAR(15), photo LONGTEXT,
      password VARCHAR(100),
      status VARCHAR(20) DEFAULT 'pending',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS material_bills (
      id INT AUTO_INCREMENT PRIMARY KEY,
      owner_user_id VARCHAR(40),
      bill_no VARCHAR(60),
      data JSON,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      UNIQUE KEY uniq_owner_bill (owner_user_id, bill_no)
    )`,
    `CREATE TABLE IF NOT EXISTS wallets (
      user_id VARCHAR(80) PRIMARY KEY,
      role VARCHAR(30),
      name VARCHAR(150),
      balance DECIMAL(12,2) DEFAULT 0,
      withdraw_pending DECIMAL(12,2) DEFAULT 0,
      total_withdrawn DECIMAL(12,2) DEFAULT 0,
      total_earned DECIMAL(12,2) DEFAULT 0
    )`,
    `CREATE TABLE IF NOT EXISTS withdrawals (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id VARCHAR(80), agent_name VARCHAR(150),
      amount DECIMAL(12,2), acc_name VARCHAR(150), bank_name VARCHAR(150),
      acc_no VARCHAR(40), ifsc VARCHAR(20),
      status VARCHAR(20) DEFAULT 'pending', reason VARCHAR(255),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      processed_at DATETIME NULL
    )`,
    `CREATE TABLE IF NOT EXISTS direct_payments (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id VARCHAR(80), amount DECIMAL(12,2), purpose VARCHAR(60),
      razorpay_order_id VARCHAR(80), razorpay_payment_id VARCHAR(80),
      status VARCHAR(20) DEFAULT 'created',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS salary_claims (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id VARCHAR(80), role VARCHAR(30), amount DECIMAL(12,2),
      data JSON, status VARCHAR(20) DEFAULT 'pending', reason VARCHAR(255),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS hrms_slips (
      id INT AUTO_INCREMENT PRIMARY KEY,
      staff_id VARCHAR(80), month VARCHAR(20), data JSON,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS fee_payments (
      id INT AUTO_INCREMENT PRIMARY KEY,
      student_id VARCHAR(80), mobile VARCHAR(15), amount DECIMAL(12,2),
      method VARCHAR(30), note VARCHAR(255), month_key VARCHAR(20),
      status VARCHAR(20) DEFAULT 'paid',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS student_transactions (
      id INT AUTO_INCREMENT PRIMARY KEY,
      student_id VARCHAR(80), data JSON,
      status VARCHAR(20) DEFAULT 'pending', reason VARCHAR(255),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS attendance (
      id INT AUTO_INCREMENT PRIMARY KEY,
      student_id VARCHAR(80), att_date DATE, status VARCHAR(20),
      data JSON,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY uniq_student_date (student_id, att_date)
    )`
  ];
  for (const s of stmts) await db.query(s);
  console.log('✅ Tables ready');
}

/* ---------------------------------------------------------
   4) Helpers
   --------------------------------------------------------- */
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' });
}
// Lenient auth: token ho to decode karke req.user set kar dete hain,
// lekin route ko block nahi karte agar token missing/invalid ho —
// kyunki frontend abhi kai jagah "best-effort" bridge token bhejta hai.
function softAuth(req, _res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (token) {
    try { req.user = jwt.verify(token, JWT_SECRET); } catch (e) { /* ignore */ }
  }
  next();
}
app.use(softAuth);

function genUserId() {
  return 'MU' + Math.floor(100000 + Math.random() * 900000);
}
function genPassword() {
  return Math.random().toString(36).slice(-8);
}

const ALLOWED_BLOB_KEYS = ['settings', 'activity', 'notices', 'mem_plans', 'members',
  'hrms_registrations', 'staff_att', 'leave_requests', 'agent_plans', 'agent_payments',
  'razorpay_config', 'sms_api_config'];

const ALLOWED_ENTITY_KEYS = ['admins', 'staff', 'agents', 'students'];

/* ---------------------------------------------------------
   5) File uploads (site-content/upload-file)
   --------------------------------------------------------- */
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
const upload = multer({ storage: multer.diskStorage({
  destination: function (req, file, cb) {
    const folder = path.join(uploadDir, (req.body.folder || 'misc').replace(/[^a-zA-Z0-9_\-]/g, '_'));
    if (!fs.existsSync(folder)) fs.mkdirSync(folder, { recursive: true });
    cb(null, folder);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '_' + file.originalname.replace(/[^a-zA-Z0-9_.\-]/g, '_'));
  }
})});
app.use('/uploads', express.static(uploadDir));

/* ============================================================
   ROUTES
   ============================================================ */

// ── Health ──────────────────────────────────────────────────
app.get('/api/health', (req, res) => res.json({ ok: true, time: new Date().toISOString() }));

// ── Auth bridge (admin / staff / agent / student login) ──────
// Frontend apna asli password-check kar chuka hota hai (Firebase/local),
// yeh route sirf ek session token deta hai. Pehli baar aane par user
// record khud-ba-khud MySQL me bhi bana diya jaata hai.
app.post('/api/auth/login', async (req, res) => {
  try {
    const { role, username, password } = req.body;
    if (!role || !username) return res.status(400).json({ error: 'role/username required' });
    const [rows] = await db.query('SELECT * FROM users WHERE role=? AND username=?', [role, username]);
    if (rows.length === 0) {
      await db.query('INSERT INTO users (role, username, password, name) VALUES (?,?,?,?)',
        [role, username, password || '', username]);
    }
    const token = signToken({ role, username });
    res.json({ token });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Admin entities (admins / staff / agents / students) ──────
app.get('/api/admin-entities/:key', async (req, res) => {
  try {
    if (!ALLOWED_ENTITY_KEYS.includes(req.params.key)) return res.status(404).json({ error: 'Unknown key' });
    const [rows] = await db.query('SELECT data FROM entities WHERE entity_key=?', [req.params.key]);
    res.json(rows.length ? rows[0].data : []);
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/admin-entities/:key', async (req, res) => {
  try {
    if (!ALLOWED_ENTITY_KEYS.includes(req.params.key)) return res.status(404).json({ error: 'Unknown key' });
    await db.query(
      'INSERT INTO entities (entity_key, data) VALUES (?, ?) ON DUPLICATE KEY UPDATE data=VALUES(data)',
      [req.params.key, JSON.stringify(req.body)]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
// alias: GET /api/students (Student Attendance / Admin panel dono use karte hain)
app.get('/api/students', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT data FROM entities WHERE entity_key=?', ['students']);
    res.json(rows.length ? rows[0].data : []);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Generic blob store (settings, notices, mem_plans, ...) ───
app.get('/api/blob/:key', async (req, res) => {
  try {
    if (!ALLOWED_BLOB_KEYS.includes(req.params.key)) return res.status(404).json({ error: 'Unknown key' });
    const [rows] = await db.query('SELECT data FROM blobs WHERE blob_key=?', [req.params.key]);
    res.json(rows.length ? rows[0].data : null);
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/blob/:key', async (req, res) => {
  try {
    if (!ALLOWED_BLOB_KEYS.includes(req.params.key)) return res.status(404).json({ error: 'Unknown key' });
    await db.query(
      'INSERT INTO blobs (blob_key, data) VALUES (?, ?) ON DUPLICATE KEY UPDATE data=VALUES(data)',
      [req.params.key, JSON.stringify(req.body)]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.delete('/api/blob/:key', async (req, res) => {
  try {
    await db.query('DELETE FROM blobs WHERE blob_key=?', [req.params.key]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
// alias: GET /api/settings -> blob 'settings'
app.get('/api/settings', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT data FROM blobs WHERE blob_key=?', ['settings']);
    res.json(rows.length ? rows[0].data : {});
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Site data (index.html content, nav buttons, login options) ─
app.get('/api/site-data', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT data_key, value FROM site_data');
    const out = {};
    rows.forEach(r => { out[r.data_key] = r.value; });
    res.json(out);
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/site-data/:key', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT value FROM site_data WHERE data_key=?', [req.params.key]);
    res.json(rows.length ? rows[0] : null);
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/site-data/:key', async (req, res) => {
  try {
    await db.query(
      'INSERT INTO site_data (data_key, value) VALUES (?, ?) ON DUPLICATE KEY UPDATE value=VALUES(value)',
      [req.params.key, JSON.stringify(req.body.value)]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/site-content/upload-file', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const publicUrl = '/uploads/' + path.basename(req.file.destination) + '/' + req.file.filename;
  res.json({ url: publicUrl, path: req.file.path, name: req.file.originalname, size: req.file.size });
});

// ── Attendance ─────────────────────────────────────────────
app.post('/api/attendance', async (req, res) => {
  try {
    const { studentId, date, status } = req.body;
    const attDate = date || new Date().toISOString().slice(0, 10);
    await db.query(
      `INSERT INTO attendance (student_id, att_date, status, data) VALUES (?,?,?,?)
       ON DUPLICATE KEY UPDATE status=VALUES(status), data=VALUES(data)`,
      [studentId, attDate, status || 'present', JSON.stringify(req.body)]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ============================================================
   MATERIAL ENTRY PORTAL
   ============================================================ */
app.post('/api/material/register', async (req, res) => {
  try {
    const { name, village, address, email, mobile, photo } = req.body;
    if (!name || !mobile) return res.status(400).json({ error: 'name/mobile required' });
    const [dup] = await db.query(
      "SELECT id FROM material_users WHERE mobile=? AND status IN ('pending','active')", [mobile]);
    if (dup.length) return res.status(409).json({ error: 'Yeh mobile number pehle se register/pending hai.' });

    await db.query(
      `INSERT INTO material_users (user_id, name, village, address, email, mobile, photo, status)
       VALUES (NULL, ?, ?, ?, ?, ?, ?, 'pending')`,
      [name, village, address, email, mobile, photo || '']
    );
    res.json({ success: true, message: 'Registration request bhej di gayi.' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/material/login', async (req, res) => {
  try {
    const { userId, secondFactor } = req.body;
    if (!userId || !secondFactor) return res.status(400).json({ error: 'userId/secondFactor required' });
    const [rows] = await db.query('SELECT * FROM material_users WHERE user_id=?', [userId]);
    if (!rows.length) return res.status(404).json({ error: 'Yeh User ID registered nahi hai.' });
    const u = rows[0];
    if (u.status === 'blocked') return res.status(403).json({ error: 'Yeh ID block hai.' });
    if (String(u.password) !== String(secondFactor) && String(u.mobile) !== String(secondFactor)) {
      return res.status(401).json({ error: 'Galat password/mobile.' });
    }
    const token = signToken({ role: 'material_user', userId: u.user_id });
    res.json({
      token,
      user: { userId: u.user_id, name: u.name, village: u.village, mobile: u.mobile, status: u.status, docId: u.id }
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/material/users/:id', async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT * FROM material_users WHERE id=? OR user_id=?', [req.params.id, req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    const u = rows[0];
    res.json({ userId: u.user_id, name: u.name, village: u.village, mobile: u.mobile, status: u.status, photo: u.photo || '', docId: u.id });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Admin: saare (pending ke alawa) material users — listing/add/edit ──
app.get('/api/material/users', async (req, res) => {
  try {
    const [rows] = await db.query("SELECT * FROM material_users WHERE status != 'pending' ORDER BY id DESC");
    res.json(rows.map(u => ({
      _docId: String(u.id), userId: u.user_id, name: u.name, village: u.village,
      address: u.address, email: u.email, mobile: u.mobile, photo: u.photo,
      status: u.status, createdAtISO: u.created_at
    })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/material/users', async (req, res) => {
  try {
    const { name, village, mobile, photo, status } = req.body;
    if (!name || !village || !mobile) return res.status(400).json({ error: 'name/village/mobile required' });
    const [dup] = await db.query("SELECT id FROM material_users WHERE mobile=? AND status != 'pending'", [mobile]);
    if (dup.length) return res.status(409).json({ error: 'Yeh mobile number pehle se registered hai.' });
    const userId = genUserId();
    await db.query(
      `INSERT INTO material_users (user_id, name, village, mobile, photo, status) VALUES (?,?,?,?,?,?)`,
      [userId, name, village, mobile, photo || '', status || 'active']
    );
    res.json({ success: true, userId });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.put('/api/material/users/:id', async (req, res) => {
  try {
    const { name, village, mobile, status, photo, blockedReason } = req.body;
    const fields = [], vals = [];
    if (name !== undefined) { fields.push('name=?'); vals.push(name); }
    if (village !== undefined) { fields.push('village=?'); vals.push(village); }
    if (mobile !== undefined) { fields.push('mobile=?'); vals.push(mobile); }
    if (status !== undefined) { fields.push('status=?'); vals.push(status); }
    if (photo !== undefined) { fields.push('photo=?'); vals.push(photo); }
    if (!fields.length) return res.json({ success: true });
    vals.push(req.params.id);
    await db.query(`UPDATE material_users SET ${fields.join(', ')} WHERE id=?`, vals);
    res.json({ success: true, blockedReason: blockedReason || '' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.delete('/api/material/users/:id', async (req, res) => {
  try {
    await db.query('DELETE FROM material_users WHERE id=?', [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// (Admin panel ke liye — pending requests list + approve/reject. Yeh
// routes abhi Admin_panel_Login.html call NAHI karti (wo Firestore
// use karta hai), lekin future me connect karne ke liye yahan bana di
// gayi hain.)
app.get('/api/material/requests', async (req, res) => {
  try {
    const [rows] = await db.query("SELECT * FROM material_users WHERE status='pending'");
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/material/requests/:id/approve', async (req, res) => {
  try {
    const userId = genUserId(), pass = genPassword();
    await db.query("UPDATE material_users SET status='active', user_id=?, password=? WHERE id=?",
      [userId, pass, req.params.id]);
    res.json({ success: true, userId, password: pass });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/material/requests/:id/reject', async (req, res) => {
  try {
    await db.query("DELETE FROM material_users WHERE id=? AND status='pending'", [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/material/bills', async (req, res) => {
  try {
    const owner = req.query.ownerUserId;
    const [rows] = owner
      ? await db.query('SELECT id, data FROM material_bills WHERE owner_user_id=? ORDER BY id DESC', [owner])
      : await db.query('SELECT id, data FROM material_bills ORDER BY id DESC');
    res.json(rows.map(r => Object.assign({ id: r.id }, r.data)));
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/material/bills', async (req, res) => {
  try {
    const data = req.body;
    await db.query(
      `INSERT INTO material_bills (owner_user_id, bill_no, data) VALUES (?,?,?)
       ON DUPLICATE KEY UPDATE data=VALUES(data)`,
      [data.ownerUserId || '', data.billNo || ('NB' + Date.now()), JSON.stringify(data)]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.delete('/api/material/bills/:id', async (req, res) => {
  try {
    await db.query('DELETE FROM material_bills WHERE id=?', [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.put('/api/material/bills/:id', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT data FROM material_bills WHERE id=?', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    const merged = Object.assign({}, rows[0].data, req.body);
    await db.query('UPDATE material_bills SET data=? WHERE id=?', [JSON.stringify(merged), req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ============================================================
   WALLET (Agent balance / withdrawals / direct payments)
   ============================================================ */
async function getOrCreateWallet(userId, name, role) {
  const [rows] = await db.query('SELECT * FROM wallets WHERE user_id=?', [userId]);
  if (rows.length) return rows[0];
  await db.query('INSERT INTO wallets (user_id, role, name) VALUES (?,?,?)', [userId, role || '', name || '']);
  return { user_id: userId, role, name, balance: 0, withdraw_pending: 0, total_withdrawn: 0, total_earned: 0 };
}

app.get('/api/wallet/me', async (req, res) => {
  try {
    const userId = (req.user && (req.user.username || req.user.userId)) || req.query.userId;
    if (!userId) return res.status(400).json({ error: 'userId required' });
    const w = await getOrCreateWallet(userId);
    res.json(w);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/wallet/withdraw', async (req, res) => {
  const conn = await db.getConnection();
  try {
    const userId = (req.user && (req.user.username || req.user.userId)) || req.body.userId || 'unknown';
    const { amount, accName, bankName, accNo, ifsc, agentName } = req.body;
    await conn.beginTransaction();
    const [rows] = await conn.query('SELECT * FROM wallets WHERE user_id=? FOR UPDATE', [userId]);
    const wallet = rows[0] || { balance: 0, withdraw_pending: 0 };
    if (!rows.length) await conn.query('INSERT INTO wallets (user_id, name) VALUES (?,?)', [userId, agentName || '']);
    if (Number(wallet.balance) < Number(amount)) {
      await conn.rollback();
      return res.status(400).json({ error: 'Withdrawable balance se zyada amount.' });
    }
    await conn.query('UPDATE wallets SET balance = balance - ?, withdraw_pending = withdraw_pending + ? WHERE user_id=?',
      [amount, amount, userId]);
    await conn.query(
      'INSERT INTO withdrawals (user_id, agent_name, amount, acc_name, bank_name, acc_no, ifsc) VALUES (?,?,?,?,?,?,?)',
      [userId, agentName || '', amount, accName, bankName, accNo, ifsc]
    );
    await conn.commit();
    res.json({ success: true });
  } catch (err) {
    await conn.rollback();
    res.status(500).json({ error: err.message });
  } finally { conn.release(); }
});

app.get('/api/wallet/withdrawals/mine', async (req, res) => {
  try {
    const userId = (req.user && (req.user.username || req.user.userId)) || req.query.userId;
    const [rows] = await db.query('SELECT * FROM withdrawals WHERE user_id=? ORDER BY id DESC', [userId]);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/wallet/withdrawals', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM withdrawals ORDER BY id DESC');
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/wallet/withdrawal/:id/process', async (req, res) => {
  const conn = await db.getConnection();
  try {
    const { action, reason } = req.body;
    await conn.beginTransaction();
    const [rows] = await conn.query('SELECT * FROM withdrawals WHERE id=? FOR UPDATE', [req.params.id]);
    if (!rows.length) { await conn.rollback(); return res.status(404).json({ error: 'Not found' }); }
    const w = rows[0];
    if (action === 'approve') {
      await conn.query("UPDATE withdrawals SET status='paid', processed_at=NOW() WHERE id=?", [req.params.id]);
      await conn.query('UPDATE wallets SET withdraw_pending = withdraw_pending - ?, total_withdrawn = total_withdrawn + ? WHERE user_id=?',
        [w.amount, w.amount, w.user_id]);
    } else {
      await conn.query("UPDATE withdrawals SET status='rejected', reason=?, processed_at=NOW() WHERE id=?", [reason || '', req.params.id]);
      await conn.query('UPDATE wallets SET withdraw_pending = withdraw_pending - ?, balance = balance + ? WHERE user_id=?',
        [w.amount, w.amount, w.user_id]);
    }
    await conn.commit();
    res.json({ success: true });
  } catch (err) {
    await conn.rollback();
    res.status(500).json({ error: err.message });
  } finally { conn.release(); }
});

app.get('/api/wallet/my-direct-payments', async (req, res) => {
  try {
    const userId = (req.user && (req.user.username || req.user.userId)) || req.query.userId;
    const [rows] = await db.query('SELECT * FROM direct_payments WHERE user_id=? ORDER BY id DESC', [userId]);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/wallet/agent-direct-payments', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM direct_payments ORDER BY id DESC');
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/wallet/my-salary-payments', async (req, res) => {
  try {
    const userId = (req.user && (req.user.username || req.user.userId)) || req.query.userId;
    const [rows] = await db.query("SELECT * FROM salary_claims WHERE user_id=? AND status='paid' ORDER BY id DESC", [userId]);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/wallet/salary-claims/:id/verify', async (req, res) => {
  try {
    await db.query("UPDATE salary_claims SET status='paid' WHERE id=?", [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ============================================================
   PAYMENTS (Razorpay / Student fee / transactions)
   ============================================================ */
app.post('/api/payments/razorpay/order', async (req, res) => {
  try {
    // NOTE: Yahan real Razorpay SDK call honi chahiye (razorpay npm
    // package + key_id/key_secret). Abhi ek mock order id de rahe
    // hain taaki flow test ho sake — production me isse Razorpay ke
    // asli orders.create() se replace karein.
    const { amount, purpose } = req.body;
    const [result] = await db.query(
      'INSERT INTO direct_payments (user_id, amount, purpose, razorpay_order_id, status) VALUES (?,?,?,?,?)',
      [(req.user && req.user.username) || 'unknown', amount, purpose || '', 'order_' + Date.now(), 'created']
    );
    res.json({ id: 'order_' + Date.now(), amount, currency: 'INR', paymentRowId: result.insertId });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/payments/razorpay/verify', async (req, res) => {
  try {
    const { paymentRowId, razorpay_payment_id } = req.body;
    if (paymentRowId) {
      await db.query("UPDATE direct_payments SET status='paid', razorpay_payment_id=? WHERE id=?",
        [razorpay_payment_id || '', paymentRowId]);
      await db.query('UPDATE wallets SET balance = balance + (SELECT amount FROM direct_payments WHERE id=?) WHERE user_id=(SELECT user_id FROM direct_payments WHERE id=?)',
        [paymentRowId, paymentRowId]);
    }
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/payments/fee', async (req, res) => {
  try {
    const { studentId, mobile, amount, method, note, monthKey } = req.body;
    const [result] = await db.query(
      'INSERT INTO fee_payments (student_id, mobile, amount, method, note, month_key) VALUES (?,?,?,?,?,?)',
      [studentId, mobile, amount, method, note, monthKey]
    );
    res.json({ success: true, payment: { id: result.insertId, studentId, amount, method, note, monthKey, status: 'paid' } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/payments/fee', async (req, res) => {
  try {
    const studentId = req.query.studentId;
    const [rows] = await db.query('SELECT * FROM fee_payments WHERE student_id=? ORDER BY id DESC', [studentId]);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/payments/student-transaction', async (req, res) => {
  try {
    const { studentId } = req.body;
    const [result] = await db.query('INSERT INTO student_transactions (student_id, data) VALUES (?,?)',
      [studentId, JSON.stringify(req.body)]);
    res.json({ success: true, id: result.insertId });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/payments/transactions/:id/verify', async (req, res) => {
  try {
    await db.query("UPDATE student_transactions SET status='verified' WHERE id=?", [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/payments/transactions/:id/reject', async (req, res) => {
  try {
    await db.query("UPDATE student_transactions SET status='rejected', reason=? WHERE id=?",
      [req.body.reason || '', req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ============================================================
   HRMS SALARY
   ============================================================ */
app.get('/api/hrms-salary/claims', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM salary_claims ORDER BY id DESC');
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/hrms-salary/claims', async (req, res) => {
  try {
    const { userId, role, amount } = req.body;
    const [result] = await db.query('INSERT INTO salary_claims (user_id, role, amount, data) VALUES (?,?,?,?)',
      [userId || (req.user && req.user.username) || '', role || '', amount || 0, JSON.stringify(req.body)]);
    res.json({ success: true, id: result.insertId });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/hrms-salary/claims/:id/approve', async (req, res) => {
  try {
    await db.query("UPDATE salary_claims SET status='approved' WHERE id=?", [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/hrms-salary/claims/:id/reject', async (req, res) => {
  try {
    await db.query("UPDATE salary_claims SET status='rejected', reason=? WHERE id=?",
      [req.body.reason || '', req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/hrms-salary/slips', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM hrms_slips ORDER BY id DESC');
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ---------------------------------------------------------
   Generic fallback (purani /api/save/:table, /api/get/:table
   style calls agar kahin aur use ho rahi ho, unke liye)
   --------------------------------------------------------- */
app.post('/api/save/:table', async (req, res) => {
  try {
    const t = req.params.table.replace(/[^a-zA-Z0-9_]/g, '');
    await db.query(
      `CREATE TABLE IF NOT EXISTS \`${t}\` (id INT AUTO_INCREMENT PRIMARY KEY, data JSON, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`
    );
    await db.query(`INSERT INTO \`${t}\` (data) VALUES (?)`, [JSON.stringify(req.body)]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/get/:table', async (req, res) => {
  try {
    const t = req.params.table.replace(/[^a-zA-Z0-9_]/g, '');
    const [rows] = await db.query(`SELECT * FROM \`${t}\``);
    res.json({ success: true, data: rows });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

/* ---------------------------------------------------------
   Start
   --------------------------------------------------------- */
const PORT = process.env.PORT || 3000;
initTables()
  .then(() => {
    app.listen(PORT, () => console.log(`🚀 Server chalu hua port ${PORT} par`));
  })
  .catch(err => {
    console.error('❌ Table setup fail hua:', err.message);
    // DB na milne par bhi server start kar dete hain taaki /api/health
    // kaam kare aur error jald pata chal jaaye (Cloud Run logs me dikhega)
    app.listen(PORT, () => console.log(`⚠️  Server chalu (DB error ke saath) port ${PORT} par`));
  });
