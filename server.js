const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ limit: '25mb', extended: true }));
app.use(express.static('.'));

/* --------------------------------------------------------------------------
   Database Connection (Cloud SQL & MySQL 8.4 Compatible)
-------------------------------------------------------------------------- */
const db = mysql.createPool({
    host: process.env.DB_HOST || '8.234.64.212',                // Cloud SQL Public IP
    user: process.env.DB_USER || 'free-trial-first-project',    // Updated DB User
    password: process.env.DB_PASSWORD || 'Anmol@2003',          // DB Password
    database: process.env.DB_NAME || 'anmol_portal_ab',         // DB Name
    waitForConnections: true,
    connectionLimit: 10,
    ssl: {
        rejectUnauthorized: false
    },
    authPlugins: {
        mysql_clear_password: () => () => Buffer.from('Anmol@2003')
    }
});

const JWT_SECRET = process.env.JWT_SECRET || 'anmol_super_secret_jwt_key_2026';

// Test Database Connection & Tables Setup
db.getConnection((err, connection) => {
    if (err) {
        console.error('❌ Table setup fail hua: ' + err.message);
    } else {
        console.log('✓ Database se successfully connection jud gaya hai!');
        
        // Create basic tables if not exist
        const createUsersTable = `
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role VARCHAR(50) DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `;
        
        connection.query(createUsersTable, (tableErr) => {
            if (tableErr) {
                console.error('❌ Users table creation error:', tableErr.message);
            } else {
                console.log('✅ Tables ready');
            }
        });

        // 🆕 Material user pending-registration requests (Anmol_material_entry_secure.html
        // ke "रजिस्ट्रेशन अनुरोध भेजें" form se yahan aata hai, admin approve karta hai)
        const createMaterialRequestsTable = `
            CREATE TABLE IF NOT EXISTS material_user_requests (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                village VARCHAR(255),
                address VARCHAR(500),
                email VARCHAR(255),
                mobile VARCHAR(20) NOT NULL,
                photo LONGTEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `;
        connection.query(createMaterialRequestsTable, (tableErr) => {
            if (tableErr) console.error('❌ material_user_requests table error:', tableErr.message);
        });

        // 🆕 Approved material users / agents (jinhe userId + password mil chuka hai
        // aur jo Anmol_material_entry_secure.html se login karke bill entry karte hain)
        const createMaterialUsersTable = `
            CREATE TABLE IF NOT EXISTS material_users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                userId VARCHAR(50) UNIQUE NOT NULL,
                name VARCHAR(255) NOT NULL,
                village VARCHAR(255),
                address VARCHAR(500),
                email VARCHAR(255),
                mobile VARCHAR(20) UNIQUE NOT NULL,
                photo LONGTEXT,
                password_hash VARCHAR(255),
                status VARCHAR(20) DEFAULT 'active',
                blockedReason VARCHAR(500),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `;
        connection.query(createMaterialUsersTable, (tableErr) => {
            if (tableErr) console.error('❌ material_users table error:', tableErr.message);
            connection.release();
        });
    }
});

// ── Helpers: MU0001-style userId aur ek random 6-char password ──
function genMaterialUserId(cb) {
    db.query("SELECT userId FROM material_users WHERE userId LIKE 'MU%'", (err, rows) => {
        if (err) return cb(err);
        let max = 0;
        (rows || []).forEach(r => {
            const num = parseInt(String(r.userId).replace('MU', ''), 10) || 0;
            if (num > max) max = num;
        });
        cb(null, 'MU' + String(max + 1).padStart(3, '0'));
    });
}
function genMuPassword() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let pwd = '';
    for (let i = 0; i < 6; i++) pwd += chars.charAt(Math.floor(Math.random() * chars.length));
    return pwd;
}

// ══════════════════════════════════════════════════════════════════
// 🆕 MATERIAL USER / AGENT REGISTRATION & LOGIN ROUTES
//   (Anmol_material_entry_secure.html + Admin_panel_Login.html isi
//   se judte hain — pehle ye routes missing the, isliye 404 aata tha)
// ══════════════════════════════════════════════════════════════════

// 1) Public self-registration request (material_entry portal ka form)
app.post('/api/material/register', (req, res) => {
    const { name, village, address, email, mobile, photo } = req.body || {};
    if (!name || !village || !address || !email || !mobile) {
        return res.status(400).json({ error: 'Saari zaroori fields bharein.' });
    }
    const dupSql = `SELECT id FROM material_users WHERE mobile = ?
                     UNION SELECT id FROM material_user_requests WHERE mobile = ?`;
    db.query(dupSql, [mobile, mobile], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        if (rows && rows.length) {
            return res.status(409).json({ error: 'Yeh mobile number pehle se registered ya pending mein hai.' });
        }
        db.query(
            'INSERT INTO material_user_requests (name, village, address, email, mobile, photo) VALUES (?,?,?,?,?,?)',
            [name, village, address, email, mobile, photo || null],
            (insErr) => {
                if (insErr) return res.status(500).json({ error: 'DB error: ' + insErr.message });
                res.status(201).json({ success: true });
            }
        );
    });
});

// 2) Admin: pending requests list
app.get('/api/material/requests', (req, res) => {
    db.query('SELECT * FROM material_user_requests ORDER BY created_at DESC', (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        res.json(rows || []);
    });
});

// 3) Admin: approve a request → generates userId + password, moves it into material_users
app.post('/api/material/requests/:id/approve', (req, res) => {
    const reqId = req.params.id;
    db.query('SELECT * FROM material_user_requests WHERE id = ?', [reqId], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        if (!rows || !rows.length) return res.status(404).json({ error: 'Request nahi mili.' });
        const r = rows[0];
        genMaterialUserId((idErr, userId) => {
            if (idErr) return res.status(500).json({ error: 'DB error: ' + idErr.message });
            const plainPassword = genMuPassword();
            const passwordHash = bcrypt.hashSync(plainPassword, 10);
            db.query(
                `INSERT INTO material_users (userId, name, village, address, email, mobile, photo, password_hash, status)
                 VALUES (?,?,?,?,?,?,?,?, 'active')`,
                [userId, r.name, r.village, r.address, r.email, r.mobile, r.photo, passwordHash],
                (insErr) => {
                    if (insErr) return res.status(500).json({ error: 'DB error: ' + insErr.message });
                    db.query('DELETE FROM material_user_requests WHERE id = ?', [reqId], () => {
                        res.json({ userId, password: plainPassword });
                    });
                }
            );
        });
    });
});

// 4) Admin: reject/delete a pending request
app.post('/api/material/requests/:id/reject', (req, res) => {
    db.query('DELETE FROM material_user_requests WHERE id = ?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        res.json({ success: true });
    });
});

// 5) Admin: list all material users (Admin Panel table)
app.get('/api/material/users', (req, res) => {
    db.query('SELECT id, userId, name, village, address, email, mobile, photo, status, blockedReason, created_at FROM material_users ORDER BY created_at DESC', (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        const mapped = (rows || []).map(u => Object.assign({ _docId: String(u.id) }, u));
        res.json(mapped);
    });
});

// 6) Admin: directly create a material user (bina request ke, "New Material User Register" form)
app.post('/api/material/users', (req, res) => {
    const { name, village, mobile, photo, status } = req.body || {};
    if (!name || !village || !mobile) {
        return res.status(400).json({ error: 'Naam, Village aur Mobile zaroori hai!' });
    }
    db.query('SELECT id FROM material_users WHERE mobile = ?', [mobile], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        if (rows && rows.length) return res.status(409).json({ error: 'Yeh mobile number pehle se registered hai!' });
        genMaterialUserId((idErr, userId) => {
            if (idErr) return res.status(500).json({ error: 'DB error: ' + idErr.message });
            const passwordHash = bcrypt.hashSync(genMuPassword(), 10);
            db.query(
                `INSERT INTO material_users (userId, name, village, mobile, photo, password_hash, status)
                 VALUES (?,?,?,?,?,?,?)`,
                [userId, name, village, mobile, photo || null, passwordHash, status || 'active'],
                (insErr) => {
                    if (insErr) return res.status(500).json({ error: 'DB error: ' + insErr.message });
                    res.status(201).json({ userId });
                }
            );
        });
    });
});

// 7) Admin: edit / block / unblock a material user
app.put('/api/material/users/:id', (req, res) => {
    const fields = req.body || {};
    const allowed = ['name', 'village', 'address', 'email', 'mobile', 'photo', 'status', 'blockedReason'];
    const sets = [];
    const values = [];
    allowed.forEach(f => {
        if (Object.prototype.hasOwnProperty.call(fields, f)) {
            sets.push(f + ' = ?');
            values.push(fields[f]);
        }
    });
    if (!sets.length) return res.status(400).json({ error: 'Update karne ke liye kuch bhi nahi bheja gaya.' });
    values.push(req.params.id);
    db.query(`UPDATE material_users SET ${sets.join(', ')} WHERE id = ?`, values, (err) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        res.json({ success: true });
    });
});

// 8) Material user login (userId + mobile-number-or-admin-issued-password)
app.post('/api/material/login', (req, res) => {
    const { userId, secondFactor } = req.body || {};
    if (!userId || !secondFactor) return res.status(400).json({ error: 'User ID aur Mobile/Password dono zaroori hain.' });
    db.query('SELECT * FROM material_users WHERE userId = ?', [userId], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        if (!rows || !rows.length) return res.status(404).json({ error: 'Yeh User ID registered nahi hai.' });
        const u = rows[0];
        if (u.status === 'blocked') {
            return res.status(403).json({ error: 'Yeh ID admin dwara block kar di gayi hai.' });
        }
        const mobileMatches = String(u.mobile || '').replace(/\D/g, '').slice(-10) === String(secondFactor).replace(/\D/g, '').slice(-10);
        const passwordMatches = u.password_hash ? bcrypt.compareSync(secondFactor, u.password_hash) : false;
        if (!mobileMatches && !passwordMatches) {
            return res.status(401).json({ error: 'Galat Mobile Number ya Password.' });
        }
        const token = jwt.sign({ userId: u.userId, role: 'material_user' }, JWT_SECRET, { expiresIn: '7d' });
        const { password_hash, ...userSafe } = u;
        userSafe._docId = String(u.id);
        res.json({ user: userSafe, token });
    });
});

// Basic Routes
app.get('/', (req, res) => {
    res.send('Library App Backend is running successfully!');
});

// 🆕 HEALTH CHECK ROUTE — frontend ka status dot (Admin/Agent/HRMS/Student
// portal ke '☁️ Render' indicator) isi route ko har 10 second mein poll
// karta hai (API_BASE + '/health' → '/api/health'). Pehle ye route missing
// tha, isliye fetch 404 deta tha aur dot hamesha red rehta tha.
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        running: true,
        db: db ? 'configured' : 'not configured',
        timestamp: new Date().toISOString()
    });
});

// Start Server
app.listen(PORT, () => {
    console.log(`🚀 Server chalu hua port ${PORT} par`);
});
