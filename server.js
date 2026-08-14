const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer'); // 🆕 file upload (Hero image/Logo/APK) ke liye

const app = express();
const PORT = process.env.PORT || 3000;

// 🆕 Render ek reverse proxy ke peeche chalta hai — isके bina Express hamesha
// req.protocol ko 'http' samajhta, jisse upload-file wala absolute URL galti se
// 'http://...' ban jaata (jo HTTPS Netlify site par mixed-content block ho jaata).
app.set('trust proxy', 1);

// Middleware
// 🆕 FIX: ab CORS sirf EXPLICITLY allowed origins ke liye khulta hai. Do
// origins allowed hain: (1) Netlify site — jahan index.html/Admin Panel
// hain, aur (2) Render ka apna backend domain — kyunki ab kuch login pages
// (jaise Material Portal) '/api/pages/<slug>' se Render se hi seedhe serve
// hote hain, aur woh page bhi isi backend ko API call karta hai. Render ka
// apna domain whitelist mein na hone ki wajah se pehle yeh exact CORS error
// aa raha tha.
// NOTE: agar future mein koi custom domain jodna ho, ya Netlify deploy-preview
// URLs (jaise https://deploy-preview-3--digitallibraryanmollive.netlify.app)
// bhi allow karne hon, to bas neeche is array mein add kar dein.
const ALLOWED_ORIGINS = [
    'https://digitallibraryanmollive.netlify.app',
    'https://library-backend-4efk.onrender.com'
];
app.use(cors({
    origin: function (origin, callback) {
        // Server-to-server / curl / Postman jaisi requests mein origin header
        // hota hi nahi — unhe allow karo (koi browser CORS risk nahi hai).
        if (!origin) return callback(null, true);
        if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
        console.warn('❌ CORS blocked origin:', origin);
        return callback(new Error('CORS: is domain se access allowed nahi hai — ' + origin));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ limit: '25mb', extended: true }));
app.use(express.static('.'));

// ── Auth helper: '/auth/login' se mila JWT token decode karke
//   req.user = { role, username } set karta hai. Token na ho / invalid ho
//   to bhi request block nahi hoti (kai routes public/self-verifying hain
//   jaisa Student_Attendance.html ke comment mein likha hai) — bas
//   req.user null rehta hai. Wallet jaise identity-based routes username
//   ko hi agentId/staffId ki tarah use karte hain. ──
function getAuthUser(req) {
    try {
        const h = req.headers.authorization || '';
        const token = h.startsWith('Bearer ') ? h.slice(7) : null;
        if (!token) return null;
        return jwt.verify(token, JWT_SECRET);
    } catch (e) {
        return null;
    }
}

/* --------------------------------------------------------------------------
   Database Connection (Cloud SQL & MySQL 8.4 Compatible)
-------------------------------------------------------------------------- */
const db = mysql.createPool({
    host: process.env.DB_HOST,                 // Cloud SQL Public IP — Render Environment se aayega
    user: process.env.DB_USER,                  // DB User — Render Environment se aayega
    password: process.env.DB_PASSWORD,           // DB Password — Render Environment se aayega
    database: process.env.DB_NAME,               // DB Name — Render Environment se aayega
    waitForConnections: true,
    connectionLimit: 10,
    ssl: {
        rejectUnauthorized: false
    },
    authPlugins: {
        mysql_clear_password: () => () => Buffer.from(process.env.DB_PASSWORD || '')
    }
});

const JWT_SECRET = process.env.JWT_SECRET;

// 🔒 SECURITY: pehle DB password aur JWT secret seedhe code mein likhe the
// (agar yeh code kabhi public GitHub repo mein hota, to password sabko dikh
// jaata). Ab sab kuch sirf Render ke Environment Variables se aata hai —
// koi bhi secret ab is file mein kahin nahi likha. Agar zaroori variable
// missing ho, to server turant clearly bata dega (chup-chaap galat/khaali
// credential se connect karne ki koshish nahi karega).
const REQUIRED_ENV = ['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME', 'JWT_SECRET'];
const missingEnv = REQUIRED_ENV.filter(k => !process.env[k]);
if (missingEnv.length) {
    console.error('❌ Yeh zaroori Environment Variables Render Dashboard mein set nahi hain: ' + missingEnv.join(', '));
    console.error('   Render → apni service → Environment tab mein jaakar inhe add karein, warna DB/login features kaam nahi karenge.');
}

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
        });

        // 🆕 Material bills/invoices (Anmol_material_entry_secure.html)
        connection.query(`
            CREATE TABLE IF NOT EXISTS material_bills (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ownerUserId VARCHAR(50) NOT NULL,
                data LONGTEXT,
                savedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `, (e) => {
            if (e) console.error('❌ material_bills table error:', e.message);
            // 🆕 FIX: agar material_bills table pehle se (kisi purane version se)
            // maujood thi bina in columns ke, to CREATE TABLE IF NOT EXISTS unhe
            // apne aap nahi jodta — isi wajah se "Unknown column 'ownerUserId'"
            // phir "Unknown column 'data'" jaisi errors ek-ek karke aa rahi thi.
            // Ab teeno zaroori columns (ownerUserId, data, savedAt) ek saath,
            // safely ensure kar diye jaate hain — jo pehle se hai use ignore
            // kar diya jaata hai (Duplicate column error).
            const ensureColumns = [
                "ALTER TABLE material_bills ADD COLUMN ownerUserId VARCHAR(50) NOT NULL DEFAULT ''",
                "ALTER TABLE material_bills ADD COLUMN data LONGTEXT",
                "ALTER TABLE material_bills ADD COLUMN savedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
            ];
            ensureColumns.forEach((sql) => {
                connection.query(sql, (alterErr) => {
                    if (alterErr && !/Duplicate column/i.test(alterErr.message)) {
                        console.error('❌ material_bills column error:', alterErr.message, '| SQL:', sql);
                    }
                });
            });
            // 🆕 FIX: purani table mein 'id' column PRIMARY KEY to tha, lekin
            // AUTO_INCREMENT nahi tha — isliye naya row insert karte waqt (jab
            // 'id' bheja hi nahi jaata) "Field 'id' doesn't have a default
            // value" error aata tha. MODIFY se use safely AUTO_INCREMENT bana
            // diya jaata hai (agar pehle se hai to yeh no-op hi rehta hai).
            connection.query(
                "ALTER TABLE material_bills MODIFY COLUMN id INT NOT NULL AUTO_INCREMENT",
                (idErr) => {
                    if (idErr) console.error('❌ material_bills id AUTO_INCREMENT fix error:', idErr.message);
                    else console.log('✅ material_bills.id AUTO_INCREMENT confirmed');
                }
            );
        });

        // 🆕 Generic key-value stores — admin-entities (admins/staff/agents/students
        // arrays) aur blob (settings/notices/mem_plans/... — routes/blob.js jaisa)
        // aur site-data (site content JSON). Frontend hamesha poori array/object
        // ek saath bhejta-padta hai, isliye ek generic table kaafi hai.
        connection.query(`
            CREATE TABLE IF NOT EXISTS kv_admin_entities (
                \`key\` VARCHAR(100) PRIMARY KEY,
                value LONGTEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        `, (e) => { if (e) console.error('❌ kv_admin_entities table error:', e.message); });
        connection.query(`
            CREATE TABLE IF NOT EXISTS kv_blob (
                \`key\` VARCHAR(100) PRIMARY KEY,
                value LONGTEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        `, (e) => { if (e) console.error('❌ kv_blob table error:', e.message); });
        connection.query(`
            CREATE TABLE IF NOT EXISTS kv_site_data (
                \`key\` VARCHAR(100) PRIMARY KEY,
                value LONGTEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        `, (e) => { if (e) console.error('❌ kv_site_data table error:', e.message); });

        // 🆕 Attendance (date+batch pe keyed merge — Student_Attendance.html)
        connection.query(`
            CREATE TABLE IF NOT EXISTS attendance_records (
                id INT AUTO_INCREMENT PRIMARY KEY,
                date VARCHAR(20) NOT NULL,
                batch VARCHAR(20) NOT NULL,
                records LONGTEXT,
                selfies LONGTEXT,
                markedBy VARCHAR(255),
                savedAt VARCHAR(50),
                UNIQUE KEY date_batch (date, batch)
            )
        `, (e) => { if (e) console.error('❌ attendance_records table error:', e.message); });

        // 🆕 Student fee payments
        connection.query(`
            CREATE TABLE IF NOT EXISTS fee_payments (
                id INT AUTO_INCREMENT PRIMARY KEY,
                studentId VARCHAR(100) NOT NULL,
                amount DECIMAL(10,2) NOT NULL,
                mode VARCHAR(50),
                note VARCHAR(500),
                status VARCHAR(20) DEFAULT 'paid',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `, (e) => { if (e) console.error('❌ fee_payments table error:', e.message); });

        // 🆕 Student → Agent direct-collect transactions (HRMS verify/reject flow)
        connection.query(`
            CREATE TABLE IF NOT EXISTS transactions (
                id VARCHAR(50) PRIMARY KEY,
                agentId VARCHAR(100),
                studentId VARCHAR(100),
                amount DECIMAL(10,2) NOT NULL,
                status VARCHAR(20) DEFAULT 'pending',
                reason VARCHAR(500),
                data LONGTEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `, (e) => { if (e) console.error('❌ transactions table error:', e.message); });

        // 🆕 HRMS salary slips (admin-generated) + claims (staff self-submitted)
        connection.query(`
            CREATE TABLE IF NOT EXISTS hrms_salary_slips (
                id VARCHAR(50) PRIMARY KEY,
                empId VARCHAR(100),
                data LONGTEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `, (e) => { if (e) console.error('❌ hrms_salary_slips table error:', e.message); });
        connection.query(`
            CREATE TABLE IF NOT EXISTS hrms_salary_claims (
                id VARCHAR(50) PRIMARY KEY,
                empId VARCHAR(100),
                status VARCHAR(30) DEFAULT 'pending',
                agentId VARCHAR(100),
                netAmount DECIMAL(10,2),
                data LONGTEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `, (e) => { if (e) console.error('❌ hrms_salary_claims table error:', e.message); });

        // 🆕 Agent wallets + withdrawals + direct payments
        connection.query(`
            CREATE TABLE IF NOT EXISTS agent_wallets (
                agentId VARCHAR(100) PRIMARY KEY,
                approved_balance DECIMAL(12,2) DEFAULT 0,
                pending_balance DECIMAL(12,2) DEFAULT 0,
                total_earned DECIMAL(12,2) DEFAULT 0
            )
        `, (e) => { if (e) console.error('❌ agent_wallets table error:', e.message); });
        connection.query(`
            CREATE TABLE IF NOT EXISTS wallet_withdrawals (
                id INT AUTO_INCREMENT PRIMARY KEY,
                agentId VARCHAR(100) NOT NULL,
                agentName VARCHAR(255),
                amount DECIMAL(10,2) NOT NULL,
                accName VARCHAR(255), bankName VARCHAR(255), accNo VARCHAR(50), ifsc VARCHAR(20),
                status VARCHAR(20) DEFAULT 'pending',
                reason VARCHAR(500),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `, (e) => { if (e) console.error('❌ wallet_withdrawals table error:', e.message); });
        connection.query(`
            CREATE TABLE IF NOT EXISTS wallet_direct_payments (
                id INT AUTO_INCREMENT PRIMARY KEY,
                agentId VARCHAR(100) NOT NULL,
                amount DECIMAL(10,2) NOT NULL,
                note VARCHAR(500),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `, (e) => { if (e) console.error('❌ wallet_direct_payments table error:', e.message); });

        // 🆕 Uploaded files (Hero image / Logo / APK / login-page HTML) — DB mein
        // hi blob ki tarah store hote hain, kyunki Render ka disk restart/redeploy
        // pe reset ho jaata hai (isliye seedhe filesystem pe save karna safe nahi).
        // 🆕 'slug' column: login-pages jaisi cheezon ko ek FIXED, memorable URL
        // deta hai (jaise /api/pages/agent-login) jo kabhi nahi badalta — chahe
        // file dobara upload/update kyun na ho jaaye. Isi se poora "Dynamic
        // Login System" bina Netlify par alag se deploy kiye kaam karta hai.
        connection.query(`
            CREATE TABLE IF NOT EXISTS site_files (
                id INT AUTO_INCREMENT PRIMARY KEY,
                slug VARCHAR(150) UNIQUE,
                folder VARCHAR(100),
                name VARCHAR(255),
                mime VARCHAR(150),
                size INT,
                data LONGBLOB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        `, (e) => {
            if (e) console.error('❌ site_files table error:', e.message);
            // Purani (pehle se maujood) site_files table mein 'slug' column jodo
            // agar pehle se nahi hai — CREATE TABLE IF NOT EXISTS purani table
            // ko khud nahi badalta.
            connection.query(`
                ALTER TABLE site_files ADD COLUMN slug VARCHAR(150) UNIQUE
            `, (alterErr) => {
                // Agar column pehle se hai to yeh error aayega — usse ignore karo
                if (alterErr && !/Duplicate column/i.test(alterErr.message)) {
                    console.error('❌ site_files slug column error:', alterErr.message);
                }
                connection.release();
                console.log('✅ Saari tables ready — koi bhi feature ab 404 nahi dega.');
            });
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

// 7b) Admin/Live-sync: single material user ki details (photo field ke saath —
//     Anmol_material_entry_secure.html ka live-profile-sync isi route ko har
//     12 second mein poll karta hai taaki photo/status turant update ho jaaye)
app.get('/api/material/users/:id', (req, res) => {
    db.query(
        'SELECT id, userId, name, village, address, email, mobile, photo, status, blockedReason, created_at FROM material_users WHERE id = ?',
        [req.params.id],
        (err, rows) => {
            if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
            if (!rows || !rows.length) return res.status(404).json({ error: 'Yeh material user nahi mila.' });
            res.json(Object.assign({ _docId: String(rows[0].id) }, rows[0]));
        }
    );
});

// 7c) Admin: material user ko permanently delete karna (Admin Panel "Delete User" feature)
app.delete('/api/material/users/:id', (req, res) => {
    db.query('DELETE FROM material_users WHERE id = ?', [req.params.id], (err, result) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        if (!result || !result.affectedRows) return res.status(404).json({ error: 'Yeh material user nahi mila.' });
        res.json({ success: true });
    });
});

// 8) Material user login (userId + mobile-number-or-admin-issued-password)
app.post('/api/material/login', (req, res) => {
    try {
        const userId = req.body && req.body.userId;
        // 🆕 FIX: 'secondFactor' hamesha String() mein convert kiya jaata hai —
        // agar frontend isse number ki tarah bhejta (jaise sirf mobile digits),
        // to bcrypt.compareSync() ek TypeError throw karta tha jo kahin bhi
        // catch nahi hota tha — poora Node.js process crash ho jaata tha!
        // Isi wajah se browser mein "Failed to fetch" (blank status) aata tha
        // — request backend tak pahunchi, par server hi crash ho gaya.
        const secondFactor = req.body && req.body.secondFactor != null ? String(req.body.secondFactor) : '';
        if (!userId || !secondFactor) return res.status(400).json({ error: 'User ID aur Mobile/Password dono zaroori hain.' });
        db.query('SELECT * FROM material_users WHERE userId = ?', [String(userId)], (err, rows) => {
            try {
                if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
                if (!rows || !rows.length) return res.status(404).json({ error: 'Yeh User ID registered nahi hai.' });
                const u = rows[0];
                if (u.status === 'blocked') {
                    return res.status(403).json({ error: 'Yeh ID admin dwara block kar di gayi hai.' });
                }
                const mobileMatches = String(u.mobile || '').replace(/\D/g, '').slice(-10) === secondFactor.replace(/\D/g, '').slice(-10);
                const passwordMatches = (u.password_hash && typeof u.password_hash === 'string')
                    ? bcrypt.compareSync(secondFactor, u.password_hash)
                    : false;
                if (!mobileMatches && !passwordMatches) {
                    return res.status(401).json({ error: 'Galat Mobile Number ya Password.' });
                }
                const token = jwt.sign({ userId: u.userId, role: 'material_user' }, JWT_SECRET, { expiresIn: '7d' });
                const { password_hash, ...userSafe } = u;
                userSafe._docId = String(u.id);
                res.json({ user: userSafe, token });
            } catch (innerErr) {
                console.error('❌ /material/login inner error:', innerErr.message);
                res.status(500).json({ error: 'Login process karte waqt error aaya: ' + innerErr.message });
            }
        });
    } catch (outerErr) {
        console.error('❌ /material/login outer error:', outerErr.message);
        res.status(500).json({ error: 'Login request mein error aaya: ' + outerErr.message });
    }
});

// ══════════════════════════════════════════════════════════════════
// 🔐 AUTH BRIDGE — Admin/Agent/Student login khud client-side (Firebase
//   data ke against) hota hai; yeh route sirf ek session token deta hai
//   taaki wallet/salary jaisi identity-based routes kaam kar sakein.
// ══════════════════════════════════════════════════════════════════
app.post('/api/auth/login', (req, res) => {
    const { role, username } = req.body || {};
    if (!role || !username) return res.status(400).json({ error: 'role aur username zaroori hain.' });
    const token = jwt.sign({ role, username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token });
});

// ══════════════════════════════════════════════════════════════════
// 🗄️ GENERIC KEY-VALUE STORES — admin-entities / blob / site-data
//   (Admin Panel ke FBSync.pull/push isi se judte hain)
// ══════════════════════════════════════════════════════════════════
const ENTITY_KEYS = ['admins', 'staff', 'agents', 'students', 'agent_logins'];
const BLOB_KEYS = ['settings', 'activity', 'notices', 'mem_plans', 'members',
    'hrms_registrations', 'staff_att', 'leave_requests', 'agent_plans', 'agent_payments',
    'razorpay_config', 'sms_api_config'];

function kvGet(table, key, res, wrapValue) {
    db.query(`SELECT value FROM ${table} WHERE \`key\` = ?`, [key], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        if (!rows || !rows.length) return res.json(wrapValue ? null : null);
        let parsed = null;
        try { parsed = JSON.parse(rows[0].value); } catch (e) { parsed = rows[0].value; }
        res.json(parsed);
    });
}
function kvSet(table, key, value, res) {
    const json = JSON.stringify(value);
    db.query(
        `INSERT INTO ${table} (\`key\`, value) VALUES (?, ?) ON DUPLICATE KEY UPDATE value = ?`,
        [key, json, json],
        (err) => {
            if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
            res.json({ success: true });
        }
    );
}

app.get('/api/admin-entities/:key', (req, res) => {
    if (!ENTITY_KEYS.includes(req.params.key)) return res.status(404).json({ error: 'Unknown entity key' });
    kvGet('kv_admin_entities', req.params.key, res);
});
app.post('/api/admin-entities/:key', (req, res) => {
    if (!ENTITY_KEYS.includes(req.params.key)) return res.status(404).json({ error: 'Unknown entity key' });
    kvSet('kv_admin_entities', req.params.key, req.body, res);
});

app.get('/api/blob/:key', (req, res) => {
    if (!BLOB_KEYS.includes(req.params.key)) return res.status(404).json({ error: 'Unknown blob key' });
    kvGet('kv_blob', req.params.key, res);
});
app.post('/api/blob/:key', (req, res) => {
    if (!BLOB_KEYS.includes(req.params.key)) return res.status(404).json({ error: 'Unknown blob key' });
    kvSet('kv_blob', req.params.key, req.body, res);
});
app.delete('/api/blob/:key', (req, res) => {
    db.query('DELETE FROM kv_blob WHERE `key` = ?', [req.params.key], (err) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        res.json({ success: true });
    });
});

// site-data: POST body { value }, GET returns { value }
// 🔒 Sirf Admin session (JWT role='Admin') hi website content badal sake —
//   index.html ise sirf PADHTA hai (login ke bina), yeh comment mein bhi
//   likha tha to ab isko enforce bhi kar diya.
app.post('/api/site-data/:key', (req, res) => {
    const auth = getAuthUser(req);
    if (!auth || String(auth.role).toLowerCase() !== 'admin') return res.status(401).json({ error: 'Sirf Admin login se hi website content badla ja sakta hai.' });
    const value = (req.body || {}).value;
    const json = JSON.stringify(value);
    db.query(
        'INSERT INTO kv_site_data (`key`, value) VALUES (?, ?) ON DUPLICATE KEY UPDATE value = ?',
        [req.params.key, json, json],
        (err) => {
            if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
            res.json({ success: true });
        }
    );
});
app.get('/api/site-data/:key', (req, res) => {
    db.query('SELECT value FROM kv_site_data WHERE `key` = ?', [req.params.key], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        if (!rows || !rows.length) return res.json(null);
        let parsed = null;
        try { parsed = JSON.parse(rows[0].value); } catch (e) { parsed = rows[0].value; }
        res.json({ value: parsed });
    });
});

// 🆕 COMBINED site-data — index.html ka LIVE SYNC (GET /api/site-data, bina
//   key ke) isi ek call se ticker/hero/stats/footer/nav/login/apps saara
//   data ek saath fetch karta hai, taaki 7 alag requests na karni padein.
//   Admin Panel jab bhi koi ek section save karta hai (POST /site-data/:key),
//   agli baar yeh route khud-ba-khud updated value bhej dega — koi extra
//   kaam nahi karna padta.
app.get('/api/site-data', (req, res) => {
    db.query('SELECT `key`, value FROM kv_site_data', (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        const out = {};
        (rows || []).forEach(r => {
            try { out[r.key] = JSON.parse(r.value); } catch (e) { out[r.key] = r.value; }
        });
        res.json(out);
    });
});

// ══════════════════════════════════════════════════════════════════
// 📤 FILE UPLOAD — Hero image / Logo / Login-page HTML / APK
//   (Admin_panel_Login.html ka gcsUploadFile() isi route ko call karta
//   hai; pehle yeh route missing tha isliye Express ka default 404 HTML
//   aata tha aur frontend "Unexpected token '<'..." error deta tha.)
//   Memory mein hi rakha jaata hai (Multer memoryStorage) aur seedhe MySQL
//   mein blob ki tarah save hota hai — Render ke ephemeral disk pe nahi,
//   isliye redeploy/restart hone par bhi file gayab nahi hoti.
// ══════════════════════════════════════════════════════════════════
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 } }); // 20MB max

// Slug ko URL-safe banata hai: "Agent Login" → "agent-login"
function slugify(str) {
    return String(str || '').toLowerCase().trim()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .slice(0, 140);
}

app.post('/api/site-content/upload-file', upload.single('file'), (req, res) => {
    const auth = getAuthUser(req);
    if (!auth || String(auth.role).toLowerCase() !== 'admin') return res.status(401).json({ error: 'Sirf Admin login se hi file upload ho sakti hai.' });
    if (!req.file) return res.status(400).json({ error: 'Koi file mili nahi (form field ka naam "file" hona chahiye).' });
    const folder = req.body.folder || 'misc';
    const slug = req.body.slug ? slugify(req.body.slug) : null;

    const respondWithFile = (id) => {
        // 🆕 Agar slug diya gaya hai (login-pages ke liye hamesha diya jaata hai), to
        // URL hamesha /api/pages/<slug> hoga — yeh URL kabhi nahi badalta, chahe file
        // dobara-dobara upload/update hoti rahe. Isi se "Dynamic Centralized Login
        // System" banta hai: Netlify par kabhi alag se file deploy nahi karni padti.
        const path = slug ? ('/api/pages/' + slug) : ('/api/site-content/file/' + id);
        const absoluteUrl = req.protocol + '://' + req.get('host') + path;
        res.status(201).json({ url: absoluteUrl, path: absoluteUrl, name: req.file.originalname, size: req.file.size, slug: slug || null });
    };

    if (slug) {
        // 🆕 UPSERT by slug: pehli baar INSERT, agli baar isi slug par UPDATE —
        // taaki "Agent Login" dobara upload karne par bhi URL wahi purana hi rahe.
        db.query(
            `INSERT INTO site_files (slug, folder, name, mime, size, data) VALUES (?,?,?,?,?,?)
             ON DUPLICATE KEY UPDATE folder=VALUES(folder), name=VALUES(name), mime=VALUES(mime), size=VALUES(size), data=VALUES(data)`,
            [slug, folder, req.file.originalname, req.file.mimetype, req.file.size, req.file.buffer],
            (err, result) => {
                if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
                respondWithFile(result.insertId);
            }
        );
    } else {
        db.query(
            'INSERT INTO site_files (folder, name, mime, size, data) VALUES (?,?,?,?,?)',
            [folder, req.file.originalname, req.file.mimetype, req.file.size, req.file.buffer],
            (err, result) => {
                if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
                respondWithFile(result.insertId);
            }
        );
    }
});

// File serve by numeric ID (purane links ke backward-compatibility ke liye)
app.get('/api/site-content/file/:id', (req, res) => {
    db.query('SELECT name, mime, data FROM site_files WHERE id=?', [req.params.id], (err, rows) => {
        if (err) return res.status(500).send('DB error');
        if (!rows || !rows.length) return res.status(404).send('File not found');
        const f = rows[0];
        res.set('Content-Type', f.mime || 'application/octet-stream');
        res.set('Content-Disposition', 'inline; filename="' + f.name + '"');
        res.send(f.data);
    });
});

// ══════════════════════════════════════════════════════════════════
// 🌐 CENTRALIZED DYNAMIC PAGE ROUTE — yeh hi woh "catch-all" route hai
//   jo aapne maanga tha. Admin/Agent/HRMS/Student/Invoice — koi bhi
//   login page ho, sabka HTML ab isi EK route se, database se seedha
//   nikal kar serve hota hai. Naya login role add karna ho to bas Admin
//   Panel se naya HTML upload karo (slug ke saath) — turant
//   /api/pages/<slug> par live ho jaata hai, Netlify par kuch bhi
//   deploy karne ki zaroorat NAHI.
// ══════════════════════════════════════════════════════════════════
app.get('/api/pages/:slug', (req, res) => {
    db.query('SELECT name, mime, data FROM site_files WHERE slug=?', [req.params.slug], (err, rows) => {
        if (err) return res.status(500).send('DB error: ' + err.message);
        if (!rows || !rows.length) return res.status(404).send('Yeh page abhi upload nahi hua hai: /' + req.params.slug);
        const f = rows[0];
        res.set('Content-Type', f.mime || 'text/html');
        res.set('Content-Disposition', 'inline; filename="' + f.name + '"');
        res.send(f.data);
    });
});

// Admin Panel ke "Login Dropdown Manager" mein sabhi upload-ho-chuke pages
// ki list dikhane ke liye (slug + naam + kab update hua)
app.get('/api/pages', (req, res) => {
    db.query("SELECT slug, name, mime, size, updated_at FROM site_files WHERE slug IS NOT NULL ORDER BY updated_at DESC", (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        res.json(rows || []);
    });
});

// Convenience direct aliases (frontend polls these paths directly)
app.get('/api/students', (req, res) => kvGet('kv_admin_entities', 'students', res));
app.get('/api/settings', (req, res) => kvGet('kv_blob', 'settings', res));

// ══════════════════════════════════════════════════════════════════
// 📋 ATTENDANCE — date+batch pe keyed merge (do students ek saath
//   save karein to ek-doosre ka data overwrite na ho)
// ══════════════════════════════════════════════════════════════════
app.post('/api/attendance', (req, res) => {
    const { date, batch, records, selfies, markedBy, savedAt } = req.body || {};
    if (!date || !batch) return res.status(400).json({ error: 'date aur batch zaroori hain.' });
    db.query('SELECT records, selfies FROM attendance_records WHERE date=? AND batch=?', [date, batch], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        let mergedRecords = records || {};
        let mergedSelfies = selfies || {};
        if (rows && rows.length) {
            try { mergedRecords = Object.assign(JSON.parse(rows[0].records || '{}'), records || {}); } catch (e) {}
            try { mergedSelfies = Object.assign(JSON.parse(rows[0].selfies || '{}'), selfies || {}); } catch (e) {}
        }
        db.query(
            `INSERT INTO attendance_records (date, batch, records, selfies, markedBy, savedAt)
             VALUES (?,?,?,?,?,?)
             ON DUPLICATE KEY UPDATE records=VALUES(records), selfies=VALUES(selfies), markedBy=VALUES(markedBy), savedAt=VALUES(savedAt)`,
            [date, batch, JSON.stringify(mergedRecords), JSON.stringify(mergedSelfies), markedBy || '', savedAt || new Date().toISOString()],
            (insErr) => {
                if (insErr) return res.status(500).json({ error: 'DB error: ' + insErr.message });
                res.json({ success: true });
            }
        );
    });
});

// ══════════════════════════════════════════════════════════════════
// 💳 PAYMENTS — student fee, Razorpay, agent-collect transactions
// ══════════════════════════════════════════════════════════════════
app.post('/api/payments/fee', (req, res) => {
    const { studentId, amount, mode, note, status } = req.body || {};
    if (!studentId || !(amount > 0)) return res.status(400).json({ error: 'studentId aur amount zaroori hain.' });
    db.query(
        'INSERT INTO fee_payments (studentId, amount, mode, note, status) VALUES (?,?,?,?,?)',
        [studentId, amount, mode || 'cash', note || '', status || 'paid'],
        (err, result) => {
            if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
            res.status(201).json({ id: result.insertId });
        }
    );
});
app.get('/api/payments/fee', (req, res) => {
    const studentId = req.query.studentId;
    const sql = studentId ? 'SELECT * FROM fee_payments WHERE studentId=? ORDER BY created_at DESC' : 'SELECT * FROM fee_payments ORDER BY created_at DESC';
    db.query(sql, studentId ? [studentId] : [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        res.json(rows || []);
    });
});

// ══════════════════════════════════════════════════════════════════
// 💳 RAZORPAY — order create + payment verify
//   Keys kabhi bhi code mein nahi likhi jaatin — dono Render Dashboard ke
//   Environment Variables se aati hain:
//     PAYMENT_API_KEY    → Razorpay "Key ID"
//     PAYMENT_API_SECRET → Razorpay "Key Secret"
//   (Node ke built-in 'https'/'crypto' se hi kaam chal jaata hai, isliye
//   koi naya npm package install karne ki zaroorat nahi.)
// ══════════════════════════════════════════════════════════════════
const https = require('https');
const crypto = require('crypto');

function razorpayRequest(path, body) {
    return new Promise((resolve, reject) => {
        const key = process.env.PAYMENT_API_KEY;
        const secret = process.env.PAYMENT_API_SECRET;
        if (!key || !secret) return reject(new Error('PAYMENT_API_KEY / PAYMENT_API_SECRET Render Environment mein set nahi hain.'));
        const payload = JSON.stringify(body);
        const options = {
            hostname: 'api.razorpay.com',
            path,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(payload),
                'Authorization': 'Basic ' + Buffer.from(key + ':' + secret).toString('base64')
            }
        };
        const reqStream = https.request(options, (resp) => {
            let data = '';
            resp.on('data', (chunk) => { data += chunk; });
            resp.on('end', () => {
                try {
                    const parsed = JSON.parse(data);
                    if (resp.statusCode >= 200 && resp.statusCode < 300) resolve(parsed);
                    else reject(new Error(parsed.error ? parsed.error.description : 'Razorpay API error'));
                } catch (e) { reject(e); }
            });
        });
        reqStream.on('error', reject);
        reqStream.write(payload);
        reqStream.end();
    });
}

app.post('/api/payments/razorpay/order', async (req, res) => {
    if (!process.env.PAYMENT_API_KEY || !process.env.PAYMENT_API_SECRET) {
        return res.status(501).json({ error: 'Payment keys Render Environment mein set nahi hain (PAYMENT_API_KEY / PAYMENT_API_SECRET).' });
    }
    const { amount, currency, receipt } = req.body || {};
    if (!(amount > 0)) return res.status(400).json({ error: 'Sahi amount bhejein.' });
    try {
        const order = await razorpayRequest('/v1/orders', {
            amount: Math.round(amount * 100), // paise mein
            currency: currency || 'INR',
            receipt: receipt || ('rcpt_' + Date.now())
        });
        res.json({ orderId: order.id, amount: order.amount, currency: order.currency, key: process.env.PAYMENT_API_KEY });
    } catch (e) {
        res.status(502).json({ error: 'Razorpay order banane mein error: ' + e.message });
    }
});

app.post('/api/payments/razorpay/verify', (req, res) => {
    const secret = process.env.PAYMENT_API_SECRET;
    if (!secret) return res.status(501).json({ error: 'PAYMENT_API_SECRET Render Environment mein set nahi hai.' });
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body || {};
    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
        return res.status(400).json({ error: 'Order ID, Payment ID aur Signature teeno zaroori hain.' });
    }
    const expected = crypto.createHmac('sha256', secret)
        .update(razorpay_order_id + '|' + razorpay_payment_id)
        .digest('hex');
    if (expected !== razorpay_signature) {
        return res.status(400).json({ error: 'Payment verify nahi hua — signature match nahi hui.' });
    }
    res.json({ success: true });
});

// ══════════════════════════════════════════════════════════════════
// 📱 SMS — OTP/notification bhejne ke liye. Key kabhi code mein nahi —
//   Render Environment se aati hai: SMS_API_KEY (+ optional SMS_SENDER_ID).
//   Neeche wala provider URL ek generic placeholder hai (Fast2SMS jaisa
//   pattern) — apne asli SMS provider (Fast2SMS/MSG91/Twilio/etc) ke
//   hisaab se path/params thoda badalna pad sakta hai.
// ══════════════════════════════════════════════════════════════════
function sendSms(mobile, message) {
    return new Promise((resolve, reject) => {
        const apiKey = process.env.SMS_API_KEY;
        if (!apiKey) return reject(new Error('SMS_API_KEY Render Environment mein set nahi hai.'));
        const params = new URLSearchParams({
            authorization: apiKey,
            route: 'q',
            message,
            numbers: mobile,
            sender_id: process.env.SMS_SENDER_ID || 'LIBRBK'
        });
        https.get('https://www.fast2sms.com/dev/bulkV2?' + params.toString(), (resp) => {
            let data = '';
            resp.on('data', (c) => { data += c; });
            resp.on('end', () => resolve(data));
        }).on('error', reject);
    });
}

app.post('/api/sms/send', async (req, res) => {
    const { mobile, message } = req.body || {};
    if (!mobile || !message) return res.status(400).json({ error: 'mobile aur message zaroori hain.' });
    if (!process.env.SMS_API_KEY) return res.status(501).json({ error: 'SMS_API_KEY Render Environment mein set nahi hai.' });
    try {
        await sendSms(mobile, message);
        res.json({ success: true });
    } catch (e) {
        res.status(502).json({ error: 'SMS bhejne mein error: ' + e.message });
    }
});

// Agent student-collect transaction (create → pending; HRMS verify/reject)
app.post('/api/payments/student-transaction', (req, res) => {
    const { agentId, amount } = req.body || {};
    if (!agentId || !(amount > 0)) return res.status(400).json({ error: 'agentId and a positive amount are required' });
    const txnId = 'TXN' + Date.now();
    db.query(
        'INSERT INTO transactions (id, agentId, studentId, amount, status, data) VALUES (?,?,?,?,?,?)',
        [txnId, agentId, req.body.studentId || null, amount, 'pending', JSON.stringify(req.body)],
        (err) => {
            if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
            res.status(201).json({ txnId });
        }
    );
});
app.post('/api/payments/transactions/:id/verify', (req, res) => {
    const id = req.params.id;
    db.query("SELECT * FROM transactions WHERE id=? AND status='pending'", [id], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        if (!rows || !rows.length) return res.status(404).json({ error: 'Transaction pending nahi mila.' });
        const t = rows[0];
        db.query("UPDATE transactions SET status='verified' WHERE id=?", [id], () => {
            db.query(
                `INSERT INTO agent_wallets (agentId, approved_balance, total_earned) VALUES (?,?,?)
                 ON DUPLICATE KEY UPDATE approved_balance = approved_balance + VALUES(approved_balance),
                                          total_earned = total_earned + VALUES(total_earned)`,
                [t.agentId, t.amount, t.amount],
                (wErr) => {
                    if (wErr) return res.status(500).json({ error: 'DB error: ' + wErr.message });
                    res.json({ success: true, txnId: id });
                }
            );
        });
    });
});
app.post('/api/payments/transactions/:id/reject', (req, res) => {
    db.query("UPDATE transactions SET status='rejected', reason=? WHERE id=?", [(req.body || {}).reason || '', req.params.id], (err) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        res.json({ success: true });
    });
});

// ══════════════════════════════════════════════════════════════════
// 🧾 HRMS SALARY — slips (admin-generated) + claims (staff self-submit,
//   agent/admin verify → wallet se deduct karke payslip)
// ══════════════════════════════════════════════════════════════════
app.get('/api/hrms-salary/slips', (req, res) => {
    db.query('SELECT * FROM hrms_salary_slips ORDER BY created_at DESC', (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        res.json((rows || []).map(r => { try { return Object.assign(JSON.parse(r.data), { id: r.id }); } catch (e) { return { id: r.id }; } }));
    });
});
// ══════════════════════════════════════════════════════════════════
// 💳 SUBSCRIPTION RENEWAL — Agent_login.html ka AGENT_APPLY_RENEWAL()
//   pehle 3 alag-alag Firebase calls karta tha (agent update, students
//   bulk-activate, payment history log). Ab yeh sab EK hi backend call
//   mein ho jaata hai — 'agents'/'students' (kv_admin_entities) aur
//   'agent_payments' (kv_blob) ko seedhe DB mein update karke.
// ══════════════════════════════════════════════════════════════════
app.post('/api/payment/update', (req, res) => {
    const { username, planId, planName, days, price, mode, refId } = req.body || {};
    if (!username || !(Number(days) > 0)) return res.status(400).json({ error: 'username aur days zaroori hain.' });

    db.query("SELECT value FROM kv_admin_entities WHERE `key`='agents'", (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        let agents = [];
        try { agents = rows && rows.length ? JSON.parse(rows[0].value) : []; } catch (e) {}
        const idx = agents.findIndex(a => a && a.username && String(a.username).toLowerCase() === String(username).toLowerCase());
        if (idx === -1) return res.status(404).json({ error: 'Agent record nahi mila. Admin se contact karein.' });

        const a = agents[idx];
        const today = new Date(); today.setHours(0, 0, 0, 0);
        const curExp = a.subExpiry ? new Date(a.subExpiry) : null;
        const base = (curExp && curExp > today) ? curExp : today;
        const newExp = new Date(base); newExp.setDate(newExp.getDate() + Number(days));
        const newExpStr = newExp.toISOString().split('T')[0];
        const newStartStr = today.toISOString().split('T')[0];
        agents[idx] = Object.assign({}, a, { planId, subStart: newStartStr, subExpiry: newExpStr });
        const agentsJson = JSON.stringify(agents);

        db.query("UPDATE kv_admin_entities SET value=? WHERE `key`='agents'", [agentsJson], (uErr) => {
            if (uErr) return res.status(500).json({ error: 'DB error: ' + uErr.message });

            // ── Is agent ke saare students ka subscription bhi turant activate karo ──
            db.query("SELECT value FROM kv_admin_entities WHERE `key`='students'", (sErr, sRows) => {
                let students = [];
                try { students = sRows && sRows.length ? JSON.parse(sRows[0].value) : []; } catch (e) {}
                let activatedCount = 0;
                if (a.agentId && Array.isArray(students)) {
                    students = students.map(s => {
                        if (s && s.agentId === a.agentId) {
                            activatedCount++;
                            return Object.assign({}, s, { subscription_status: 'active', subscription_expiry: newExpStr });
                        }
                        return s;
                    });
                }
                const saveStudents = (cb) => {
                    if (!activatedCount) return cb();
                    db.query("UPDATE kv_admin_entities SET value=? WHERE `key`='students'", [JSON.stringify(students)], () => cb());
                };

                saveStudents(() => {
                    // ── Payment history log karo ──
                    db.query("SELECT value FROM kv_blob WHERE `key`='agent_payments'", (pErr, pRows) => {
                        let payments = [];
                        try { payments = pRows && pRows.length ? JSON.parse(pRows[0].value) : []; } catch (e) {}
                        const paymentRecord = {
                            id: 'pay' + Date.now(), agentId: a.id, agentDbId: a.agentId, agentName: a.name,
                            planId, planName, amount: price, mode: mode || '', note: refId ? ('Ref: ' + refId) : '',
                            date: new Date().toLocaleString('hi-IN'), newExpiry: newExpStr
                        };
                        payments.push(paymentRecord);
                        const paymentsJson = JSON.stringify(payments);
                        db.query(
                            "INSERT INTO kv_blob (`key`, value) VALUES ('agent_payments', ?) ON DUPLICATE KEY UPDATE value = ?",
                            [paymentsJson, paymentsJson],
                            (finalErr) => {
                                if (finalErr) return res.status(500).json({ error: 'DB error: ' + finalErr.message });
                                res.json({ subStart: newStartStr, subExpiry: newExpStr, agent: agents[idx], paymentRecord, studentsActivated: activatedCount });
                            }
                        );
                    });
                });
            });
        });
    });
});

// ══════════════════════════════════════════════════════════════════
// 🧾 STAFF SALARY SYNC — HRMS ke liye 'staff' data. Yeh route wahi
//   'admin-entities/staff' hi hai (naya endpoint nahi banaya), taaki
//   Admin Panel se add/edit kiya gaya staff seedhe HRMS salary-calc mein
//   bhi reflect ho. Alag naam se alias diya gaya hai taaki frontend code
//   mein intent saaf rahe ('/salary/sync' padhne mein samajh aata hai).
// ══════════════════════════════════════════════════════════════════
app.get('/api/salary/sync', (req, res) => kvGet('kv_admin_entities', 'staff', res));

app.get('/api/hrms-salary/claims', (req, res) => {
    db.query('SELECT * FROM hrms_salary_claims ORDER BY created_at DESC', (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        res.json((rows || []).map(r => { try { return Object.assign(JSON.parse(r.data), { id: r.id, status: r.status }); } catch (e) { return { id: r.id, status: r.status }; } }));
    });
});
app.post('/api/hrms-salary/claims', (req, res) => {
    const claim = req.body || {};
    const id = claim.id || ('CLM' + Date.now());
    db.query(
        'INSERT INTO hrms_salary_claims (id, empId, status, netAmount, data) VALUES (?,?,?,?,?)',
        [id, claim.empId || null, 'pending', claim.net || 0, JSON.stringify(claim)],
        (err) => {
            if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
            res.status(201).json({ id });
        }
    );
});
// Staff claim → Agent verifies (deduct agent wallet)
app.post('/api/wallet/salary-claims/:id/verify', (req, res) => {
    const auth = getAuthUser(req);
    const agentId = auth ? auth.username : (req.body && req.body.agentId);
    if (!agentId) return res.status(401).json({ error: 'Agent identity nahi mili — dobara login karein.' });
    db.query("SELECT * FROM hrms_salary_claims WHERE id=? AND status='pending'", [req.params.id], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        if (!rows || !rows.length) return res.status(404).json({ error: 'Claim pending nahi mila.' });
        const c = rows[0];
        db.query('SELECT approved_balance FROM agent_wallets WHERE agentId=?', [agentId], (wErr, wRows) => {
            if (wErr) return res.status(500).json({ error: 'DB error: ' + wErr.message });
            const balance = wRows && wRows.length ? Number(wRows[0].approved_balance) : 0;
            if (balance < Number(c.netAmount)) return res.status(400).json({ error: 'Aapke Wallet mein paise kam hain.' });
            const transferDueBy = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
            db.query('UPDATE agent_wallets SET approved_balance = approved_balance - ? WHERE agentId=?', [c.netAmount, agentId], () => {
                db.query("UPDATE hrms_salary_claims SET status='pending_admin', agentId=? WHERE id=?", [agentId, c.id], (uErr) => {
                    if (uErr) return res.status(500).json({ error: 'DB error: ' + uErr.message });
                    res.json({ walletDeductedAmount: c.netAmount, transferDueBy });
                });
            });
        });
    });
});
// Admin final approve → generates payslip
app.post('/api/hrms-salary/claims/:id/approve', (req, res) => {
    db.query("SELECT * FROM hrms_salary_claims WHERE id=? AND (status='pending' OR status='pending_admin')", [req.params.id], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        if (!rows || !rows.length) return res.status(400).json({ error: 'Yeh claim pending nahi hai (already processed).' });
        const c = rows[0];
        db.query("UPDATE hrms_salary_claims SET status='approved' WHERE id=?", [c.id], () => {
            const slipId = 'SLP' + Date.now();
            db.query('INSERT INTO hrms_salary_slips (id, empId, data) VALUES (?,?,?)', [slipId, c.empId, c.data], (sErr) => {
                if (sErr) return res.status(500).json({ error: 'DB error: ' + sErr.message });
                res.json({ netAmount: c.netAmount, slipId });
            });
        });
    });
});
app.post('/api/hrms-salary/claims/:id/reject', (req, res) => {
    db.query("UPDATE hrms_salary_claims SET status='rejected' WHERE id=? AND status IN ('pending','pending_admin')", [req.params.id], (err, result) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        if (!result.affectedRows) return res.status(400).json({ error: 'Yeh claim pending nahi hai (already processed).' });
        res.json({ success: true });
    });
});

// ══════════════════════════════════════════════════════════════════
// 👛 AGENT WALLET — balance, withdrawals, direct-collect payments
//   NOTE: identity JWT token ke 'username' se aati hai (Agent login ke
//   /auth/login bridge se). Production mein isse asli agentId se map
//   karna behtar hoga agar dono alag ho sakte hain.
// ══════════════════════════════════════════════════════════════════
function requireAgentId(req, res) {
    const auth = getAuthUser(req);
    const agentId = auth ? auth.username : null;
    if (!agentId) { res.status(401).json({ error: 'Login session nahi mila — dobara login karein.' }); return null; }
    return agentId;
}

app.get('/api/wallet/me', (req, res) => {
    const agentId = requireAgentId(req, res); if (!agentId) return;
    db.query('SELECT * FROM agent_wallets WHERE agentId=?', [agentId], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        res.json(rows && rows.length ? rows[0] : { approved_balance: 0, pending_balance: 0, total_earned: 0 });
    });
});
app.get('/api/wallet/my-salary-payments', (req, res) => {
    const agentId = requireAgentId(req, res); if (!agentId) return;
    db.query("SELECT * FROM hrms_salary_claims WHERE agentId=? AND status IN ('pending_admin','approved') ORDER BY created_at DESC", [agentId], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        res.json((rows || []).map(r => { try { return Object.assign(JSON.parse(r.data), { amount: r.netAmount }); } catch (e) { return { amount: r.netAmount }; } }));
    });
});
app.get('/api/wallet/withdrawals/mine', (req, res) => {
    const agentId = requireAgentId(req, res); if (!agentId) return;
    db.query('SELECT * FROM wallet_withdrawals WHERE agentId=? ORDER BY created_at DESC', [agentId], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        res.json(rows || []);
    });
});
app.get('/api/wallet/my-direct-payments', (req, res) => {
    const agentId = requireAgentId(req, res); if (!agentId) return;
    db.query('SELECT * FROM wallet_direct_payments WHERE agentId=? ORDER BY created_at DESC', [agentId], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        res.json(rows || []);
    });
});
app.post('/api/wallet/withdraw', (req, res) => {
    const agentId = requireAgentId(req, res); if (!agentId) return;
    const { amount, accName, bankName, accNo, ifsc, agentName } = req.body || {};
    if (!(amount > 0)) return res.status(400).json({ error: 'Sahi amount daalein.' });
    db.query('SELECT approved_balance FROM agent_wallets WHERE agentId=?', [agentId], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        const balance = rows && rows.length ? Number(rows[0].approved_balance) : 0;
        if (balance < amount) return res.status(400).json({ error: 'Aapke Withdrawable Balance se zyada amount hai — kam amount daalein.' });
        db.query('UPDATE agent_wallets SET approved_balance = approved_balance - ?, pending_balance = pending_balance + ? WHERE agentId=?', [amount, amount, agentId], (uErr) => {
            if (uErr) return res.status(500).json({ error: 'DB error: ' + uErr.message });
            db.query(
                'INSERT INTO wallet_withdrawals (agentId, agentName, amount, accName, bankName, accNo, ifsc, status) VALUES (?,?,?,?,?,?,?,\'pending\')',
                [agentId, agentName || '', amount, accName, bankName, accNo, ifsc],
                (insErr) => {
                    if (insErr) return res.status(500).json({ error: 'DB error: ' + insErr.message });
                    res.status(201).json({ success: true });
                }
            );
        });
    });
});
// Admin: list all withdrawals + approve/reject
app.get('/api/wallet/withdrawals', (req, res) => {
    db.query('SELECT * FROM wallet_withdrawals ORDER BY created_at DESC', (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        res.json(rows || []);
    });
});
app.post('/api/wallet/withdrawal/:id/process', (req, res) => {
    const { action, reason } = req.body || {};
    db.query("SELECT * FROM wallet_withdrawals WHERE id=? AND status='pending'", [req.params.id], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        if (!rows || !rows.length) return res.status(404).json({ error: 'Withdrawal pending nahi mila.' });
        const w = rows[0];
        if (action === 'approve') {
            db.query("UPDATE wallet_withdrawals SET status='paid' WHERE id=?", [w.id], () => {
                db.query('UPDATE agent_wallets SET pending_balance = pending_balance - ? WHERE agentId=?', [w.amount, w.agentId], (uErr) => {
                    if (uErr) return res.status(500).json({ error: 'DB error: ' + uErr.message });
                    res.json({ success: true });
                });
            });
        } else {
            // reject → refund back to approved_balance
            db.query("UPDATE wallet_withdrawals SET status='rejected', reason=? WHERE id=?", [reason || '', w.id], () => {
                db.query('UPDATE agent_wallets SET pending_balance = pending_balance - ?, approved_balance = approved_balance + ? WHERE agentId=?', [w.amount, w.amount, w.agentId], (uErr) => {
                    if (uErr) return res.status(500).json({ error: 'DB error: ' + uErr.message });
                    res.json({ success: true });
                });
            });
        }
    });
});
// Admin: student→agent direct-collect payments summary (today/month)
app.get('/api/wallet/agent-direct-payments', (req, res) => {
    db.query(
        `SELECT
            SUM(CASE WHEN DATE(created_at)=CURDATE() THEN amount ELSE 0 END) AS today_total,
            SUM(CASE WHEN DATE(created_at)=CURDATE() THEN 1 ELSE 0 END) AS today_count,
            SUM(CASE WHEN YEAR(created_at)=YEAR(CURDATE()) AND MONTH(created_at)=MONTH(CURDATE()) THEN amount ELSE 0 END) AS month_total,
            SUM(CASE WHEN YEAR(created_at)=YEAR(CURDATE()) AND MONTH(created_at)=MONTH(CURDATE()) THEN 1 ELSE 0 END) AS month_count
         FROM wallet_direct_payments`,
        (err, rows) => {
            if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
            const r = (rows && rows[0]) || {};
            res.json({
                today: { total: Number(r.today_total) || 0, count: Number(r.today_count) || 0 },
                month: { total: Number(r.month_total) || 0, count: Number(r.month_count) || 0 }
            });
        }
    );
});

// ══════════════════════════════════════════════════════════════════
// 🧾 MATERIAL BILLS/INVOICES (Anmol_material_entry_secure.html)
// ══════════════════════════════════════════════════════════════════
app.post('/api/material/bills', (req, res) => {
    const body = req.body || {};
    const ownerUserId = body.ownerUserId;
    if (!ownerUserId) return res.status(400).json({ error: 'ownerUserId zaroori hai.' });
    // 🆕 FIX: pehle yahan har save par HAMESHA naya row INSERT hota tha —
    // chahe wahi Bill No dobara save kiya jaaye. Frontend isi behavior ki
    // ummeed karta hai ki ownerUserId + billNo match hone par UPDATE ho,
    // naya duplicate row na bane. Ab pehle check karte hain ki isi user ka
    // isi Bill No wala record pehle se hai kya — agar hai to UPDATE, nahi to
    // naya INSERT.
    const billNo = body.billNo || null;
    const findExisting = (cb) => {
        if (!billNo) return cb(null); // Bill No khaali hai — hamesha naya bill
        db.query(
            "SELECT id FROM material_bills WHERE ownerUserId=? AND JSON_UNQUOTE(JSON_EXTRACT(data, '$.billNo'))=? LIMIT 1",
            [ownerUserId, billNo],
            (err, rows) => cb(err ? null : (rows && rows[0] ? rows[0].id : null))
        );
    };
    findExisting((existingId) => {
        if (existingId) {
            db.query('UPDATE material_bills SET data=? WHERE id=?', [JSON.stringify(body), existingId], (uErr) => {
                if (uErr) return res.status(500).json({ error: 'DB error: ' + uErr.message });
                res.status(200).json({ id: existingId, updated: true });
            });
        } else {
            const doInsert = (retryDone) => {
                db.query('INSERT INTO material_bills (ownerUserId, data) VALUES (?,?)', [ownerUserId, JSON.stringify(body)], (err, result) => {
                    // 🆕 SELF-HEAL FIX: agar Render par abhi bhi purana table (bina
                    // AUTO_INCREMENT wala 'id') chal raha ho, to startup ka ALTER
                    // TABLE fix kabhi silently fail ho sakta hai (jaise DB user ke
                    // paas ALTER privilege na ho, ya woh fix us waqt DB se connect
                    // hi na ho paaya ho). Pehle is wajah se "Field 'id' doesn't
                    // have a default value" seedha user tak chala jaata tha. Ab
                    // agar yehi specific error aaye, to hum turant khud ALTER
                    // TABLE chala kar 'id' ko AUTO_INCREMENT bana dete hain aur
                    // INSERT ko ek baar khud-b-khud retry karte hain — user ko
                    // dobara try karne ki zaroorat nahi padti.
                    if (err && !retryDone && /doesn't have a default value/i.test(err.message)) {
                        console.warn('⚠️ material_bills.id AUTO_INCREMENT missing tha — auto-fix karke retry kar rahe hain...');
                        db.query('ALTER TABLE material_bills MODIFY COLUMN id INT NOT NULL AUTO_INCREMENT', (fixErr) => {
                            if (fixErr) {
                                console.error('❌ material_bills id auto-fix fail hua:', fixErr.message);
                                return res.status(500).json({ error: 'DB error: ' + err.message });
                            }
                            console.log('✅ material_bills.id AUTO_INCREMENT auto-fix ho gaya, ab retry kar rahe hain');
                            doInsert(true);
                        });
                        return;
                    }
                    if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
                    res.status(201).json({ id: result.insertId, updated: false });
                });
            };
            doInsert(false);
        }
    });
});
app.get('/api/material/bills', (req, res) => {
    const ownerUserId = req.query.ownerUserId;
    const sql = ownerUserId ? 'SELECT * FROM material_bills WHERE ownerUserId=? ORDER BY savedAt DESC' : 'SELECT * FROM material_bills ORDER BY savedAt DESC';
    db.query(sql, ownerUserId ? [ownerUserId] : [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        res.json((rows || []).map(r => { try { return Object.assign(JSON.parse(r.data), { id: r.id, savedAt: r.savedAt }); } catch (e) { return { id: r.id, savedAt: r.savedAt }; } }));
    });
});
app.put('/api/material/bills/:id', (req, res) => {
    db.query('SELECT ownerUserId, data FROM material_bills WHERE id=?', [req.params.id], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        if (!rows || !rows.length) return res.status(404).json({ error: 'Bill nahi mila.' });
        // 🆕 SECURITY FIX: pehle koi bhi logged-in material user, ID guess
        // karke doosre user ka bill edit kar sakta tha. Ab check karte hain
        // ki jo ownerUserId request mein bheja gaya hai, wahi is bill ka
        // asli malik ho — warna edit reject ho jaayega.
        const requestOwnerId = (req.body || {}).ownerUserId;
        if (requestOwnerId && rows[0].ownerUserId && requestOwnerId !== rows[0].ownerUserId) {
            return res.status(403).json({ error: 'Yeh bill aapka nahi hai — edit nahi kar sakte.' });
        }
        let merged = {};
        try { merged = JSON.parse(rows[0].data); } catch (e) {}
        Object.assign(merged, req.body || {});
        db.query('UPDATE material_bills SET data=? WHERE id=?', [JSON.stringify(merged), req.params.id], (uErr) => {
            if (uErr) return res.status(500).json({ error: 'DB error: ' + uErr.message });
            res.json({ success: true });
        });
    });
});
app.delete('/api/material/bills/:id', (req, res) => {
    db.query('DELETE FROM material_bills WHERE id=?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        res.json({ success: true });
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

// ══════════════════════════════════════════════════════════════════
// 🛡️ SAFETY NET — yeh sabse aakhri mein aata hai (upar ke SAARE routes
//   define ho jaane ke baad — isliye /api/health jaisi cheezein isse
//   pehle hi match ho jaati hain, yeh sirf bacha hua traffic pakadta hai).
//   Kaam: kabhi bhi frontend ko HTML na mile, hamesha JSON hi mile —
//   chahe route na mila ho, chahe upload fail hua ho, chahe koi aur
//   unexpected error aaya ho. Isi wajah se "Unexpected token '<',
//   <!DOCTYPE" jaisi errors dobara kabhi nahi aayengi.
// ══════════════════════════════════════════════════════════════════

// 1) Koi bhi /api/* route jo upar define nahi hua — HTML 404 ki jagah JSON 404
app.use('/api', (req, res) => {
    res.status(404).json({ error: 'Yeh API route maujood nahi hai: ' + req.method + ' ' + req.originalUrl });
});

// 2) Global error handler — Multer errors (file bahut badi/galat field name)
//    aur koi bhi anya crash yahan pakda jaata hai, JSON ki tarah bheja jaata hai
app.use((err, req, res, next) => {
    console.error('❌ Unhandled error:', err && err.message);
    if (err && err.name === 'MulterError') {
        let msg = 'File upload mein error: ' + err.message;
        if (err.code === 'LIMIT_FILE_SIZE') msg = 'File bahut badi hai (max 20MB allowed).';
        return res.status(400).json({ error: msg });
    }
    res.status(500).json({ error: (err && err.message) || 'Server mein anjaan error aaya.' });
});

// ══════════════════════════════════════════════════════════════════
// 🛡️ PROCESS-LEVEL SAFETY NET — agar kahin bhi (kisi bhi route ke
//   db.query callback, bcrypt, jwt, waghera mein) koi unexpected error
//   throw ho jaaye jo upar wale error-handler tak nahi pahunch paata
//   (kyunki woh sirf route ke andar wale synchronous throws pakadta
//   hai, deeply-nested async callbacks ke throws nahi), to NORMALLY
//   Node.js poora process crash kar deta — matlab TURANT us waqt jo
//   bhi user site use kar raha ho, sabke liye "Failed to fetch" (server
//   se koi jawab hi nahi) aa jaata, jab tak Render dobara restart na kare.
//   Ab aisi koi bhi crash sirf LOG hogi, server chalta rahega — sirf
//   wahi ek request fail hogi, baaki poori site chalti rahegi.
// ══════════════════════════════════════════════════════════════════
process.on('uncaughtException', (err) => {
    console.error('🚨 UNCAUGHT EXCEPTION (server crash rukwaya gaya):', err && err.stack);
});
process.on('unhandledRejection', (reason) => {
    console.error('🚨 UNHANDLED PROMISE REJECTION (server crash rukwaya gaya):', reason);
});

// Start Server
app.listen(PORT, () => {
    console.log(`🚀 Server chalu hua port ${PORT} par`);
});
