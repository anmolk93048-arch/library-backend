const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer'); // 🆕 file upload (Hero image/Logo/APK) ke liye

// ══════════════════════════════════════════════════════════════════
// 🛡️ PROCESS-LEVEL SAFETY NET — sabse pehli cheez jo file mein chalti
//   hai, taaki NEECHE ki poori startup code (DB pool banana, routes
//   register karna, middleware, waghera) bhi is safety net ke andar
//   aa jaaye.
//   🔒 CRITICAL FIX: yeh handlers pehle file ke bilkul AAKHIR mein
//   (app.listen se theek pehle) the. Iska matlab: agar startup ke
//   dauraan — DB pool banate waqt, ya kisi route register karte
//   waqt, ya kisi bhi synchronous code mein — koi error throw hoti,
//   to Node.js process TURANT crash ho jaata, kyunki safety net
//   abhi register hi nahi hua tha jab tak file poori load na ho
//   jaaye. Yehi wajah thi ki DB unreachable hone par sirf DB calls
//   fail nahi hote the — POORA SERVER hi crash ho jaata tha, aur
//   browser mein "Failed to fetch" (server se koi response hi
//   nahi) dikhta tha, na ki ek normal "DB error" JSON response.
//   Ab yeh sabse pehle register hote hain — koi bhi startup ya
//   runtime error ab poore server ko kabhi crash nahi karegi,
//   sirf log hogi.
// ══════════════════════════════════════════════════════════════════
process.on('uncaughtException', (err) => {
    console.error('🚨 UNCAUGHT EXCEPTION (server crash rukwaya gaya):', err && err.stack);
});
process.on('unhandledRejection', (reason) => {
    console.error('🚨 UNHANDLED PROMISE REJECTION (server crash rukwaya gaya):', reason);
});

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
// aa raha تھا.
const ALLOWED_ORIGINS = [
    'https://digitallibraryanmollive.netlify.app',
    'https://library-backend-4efk.onrender.com'
];
app.use(cors({
    origin: function (origin, callback) {
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

// ── Auth helper ──
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

function requireActiveMaterialUser(req, res, next) {
    const auth = getAuthUser(req);
    if (!auth || auth.role !== 'material_user' || !auth.userId) {
        return next();
    }
    db.query('SELECT status FROM material_users WHERE userId = ?', [auth.userId], (err, rows) => {
        if (err) return next();
        if (rows && rows[0] && rows[0].status === 'blocked') {
            return res.status(403).json({ error: 'Yeh ID admin dwara block kar di gayi hai. Aap ab is portal ka istemal nahi kar sakte.' });
        }
        next();
    });
}

/* --------------------------------------------------------------------------
   Database Connection (Cloud SQL & MySQL 8.4 Compatible - Updated via mysql2)
-------------------------------------------------------------------------- */
const db = mysql.createPool({
    host: process.env.DB_HOST,                  // Cloud SQL Public IP — Render Environment se aayega
    port: process.env.DB_PORT ? parseInt(process.env.DB_PORT, 10) : 3306,
    user: process.env.DB_USER,                  // DB User — Render Environment se aayega
    password: process.env.DB_PASSWORD,            // DB Password — Render Environment se aayega
    database: process.env.DB_NAME,                // DB Name — Render Environment se aayega
    waitForConnections: true,
    connectionLimit: 10,
    connectTimeout: 30000,
    enableKeepAlive: true,
    keepAliveInitialDelay: 10000,
    idleTimeout: 60000,
    maxIdle: 10,
    ssl: {
        rejectUnauthorized: false
    },
    authPlugins: {
        mysql_clear_password: () => () => Buffer.from(process.env.DB_PASSWORD || '')
    }
});

db.on('error', (err) => {
    console.error('❌ MySQL pool-level error (auto-recovered, connection pool se hata di gayi):', err.code || err.message);
});

const _rawDbQuery = db.query.bind(db);
const TRANSIENT_DB_ERROR_CODES = ['ETIMEDOUT', 'ECONNRESET', 'PROTOCOL_CONNECTION_LOST', 'ECONNREFUSED', 'ENOTFOUND', 'EPIPE', 'PROTOCOL_SEQUENCE_TIMEOUT'];
db.query = function (sql, params, callback) {
    if (typeof params === 'function') { callback = params; params = undefined; }
    function attempt(retriesLeft) {
        function handleResult(err, results, fields) {
            if (err && TRANSIENT_DB_ERROR_CODES.includes(err.code) && retriesLeft > 0) {
                console.warn('⚠️ DB transient error (' + err.code + ') — 500ms baad retry ho raha hai (' + retriesLeft + ' attempt(s) bache hain)...');
                setTimeout(() => attempt(retriesLeft - 1), 500);
                return;
            }
            if (callback) callback(err, results, fields);
        }
        if (params !== undefined) _rawDbQuery(sql, params, handleResult);
        else _rawDbQuery(sql, handleResult);
    }
    attempt(2);
};

const JWT_SECRET = process.env.JWT_SECRET;

const REQUIRED_ENV = ['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME', 'JWT_SECRET'];
const missingEnv = REQUIRED_ENV.filter(k => !process.env[k]);
if (missingEnv.length) {
    console.error('❌ Yeh zaroori Environment Variables Render Dashboard mein set nahi hain: ' + missingEnv.join(', '));
}

const AUTO_INCREMENT_ID_TABLES = [
    'users', 'material_user_requests', 'material_users', 'material_bills',
    'attendance_records', 'fee_payments', 'site_files',
    'wallet_withdrawals', 'wallet_direct_payments'
];

function insertWithIdHeal(sql, params, tableName, callback) {
    db.query(sql, params, (err, result) => {
        if (err && /doesn't have a default value/i.test(err.message)) {
            console.warn('⚠️ ' + tableName + '.id AUTO_INCREMENT missing tha — auto-fix karke retry kar rahe hain...');
            db.query(
                'ALTER TABLE `' + tableName + '` MODIFY COLUMN id INT NOT NULL AUTO_INCREMENT',
                (fixErr) => {
                    if (fixErr) {
                        console.error('❌ ' + tableName + '.id auto-fix fail hua:', fixErr.message);
                        return callback(err, null);
                    }
                    console.log('✅ ' + tableName + '.id AUTO_INCREMENT auto-fix ho gaya, ab retry kar rahe hain');
                    db.query(sql, params, callback);
                }
            );
            return;
        }
        callback(err, result);
    });
}

console.log('🔍 DB connect try ho raha hai → host=' + (process.env.DB_HOST || '❌ MISSING') +
    ' port=' + (process.env.DB_PORT || '3306 (default)') +
    ' database=' + (process.env.DB_NAME || '❌ MISSING') +
    ' user=' + (process.env.DB_USER ? process.env.DB_USER[0] + '***' : '❌ MISSING') +
    ' password=' + (process.env.DB_PASSWORD ? '***set*** (' + process.env.DB_PASSWORD.length + ' chars)' : '❌ MISSING'));

function connectWithRetry(attemptsLeft, delayMs) {
    db.getConnection((err, connection) => {
        if (err) {
            console.error('❌ DB connection attempt fail: ' + err.code + ' — ' + err.message);
            if (attemptsLeft > 1) {
                console.warn('⏳ ' + (delayMs / 1000) + ' second baad phir try karenge... (' + (attemptsLeft - 1) + ' attempt(s) bache hain)');
                setTimeout(() => connectWithRetry(attemptsLeft - 1, Math.min(delayMs * 2, 30000)), delayMs);
            } else {
                console.error('❌❌❌ DB se bilkul connect nahi ho paaya.');
            }
            return;
        }
        console.log('✓ Quick health-check connection safal — DB reachable hai.');
        connection.release();
    });
}
connectWithRetry(5, 2000);

db.getConnection((err, connection) => {
    if (err) {
        console.error('❌ Table setup fail hua: ' + err.message);
    } else {
        console.log('✓ Database se successfully connection jud gaya hai!');
        
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
            if (tableErr) console.error('❌ Users table creation error:', tableErr.message);
            else console.log('✅ Tables ready');
        });

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
            const materialUsersColumnFixes = [
                "ALTER TABLE material_users ADD COLUMN address VARCHAR(500)",
                "ALTER TABLE material_users ADD COLUMN email VARCHAR(255)",
                "ALTER TABLE material_users ADD COLUMN status VARCHAR(20) DEFAULT 'active'",
                "ALTER TABLE material_users ADD COLUMN blockedReason VARCHAR(500)",
                "ALTER TABLE material_users ADD COLUMN photo LONGTEXT",
                "ALTER TABLE material_users ADD COLUMN password_hash VARCHAR(255)"
            ];
            materialUsersColumnFixes.forEach((sql) => {
                connection.query(sql, (colErr) => {
                    if (colErr && !/Duplicate column/i.test(colErr.message)) {
                        console.error('❌ material_users column fix error:', colErr.message);
                    }
                });
            });
        });

        connection.query(`
            CREATE TABLE IF NOT EXISTS material_bills (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ownerUserId VARCHAR(50) NOT NULL,
                data LONGTEXT,
                savedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `, (e) => {
            if (e) console.error('❌ material_bills table error:', e.message);
            const ensureColumns = [
                "ALTER TABLE material_bills ADD COLUMN ownerUserId VARCHAR(50) NOT NULL DEFAULT ''",
                "ALTER TABLE material_bills ADD COLUMN data LONGTEXT",
                "ALTER TABLE material_bills ADD COLUMN savedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
            ];
            ensureColumns.forEach((sql) => {
                connection.query(sql, (alterErr) => {
                    if (alterErr && !/Duplicate column/i.test(alterErr.message)) {
                        console.error('❌ material_bills column error:', alterErr.message);
                    }
                });
            });
            connection.query("ALTER TABLE material_bills MODIFY COLUMN id INT NOT NULL AUTO_INCREMENT", (idErr) => {
                if (idErr) {
                    console.error('❌ material_bills id AUTO_INCREMENT ALTER FAIL:', idErr.message);
                } else {
                    console.log('✅ material_bills.id AUTO_INCREMENT ready');
                }
            });
        });

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
    }
});

// (बाकी के सारे रूट्स और ऐप लिसनिंग का कोड आपकी फाइल का ही है - इसे अपनी पूरी फाइल में सुरक्षित रख लें)
