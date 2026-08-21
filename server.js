const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer'); // 🆕 file upload (Hero image/Logo/APK) ke liye

// ══════════════════════════════════════════════════════════════════
// 🛡️ PROCESS-LEVEL SAFETY NET
// ══════════════════════════════════════════════════════════════════
process.on('uncaughtException', (err) => {
    console.error('🚨 UNCAUGHT EXCEPTION (server crash rukwaya gaya):', err && err.stack);
});
process.on('unhandledRejection', (reason) => {
    console.error('🚨 UNHANDLED PROMISE REJECTION (server crash rukwaya gaya):', reason);
});

const app = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1);

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
   Database Connection
-------------------------------------------------------------------------- */
const db = mysql.createPool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT ? parseInt(process.env.DB_PORT, 10) : 3306,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
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
    console.error('❌ MySQL pool-level error:', err.code || err.message);
});

const _rawDbQuery = db.query.bind(db);
const TRANSIENT_DB_ERROR_CODES = ['ETIMEDOUT', 'ECONNRESET', 'PROTOCOL_CONNECTION_LOST', 'ECONNREFUSED', 'ENOTFOUND', 'EPIPE', 'PROTOCOL_SEQUENCE_TIMEOUT'];
db.query = function (sql, params, callback) {
    if (typeof params === 'function') { callback = params; params = undefined; }
    function attempt(retriesLeft) {
        function handleResult(err, results, fields) {
            if (err && TRANSIENT_DB_ERROR_CODES.includes(err.code) && retriesLeft > 0) {
                console.warn('⚠️ DB transient error — retry ho raha hai...');
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
    console.error('❌ Yeh zaroori Environment Variables set nahi hain: ' + missingEnv.join(', '));
}

// ── TABLES INITIALIZATION ──────────────────────────────────────────
db.getConnection((err, connection) => {
    if (err) {
        console.error('❌ Table setup fail hua: ' + err.message);
    } else {
        console.log('✓ Database se successfully connection jud gaya hai!');
        connection.release();
    }
});

// ══════════════════════════════════════════════════════════════════
// 🚀 SERVER STARTUP — Yeh sabse zaroori hai taaki server band na ho
// ══════════════════════════════════════════════════════════════════
app.listen(PORT, () => {
    console.log(`🚀 Server is successfully running on port ${PORT}`);
});
