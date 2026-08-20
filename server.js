const express = require('express');
const { Pool } = require('pg'); // 🆕 Supabase (PostgreSQL) ke liye pg package
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');

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

/* --------------------------------------------------------------------------
   Database Connection (Supabase / PostgreSQL Pool)
-------------------------------------------------------------------------- */
const db = new Pool({
    connectionString: process.env.DATABASE_URL, // Supabase ka connection string Render env mein rahega
    ssl: {
        rejectUnauthorized: false
    }
});

// PostgreSQL ke liye query helper taaki aapke purane mysql query format ('SELECT * FROM users WHERE id = ?', [id]) ko 
// automatically PostgreSQL format ($1, $2...) mein convert kiya ja sake ya aap seedhe use kar sakein.
// Lekin agar aapne query likhi hain, toh dhyan rakhein ki Postgres $1, $2 use karta hai.
db.query = async function (text, params, callback) {
    if (typeof params === 'function') {
        callback = params;
        params = undefined;
    }
    try {
        // MySQL ke '?' placeholders ko PostgreSQL ke '$1, $2, $3...' mein automatically badalne ka jugaad
        let paramIndex = 1;
        const convertedText = text.replace(/\?/g, () => `$${paramIndex++}`);
        
        const start = Date.now();
        const res = await Pool.prototype.query.call(db, convertedText, params);
        const duration = Date.now() - start;
        
        if (callback) callback(null, res.rows, res);
        return res;
    } catch (err) {
        console.error('❌ Database Query Error:', err.message, 'SQL:', text);
        if (callback) callback(err, null, null);
        throw err;
    }
};

db.on('error', (err) => {
    console.error('❌ Unexpected error on idle PostgreSQL client', err);
});

const JWT_SECRET = process.env.JWT_SECRET;

const REQUIRED_ENV = ['DATABASE_URL', 'JWT_SECRET'];
const missingEnv = REQUIRED_ENV.filter(k => !process.env[k]);
if (missingEnv.length) {
    console.error('❌ Missing Environment Variables: ' + missingEnv.join(', '));
}

console.log('🔍 Supabase Database connect try ho raha hai...');

// Tables setup for Supabase (PostgreSQL syntax)
db.connect((err, client, release) => {
    if (err) {
        console.error('❌ Supabase DB connection fail hua:', err.stack);
    } else {
        console.log('✓ Supabase Database se successfully connection jud gaya hai!');
        release();

        // Tables creation
        client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role VARCHAR(50) DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `).catch(e => console.error('Users table error:', e.message));

        client.query(`
            CREATE TABLE IF NOT EXISTS material_user_requests (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                village VARCHAR(255),
                address VARCHAR(500),
                email VARCHAR(255),
                mobile VARCHAR(20) NOT NULL,
                photo TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `).catch(e => console.error('Material requests table error:', e.message));

        client.query(`
            CREATE TABLE IF NOT EXISTS material_users (
                id SERIAL PRIMARY KEY,
                userId VARCHAR(50) UNIQUE NOT NULL,
                name VARCHAR(255) NOT NULL,
                village VARCHAR(255),
                address VARCHAR(500),
                email VARCHAR(255),
                mobile VARCHAR(20) UNIQUE NOT NULL,
                photo TEXT,
                password_hash VARCHAR(255),
                status VARCHAR(20) DEFAULT 'active',
                blockedReason VARCHAR(500),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `).catch(e => console.error('Material users table error:', e.message));
    }
});

// (बाकी का आपका सारा कोड यहाँ सुरक्षित रहेगा)
