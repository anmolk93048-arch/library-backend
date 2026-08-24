const express = require('express');
const { Pool } = require('pg');
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

// 🆕 PERMANENT FIX for "Block karne par bhi user login/kaam karta rehta hai":
//   Login-time JWT token 7 din tak valid rehta hai aur usme sirf userId/role
//   store hota hai — agar Admin kisi CURRENTLY LOGGED-IN user ko beech mein
//   block kar de, to purana token khud-ba-khud invalid nahi hota (JWT ka yehi
//   design hai)। Isliye material-user ke har sensitive action (bill save/edit/
//   delete, mobile number change) par yeh middleware turant DB se current
//   status dobara check karta hai — token valid hone ke bawajood block hote
//   hi agli hi request se turant 403 mil jaata hai, session khatam hone ka
//   intezaar nahi karna padta.
function requireActiveMaterialUser(req, res, next) {
    const auth = getAuthUser(req);
    if (!auth || auth.role !== 'material_user' || !auth.userId) {
        // Token na ho / kisi aur role ka ho — purana behavior hi chalne do
        // (yeh routes pehle bhi bina is check ke kaam karte the).
        return next();
    }
    db.query('SELECT status FROM material_users WHERE userId = ?', [auth.userId], (err, rows) => {
        if (err) return next(); // DB check fail ho jaaye to request block mat karo
        if (rows && rows[0] && rows[0].status === 'blocked') {
            return res.status(403).json({ error: 'Yeh ID admin dwara block kar di gayi hai. Aap ab is portal ka istemal nahi kar sakte.' });
        }
        next();
    });
}

/* --------------------------------------------------------------------------
   Database Connection (Supabase / PostgreSQL Compatible)
-------------------------------------------------------------------------- */

// insertWithIdHeal — Postgres mein 'id SERIAL PRIMARY KEY' hamesha khud
// apna default value (sequence se) leta hai, isliye MySQL wali "Field 'id'
// doesn't have a default value" error yahan kabhi aa hi nahi sakti — is
// function ka self-heal/retry hissa is liye ab zaroori nahi raha. Function
// wahi rehta hai (sirf db.query ko forward karta hai) taaki neeche ke ~15
// call sites bina badle chalte rahein.
function insertWithIdHeal(sql, params, tableName, callback) {
    db.query(sql, params, callback);
}
const db = new Pool(
    process.env.DATABASE_URL
        ? {
            // Supabase Connection String (Project Settings → Database → Connection string
            // → "URI" ya "Connection pooling"). Format:
            // postgresql://postgres:[PASSWORD]@[HOST]:5432/postgres
            connectionString: process.env.DATABASE_URL,
            ssl: { rejectUnauthorized: false },
            connectionTimeoutMillis: 30000,
            idleTimeoutMillis: 60000,
            keepAlive: true,
            keepAliveInitialDelayMillis: 10000,
            max: 10
        }
        : {
            // Discrete params (agar DATABASE_URL na ho to fallback) — Supabase
            // Project Settings → Database mein yeh sab alag-alag bhi milte hain.
            host: process.env.DB_HOST,
            port: process.env.DB_PORT ? parseInt(process.env.DB_PORT, 10) : 5432,
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD,
            database: process.env.DB_NAME,
            ssl: { rejectUnauthorized: false },
            connectionTimeoutMillis: 30000,
            idleTimeoutMillis: 60000,
            keepAlive: true,
            keepAliveInitialDelayMillis: 10000,
            max: 10
        }
);

// 🆕 Pool-level error handler — agar koi idle connection background mein
// khud hi drop ho jaaye, to Node.js process crash nahi hoga, sirf log hoga.
db.on('error', (err) => {
    console.error('❌ Postgres pool-level error (auto-recovered, connection pool se hata di gayi):', err.code || err.message);
});

// ══════════════════════════════════════════════════════════════════
// 🔄 MYSQL2 → PG COMPATIBILITY SHIM
//   Poori file mein ~90+ jagah `db.query(sql, params, callback)` MySQL2
//   ke andaaz mein likha hua hai: '?' placeholders, backtick-quoted
//   column naam (jaise `key`), callback mein seedhe 'rows' array milna
//   (SELECT ke liye), aur 'result.insertId'/'result.affectedRows' milna
//   (INSERT/UPDATE/DELETE ke liye). node-postgres (pg) in sabka format
//   alag hai — '$1,$2' placeholders, double-quote identifiers, callback
//   mein '{rows, rowCount}' object.
//   Is shim ka maksad: NEECHE ki saari 90+ existing routes BINA CHHUE
//   kaam karte rahein — SQL text ko yahin (ek hi jagah) convert kar
//   diya jaata hai, aur pg ka result wapas mysql2-jaisi shape mein de
//   diya jaata hai.
// ══════════════════════════════════════════════════════════════════
const TRANSIENT_DB_ERROR_CODES = [
    'ETIMEDOUT', 'ECONNRESET', 'ECONNREFUSED', 'ENOTFOUND', 'EPIPE',
    '57P03', // cannot_connect_now
    '08006', // connection_failure
    '08001', // sqlclient_unable_to_establish_sqlconnection
    '08004'  // sqlserver_rejected_establishment_of_sqlconnection
];

// Tables jinke 'id' column par SERIAL (auto-increment) hai — INSERT ke baad
// '.insertId' chahiye to yahan RETURNING id khud-b-khud jud jaata hai.
const AUTO_ID_TABLES = new Set([
    'users', 'material_user_requests', 'material_users', 'material_bills',
    'attendance_records', 'fee_payments', 'site_files',
    'wallet_withdrawals', 'wallet_direct_payments'
]);

function convertSqlToPg(sql) {
    // MySQL backtick identifiers → Postgres double-quote identifiers
    let out = sql.replace(/`([^`]+)`/g, '"$1"');
    // '?' positional placeholders → '$1, $2, ...' (order-preserving)
    let i = 0;
    out = out.replace(/\?/g, () => '$' + (++i));
    // Agar INSERT INTO kisi AUTO_ID table mein hai aur RETURNING already
    // nahi hai, to '.insertId' compatibility ke liye khud jod dete hain.
    if (/^\s*INSERT\s+INTO/i.test(out) && !/RETURNING/i.test(out)) {
        const m = /^\s*INSERT\s+INTO\s+"?(\w+)"?/i.exec(out);
        if (m && AUTO_ID_TABLES.has(m[1])) {
            out = out.replace(/;\s*$/, '') + ' RETURNING id';
        }
    }
    return out;
}

const _rawPgQuery = db.query.bind(db);
db.query = function (sql, params, callback) {
    // db.query(sql, cb) aur db.query(sql, params, cb) — dono call-styles support karo
    if (typeof params === 'function') { callback = params; params = undefined; }
    const pgSql = convertSqlToPg(sql);
    const pgParams = params !== undefined ? params : [];
    function attempt(retriesLeft) {
        _rawPgQuery(pgSql, pgParams, (err, result) => {
            if (err && TRANSIENT_DB_ERROR_CODES.includes(err.code) && retriesLeft > 0) {
                console.warn('⚠️ DB transient error (' + err.code + ') — 500ms baad retry ho raha hai (' + retriesLeft + ' attempt(s) bache hain)...');
                setTimeout(() => attempt(retriesLeft - 1), 500);
                return;
            }
            if (err) { if (callback) callback(err); return; }
            // mysql2-compatible shape: rows array (SELECT ke liye) + usi
            // array par insertId/affectedRows properties (INSERT/UPDATE/
            // DELETE consumers ke liye) — JS arrays objects hi hain, isliye
            // dono ek saath chal sakte hain.
            const compat = result.rows || [];
            compat.insertId = (result.rows && result.rows[0] && result.rows[0].id) || undefined;
            compat.affectedRows = result.rowCount || 0;
            if (callback) callback(null, compat, result.fields);
        });
    }
    attempt(2); // pehli koshish + 2 retries = total 3 attempts
};

// `db.getConnection()` (startup table-setup ke liye) — pg Pool mein iska
// naam `.connect()` hai aur release ek alag callback-param hoti hai; yeh
// shim usi connection object par mysql2-jaisa `.release()` method jod
// deta hai taaki neeche ka startup code bina badle chal sake.
const _rawPgConnect = db.connect.bind(db);
db.getConnection = function (cb) {
    _rawPgConnect(function (err, client, releaseFn) {
        if (err) return cb(err);
        client.release = releaseFn;
        cb(null, client);
    });
};

const JWT_SECRET = process.env.JWT_SECRET;

// 🔒 SECURITY: pehle DB password aur JWT secret seedhe code mein likhe the
// (agar yeh code kabhi public GitHub repo mein hota, to password sabko dikh
// jaata). Ab sab kuch sirf Render ke Environment Variables se aata hai —
// koi bhi secret ab is file mein kahin nahi likha. Agar zaroori variable
// missing ho, to server turant clearly bata dega (chup-chaap galat/khaali
// credential se connect karne ki koshish nahi karega).
const REQUIRED_ENV = process.env.DATABASE_URL ? ['DATABASE_URL', 'JWT_SECRET'] : ['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME', 'JWT_SECRET'];
const missingEnv = REQUIRED_ENV.filter(k => !process.env[k]);
if (missingEnv.length) {
    console.error('❌ Yeh zaroori Environment Variables Render Dashboard mein set nahi hain: ' + missingEnv.join(', '));
    console.error('   Render → apni service → Environment tab mein jaakar inhe add karein, warna DB/login features kaam nahi karenge.');
}

// 🆕 DIAGNOSTIC LOG: exact config (password masked) jo istemal ho raha hai —
// taaki agar connection fail ho to Render Logs mein turant dikh jaaye ki
// KAUN SA host/port/database/user try ho raha hai. "Total outage" (yaani
// HAR route fail ho raha ho) zyada tar in wajahon se hoti hai, jinhe
// timeout/retry jaisi client-side tuning theek nahi kar sakti:
//   1. DATABASE_URL (ya DB_HOST/DB_PORT) galat hai Render Environment mein
//   2. Supabase project paused pada hai (free-tier projects kuch din ki
//      inactivity ke baad khud paused ho jaate hain — Supabase Dashboard
//      kholkar "Restore project" karna padta hai)
//   3. DB_USER/DB_PASSWORD galat hai
if (process.env.DATABASE_URL) {
    console.log('🔍 DB connect try ho raha hai → DATABASE_URL se (connection string) — set hai ✓');
} else {
    console.log('🔍 DB connect try ho raha hai → host=' + (process.env.DB_HOST || '❌ MISSING') +
        ' port=' + (process.env.DB_PORT || '5432 (default)') +
        ' database=' + (process.env.DB_NAME || '❌ MISSING') +
        ' user=' + (process.env.DB_USER ? process.env.DB_USER[0] + '***' : '❌ MISSING') +
        ' password=' + (process.env.DB_PASSWORD ? '***set*** (' + process.env.DB_PASSWORD.length + ' chars)' : '❌ MISSING'));
}

// 🆕 Startup par bhi retry-with-backoff — agar DB thodi der ke liye
// unreachable ho (jaise Render aur DB ek saath cold-start ho rahe hon),
// to sirf ek baar try karke haar maan lene ki bajaye 5 baar, badhte hue
// gap ke saath, try karta hai. Yeh sirf ek quick health-check hai —
// asli table-setup (neeche) apne aap chalta hai jaise pehle chalta tha.
function connectWithRetry(attemptsLeft, delayMs) {
    db.getConnection((err, connection) => {
        if (err) {
            console.error('❌ DB connection attempt fail: ' + err.code + ' — ' + err.message);
            if (attemptsLeft > 1) {
                console.warn('⏳ ' + (delayMs / 1000) + ' second baad phir try karenge... (' + (attemptsLeft - 1) + ' attempt(s) bache hain)');
                setTimeout(() => connectWithRetry(attemptsLeft - 1, Math.min(delayMs * 2, 30000)), delayMs);
            } else {
                console.error('❌❌❌ DB se bilkul connect nahi ho paaya. Yeh checklist verify karein:');
                console.error('   1. Render → Environment tab → DATABASE_URL (ya DB_HOST/DB_PORT/DB_USER/DB_PASSWORD/DB_NAME) sahi hain?');
                console.error('   2. Supabase Dashboard mein project "Paused" to nahi hai? (free-tier projects kuch din ki inactivity ke baad khud paused ho jaate hain)');
                console.error('   3. Supabase → Project Settings → Database → Connection string (URI) sahi copy kiya gaya hai?');
                console.error('   4. Yeh PostgreSQL database hai — agar aapne kahin MySQL/mysql2 setup kiya hai wahan yeh config apply nahi hoga.');
                console.error('   Server phir bhi chalta rahega aur naye connection attempts karta rahega jab bhi koi request aayegi.');
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
        return;
    }
    console.log('✓ Database se successfully connection jud gaya hai!');

    // 🆕 Postgres mein columns UNQUOTED likhne par khud-b-khud lowercase ho
    // jaate hain (jaise ownerUserId → owneruserid) — poori file mein saari
    // queries bhi inhe kahin quote nahi karti (sirf `key` backtick se aata
    // hai, jo shim ne upar "key" mein convert kiya hai), isliye yeh consistent
    // rehta hai aur sab kuch bina kisi extra rename ke match karta hai.
    const DDL_STATEMENTS = [
        ['users', `
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role VARCHAR(50) DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `],
        // 🆕 Material user pending-registration requests (Anmol_material_entry_secure.html
        // ke "रजिस्ट्रेशन अनुरोध भेजें" form se yahan aata hai, admin approve karta hai)
        ['material_user_requests', `
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
        `],
        // 🆕 Approved material users / agents (jinhe userId + password mil chuka hai
        // aur jo Anmol_material_entry_secure.html se login karke bill entry karte hain)
        ['material_users', `
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
        `],
        // 🆕 Material bills/invoices (Anmol_material_entry_secure.html)
        ['material_bills', `
            CREATE TABLE IF NOT EXISTS material_bills (
                id SERIAL PRIMARY KEY,
                ownerUserId VARCHAR(50) NOT NULL,
                data TEXT,
                savedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `],
        // 🆕 Generic key-value stores — admin-entities (admins/staff/agents/students
        // arrays) aur blob (settings/notices/mem_plans/... ) aur site-data (site
        // content JSON). Frontend hamesha poori array/object ek saath bhejta-padta
        // hai, isliye ek generic table kaafi hai. "key" quoted hai kyunki shim
        // backtick-columns (`key`) ko double-quote mein convert karta hai.
        ['kv_admin_entities', `
            CREATE TABLE IF NOT EXISTS kv_admin_entities (
                "key" VARCHAR(100) PRIMARY KEY,
                value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `],
        ['kv_blob', `
            CREATE TABLE IF NOT EXISTS kv_blob (
                "key" VARCHAR(100) PRIMARY KEY,
                value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `],
        ['kv_site_data', `
            CREATE TABLE IF NOT EXISTS kv_site_data (
                "key" VARCHAR(100) PRIMARY KEY,
                value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `],
        // 🆕 Attendance (date+batch pe keyed merge — Student_Attendance.html)
        ['attendance_records', `
            CREATE TABLE IF NOT EXISTS attendance_records (
                id SERIAL PRIMARY KEY,
                date VARCHAR(20) NOT NULL,
                batch VARCHAR(20) NOT NULL,
                records TEXT,
                selfies TEXT,
                markedBy VARCHAR(255),
                savedAt VARCHAR(50),
                UNIQUE (date, batch)
            )
        `],
        // 🆕 Student fee payments
        ['fee_payments', `
            CREATE TABLE IF NOT EXISTS fee_payments (
                id SERIAL PRIMARY KEY,
                studentId VARCHAR(100) NOT NULL,
                amount DECIMAL(10,2) NOT NULL,
                mode VARCHAR(50),
                note VARCHAR(500),
                status VARCHAR(20) DEFAULT 'paid',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `],
        // 🆕 Student → Agent direct-collect transactions (HRMS verify/reject flow)
        ['transactions', `
            CREATE TABLE IF NOT EXISTS transactions (
                id VARCHAR(50) PRIMARY KEY,
                agentId VARCHAR(100),
                studentId VARCHAR(100),
                amount DECIMAL(10,2) NOT NULL,
                status VARCHAR(20) DEFAULT 'pending',
                reason VARCHAR(500),
                data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `],
        // 🆕 HRMS salary slips (admin-generated) + claims (staff self-submitted)
        ['hrms_salary_slips', `
            CREATE TABLE IF NOT EXISTS hrms_salary_slips (
                id VARCHAR(50) PRIMARY KEY,
                empId VARCHAR(100),
                data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `],
        ['hrms_salary_claims', `
            CREATE TABLE IF NOT EXISTS hrms_salary_claims (
                id VARCHAR(50) PRIMARY KEY,
                empId VARCHAR(100),
                status VARCHAR(30) DEFAULT 'pending',
                agentId VARCHAR(100),
                netAmount DECIMAL(10,2),
                data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `],
        // 🆕 Agent wallets + withdrawals + direct payments
        ['agent_wallets', `
            CREATE TABLE IF NOT EXISTS agent_wallets (
                agentId VARCHAR(100) PRIMARY KEY,
                approved_balance DECIMAL(12,2) DEFAULT 0,
                pending_balance DECIMAL(12,2) DEFAULT 0,
                total_earned DECIMAL(12,2) DEFAULT 0
            )
        `],
        ['wallet_withdrawals', `
            CREATE TABLE IF NOT EXISTS wallet_withdrawals (
                id SERIAL PRIMARY KEY,
                agentId VARCHAR(100) NOT NULL,
                agentName VARCHAR(255),
                amount DECIMAL(10,2) NOT NULL,
                accName VARCHAR(255), bankName VARCHAR(255), accNo VARCHAR(50), ifsc VARCHAR(20),
                status VARCHAR(20) DEFAULT 'pending',
                reason VARCHAR(500),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `],
        ['wallet_direct_payments', `
            CREATE TABLE IF NOT EXISTS wallet_direct_payments (
                id SERIAL PRIMARY KEY,
                agentId VARCHAR(100) NOT NULL,
                amount DECIMAL(10,2) NOT NULL,
                note VARCHAR(500),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `],
        // 🆕 Student subscription Razorpay orders — jab order create hota hai
        // tabhi studentId/planId/days yahan save ho jaate hain, taaki verify
        // step client se dobara yeh values na maange (jo tamper ho sakti thin)
        // balki seedha yahi se padh kar student ko activate kare.
        ['student_subscription_orders', `
            CREATE TABLE IF NOT EXISTS student_subscription_orders (
                orderId VARCHAR(100) PRIMARY KEY,
                studentId VARCHAR(100) NOT NULL,
                planId VARCHAR(150),
                planName VARCHAR(150),
                days INT NOT NULL,
                amount DECIMAL(10,2) NOT NULL,
                status VARCHAR(20) DEFAULT 'created',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `],
        // 🆕 Agent subscription Razorpay orders — student_subscription_orders
        // jaisa hi, taaki verify step client se plan/amount/days dobara na
        // maange (jo tamper ho sakti thin) balki seedha yahi se padhe.
        ['agent_subscription_orders', `
            CREATE TABLE IF NOT EXISTS agent_subscription_orders (
                orderId VARCHAR(100) PRIMARY KEY,
                username VARCHAR(100) NOT NULL,
                planId VARCHAR(150),
                planName VARCHAR(150),
                days INT NOT NULL,
                amount DECIMAL(10,2) NOT NULL,
                status VARCHAR(20) DEFAULT 'created',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `],
        // 🆕 Customer Registration Razorpay orders — jab order create hota
        // hai tabhi customer ka naam/mobile/plan/amount yahan save ho jaate
        // hain, taaki verify step client se dobara yeh values na maange
        // (jo tamper ho sakti thin) balki seedha yahi se padhe.
        ['customer_registration_orders', `
            CREATE TABLE IF NOT EXISTS customer_registration_orders (
                orderId VARCHAR(100) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                mobile VARCHAR(20) NOT NULL,
                email VARCHAR(255),
                address VARCHAR(500),
                note VARCHAR(500),
                agentId VARCHAR(100) NOT NULL,
                planId VARCHAR(150),
                planName VARCHAR(150),
                amount DECIMAL(10,2) NOT NULL,
                status VARCHAR(20) DEFAULT 'created',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `],

        // 🆕 Uploaded files (Hero image / Logo / APK / login-page HTML) — DB mein
        // hi blob ki tarah store hote hain, kyunki Render ka disk restart/redeploy
        // pe reset ho jaata hai. 'slug': login-pages jaisi cheezon ko ek FIXED,
        // memorable URL deta hai (jaise /api/pages/agent-login) jo kabhi nahi
        // badalta — chahe file dobara upload/update kyun na ho jaaye. LONGBLOB →
        // BYTEA (Postgres ka binary-data type; node-postgres Buffer object ko
        // ismein seedha, bina kisi extra conversion ke, store kar deta hai).
        ['site_files', `
            CREATE TABLE IF NOT EXISTS site_files (
                id SERIAL PRIMARY KEY,
                slug VARCHAR(150) UNIQUE,
                folder VARCHAR(100),
                name VARCHAR(255),
                mime VARCHAR(150),
                size INT,
                data BYTEA,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `],
        // 🆕 GLOBAL NOTIFICATION SYSTEM — Admin→Agent, Admin→SabAgents,
        // Agent→Student, Agent→SabStudents, Agent→Employee, Agent→SabEmployees.
        // target_scope: 'agent' | 'all_agents' | 'student' | 'all_students' |
        //               'employee' | 'all_employees'
        // target_id: specific agentId/studentId/empId (all_* ke liye NULL)
        // scope_agent_id: 'all_students'/'all_employees' ke liye — kis agent
        //                 ke sabhi students/employees ko yeh jaayega
        // read_by: JSON array — jinhone padh liya unki id (agentId/studentId/
        //          empId/'admin') yahan add ho jaati hai
        ['notifications', `
            CREATE TABLE IF NOT EXISTS notifications (
                id SERIAL PRIMARY KEY,
                from_role VARCHAR(30) NOT NULL,
                from_name VARCHAR(255),
                target_scope VARCHAR(30) NOT NULL,
                target_id VARCHAR(100),
                scope_agent_id VARCHAR(100),
                title VARCHAR(255) NOT NULL,
                message TEXT,
                urgency VARCHAR(20) DEFAULT 'info',
                read_by TEXT DEFAULT '[]',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `]
    ];

    // 🆕 Purani (pehle se maujood) tables mein missing columns jodne ke liye —
    // Postgres ka 'ADD COLUMN IF NOT EXISTS' MySQL ke "Duplicate column error
    // ko catch karo" pattern se kaafi seedha/saaf hai, koi error-message
    // pattern-matching ki zaroorat nahi.
    const COLUMN_FIXES = [
        "ALTER TABLE material_users ADD COLUMN IF NOT EXISTS address VARCHAR(500)",
        "ALTER TABLE material_users ADD COLUMN IF NOT EXISTS email VARCHAR(255)",
        "ALTER TABLE material_users ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active'",
        "ALTER TABLE material_users ADD COLUMN IF NOT EXISTS blockedReason VARCHAR(500)",
        "ALTER TABLE material_users ADD COLUMN IF NOT EXISTS photo TEXT",
        "ALTER TABLE material_users ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255)",
        "ALTER TABLE material_bills ADD COLUMN IF NOT EXISTS ownerUserId VARCHAR(50) NOT NULL DEFAULT ''",
        "ALTER TABLE material_bills ADD COLUMN IF NOT EXISTS data TEXT",
        "ALTER TABLE material_bills ADD COLUMN IF NOT EXISTS savedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
        "ALTER TABLE site_files ADD COLUMN IF NOT EXISTS slug VARCHAR(150) UNIQUE"
    ];

    // 🆕 'updated_at' column ko row update hote hi khud-ba-khud "abhi" set
    // karne ke liye (MySQL ka 'ON UPDATE CURRENT_TIMESTAMP' — Postgres mein
    // yeh ek trigger se hota hai, inline column-option se nahi).
    const TRIGGER_SETUP = `
        CREATE OR REPLACE FUNCTION set_updated_at_now()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = CURRENT_TIMESTAMP;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    `;
    const TRIGGER_TABLES = ['kv_admin_entities', 'kv_blob', 'kv_site_data', 'site_files'];

    function runSequential(items, runOne, done) {
        let i = 0;
        function next() {
            if (i >= items.length) return done();
            runOne(items[i], () => { i++; next(); });
        }
        next();
    }

    runSequential(DDL_STATEMENTS, ([tableName, sql], cb) => {
        connection.query(sql, (e) => {
            if (e) console.error('❌ ' + tableName + ' table error:', e.message);
            cb();
        });
    }, () => {
        runSequential(COLUMN_FIXES, (sql, cb) => {
            connection.query(sql, (e) => {
                if (e) console.error('❌ Column fix error (' + sql + '):', e.message);
                cb();
            });
        }, () => {
            connection.query(TRIGGER_SETUP, (trigErr) => {
                if (trigErr) { console.error('❌ updated_at trigger function error:', trigErr.message); }
                runSequential(TRIGGER_TABLES, (t, cb) => {
                    connection.query(
                        `DROP TRIGGER IF EXISTS trg_set_updated_at ON ${t}; ` +
                        `CREATE TRIGGER trg_set_updated_at BEFORE UPDATE ON ${t} ` +
                        `FOR EACH ROW EXECUTE FUNCTION set_updated_at_now();`,
                        (e) => {
                            if (e) console.error('❌ ' + t + ' updated_at trigger error:', e.message);
                            cb();
                        }
                    );
                }, () => {
                    connection.release();
                    console.log('✅ Saari tables ready — koi bhi feature ab 404 nahi dega.');
                });
            });
        });
    });
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
        insertWithIdHeal(
            'INSERT INTO material_user_requests (name, village, address, email, mobile, photo) VALUES (?,?,?,?,?,?)',
            [name, village, address, email, mobile, photo || null],
            'material_user_requests',
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
            insertWithIdHeal(
                `INSERT INTO material_users (userId, name, village, address, email, mobile, photo, password_hash, status)
                 VALUES (?,?,?,?,?,?,?,?, 'active')`,
                [userId, r.name, r.village, r.address, r.email, r.mobile, r.photo, passwordHash],
                'material_users',
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
            insertWithIdHeal(
                `INSERT INTO material_users (userId, name, village, mobile, photo, password_hash, status)
                 VALUES (?,?,?,?,?,?,?)`,
                [userId, name, village, mobile, photo || null, passwordHash, status || 'active'],
                'material_users',
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

// 9) 🆕 Material user: login ke baad khud apna mobile number badalna
//   (Anmol_material_entry.html ke "मोबाइल नंबर बदलें" form se yahan aata
//   hai). Yeh route login-time wale JWT token se hi authenticate karta
//   hai — koi bhi doosre user ka mobile isse nahi badla ja sakta. Update
//   hote hi wahi row (material_users.mobile) badalti hai jise Admin Panel
//   bhi seedhe '/api/material/users' se padhta hai — isliye Admin ko bhi
//   turant naya number dikhne lagta hai. Frontend is response ke baad
//   khud user ko turant logout kar deta hai, taaki agli baar login sirf
//   naye mobile number se ho.
app.post('/api/material/change-mobile', requireActiveMaterialUser, (req, res) => {
    try {
        const auth = getAuthUser(req);
        if (!auth || auth.role !== 'material_user' || !auth.userId) {
            return res.status(401).json({ error: 'Session expire ho gaya hai. Kripya dobara login karein.' });
        }
        const rawMobile = req.body && req.body.newMobile;
        const newMobile = rawMobile != null ? String(rawMobile).trim() : '';
        const digitsOnly = newMobile.replace(/\D/g, '');
        if (digitsOnly.length !== 10) {
            return res.status(400).json({ error: 'Kripya sahi 10-digit mobile number dalein.' });
        }
        db.query('SELECT id, mobile FROM material_users WHERE userId = ?', [auth.userId], (err, rows) => {
            if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
            if (!rows || !rows.length) return res.status(404).json({ error: 'Yeh User ID nahi mila.' });
            const me = rows[0];
            // Duplicate check: koi aur material user isi mobile (last 10 digits
            // ke aadhar par, taaki formatting ka farq na pade) se registered na ho.
            db.query('SELECT id, mobile FROM material_users WHERE id != ?', [me.id], (dupErr, others) => {
                if (dupErr) return res.status(500).json({ error: 'DB error: ' + dupErr.message });
                const clash = (others || []).some(r => String(r.mobile || '').replace(/\D/g, '').slice(-10) === digitsOnly);
                if (clash) {
                    return res.status(409).json({ error: 'Yeh mobile number pehle se kisi aur ID se registered hai.' });
                }
                db.query('UPDATE material_users SET mobile = ? WHERE id = ?', [digitsOnly, me.id], (uErr) => {
                    if (uErr) return res.status(500).json({ error: 'DB error: ' + uErr.message });
                    res.json({ success: true, mobile: digitsOnly });
                });
            });
        });
    } catch (e) {
        res.status(500).json({ error: 'Server mein error aaya: ' + e.message });
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
    'razorpay_config', 'sms_api_config', 'agent_pending_registrations', 'customer_pending_registrations'];

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
        `INSERT INTO ${table} ("key", value) VALUES (?, ?) ON CONFLICT ("key") DO UPDATE SET value = EXCLUDED.value`,
        [key, json],
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
        'INSERT INTO kv_site_data ("key", value) VALUES (?, ?) ON CONFLICT ("key") DO UPDATE SET value = EXCLUDED.value',
        [req.params.key, json],
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
        insertWithIdHeal(
            `INSERT INTO site_files (slug, folder, name, mime, size, data) VALUES (?,?,?,?,?,?)
             ON CONFLICT (slug) DO UPDATE SET folder=EXCLUDED.folder, name=EXCLUDED.name, mime=EXCLUDED.mime, size=EXCLUDED.size, data=EXCLUDED.data`,
            [slug, folder, req.file.originalname, req.file.mimetype, req.file.size, req.file.buffer],
            'site_files',
            (err, result) => {
                if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
                respondWithFile(result.insertId);
            }
        );
    } else {
        insertWithIdHeal(
            'INSERT INTO site_files (folder, name, mime, size, data) VALUES (?,?,?,?,?)',
            [folder, req.file.originalname, req.file.mimetype, req.file.size, req.file.buffer],
            'site_files',
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
    // 🔒 FIX: MySQL mein VARCHAR comparison zyada tar case-insensitive hoti
    // hai (default collation), lekin Postgres mein '=' hamesha case-sensitive
    // hai. slugify() upload ke waqt hamesha lowercase karta hai, lekin yahan
    // URL se aaya slug seedha (bina lowercase kiye) compare ho raha tha —
    // isliye MySQL→Postgres migration ke baad koi bhi thoda different-case
    // URL (jaise /Admin-Login) match nahi karta tha, chahe file upload ho
    // chuki ho. Ab LOWER() dono taraf lagाya hai, taaki casing kabhi matter
    // na kare.
    db.query('SELECT name, mime, data FROM site_files WHERE LOWER(slug)=LOWER(?)', [req.params.slug], (err, rows) => {
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

// 🔒 FIX: pehle frontend khud hi agla SHL-XXX ID "guess" karta tha —
// sirf screen par abhi dikh rahe rows aur ek purani localStorage copy
// dekhkar. Agar table filtered ho, ya kisi doosre device/agent ne
// beech mein koi student add kiya ho jo abhi is browser mein sync
// nahi hua, to yeh guess galat ho jaata — duplicate ya gaya-guzra ID
// ban jaata. Ab yeh ID seedha live database (jo hamesha sabse sahi/
// up-to-date jagah hai) dekh kar diya jaata hai.
// 🆕 PENDING REGISTRATION SYNC — pehle "Agent Register" form seedha
// Firebase (shdl/agent_logins) mein likh kar turant agent ko active kar
// deta tha — Admin Panel ko iske baare mein pata hi nahi chalta tha,
// koi "Pending" list thi hi nahi jahan yeh dikhta. Ab yeh backend mein
// pending register hota hai; Admin Panel isse dekh kar Approve/Reject
// karta hai — approve hone tak agent login nahi kar sakta.
app.post('/api/agent-registrations', (req, res) => {
    const { name, username, password, mobile, company } = req.body || {};
    if (!name || !username || !password) return res.status(400).json({ error: 'Naam, username aur password zaroori hain.' });
    if (password.length < 4) return res.status(400).json({ error: 'Password kam se kam 4 characters ka hona chahiye.' });
    const uname = String(username).trim().toLowerCase();
    if (uname.indexOf(' ') !== -1) return res.status(400).json({ error: 'Username mein space nahi hona chahiye.' });

    db.query("SELECT value FROM kv_admin_entities WHERE \"key\"='agents'", (aErr, aRows) => {
        if (aErr) return res.status(500).json({ error: 'DB error: ' + aErr.message });
        let agents = [];
        try { agents = aRows && aRows.length ? JSON.parse(aRows[0].value) : []; } catch (e) {}
        if (agents.some(a => a && a.username && a.username.toLowerCase() === uname)) {
            return res.status(409).json({ error: 'Yeh username pehle se ek active agent ke paas hai.' });
        }
        db.query("SELECT value FROM kv_blob WHERE \"key\"='agent_pending_registrations'", (pErr, pRows) => {
            if (pErr) return res.status(500).json({ error: 'DB error: ' + pErr.message });
            let pending = [];
            try { pending = pRows && pRows.length ? JSON.parse(pRows[0].value) : []; } catch (e) {}
            if (pending.some(p => p && p.username && p.username.toLowerCase() === uname && p.status === 'pending')) {
                return res.status(409).json({ error: 'Is username se ek registration pehle se hi Admin approval ka wait kar raha hai.' });
            }
            const rec = {
                id: 'REG' + Date.now(), name, username: uname, password, mobile: mobile || '', company: company || '',
                status: 'pending', submittedOn: new Date().toISOString()
            };
            pending.push(rec);
            db.query(
                "INSERT INTO kv_blob (\"key\", value) VALUES ('agent_pending_registrations', ?) ON CONFLICT (\"key\") DO UPDATE SET value = EXCLUDED.value",
                [JSON.stringify(pending)],
                (insErr) => {
                    if (insErr) return res.status(500).json({ error: 'DB error: ' + insErr.message });
                    res.status(201).json({ success: true, id: rec.id });
                }
            );
        });
    });
});


// ══════════════════════════════════════════════════════════════════
// 📋 CUSTOMER REGISTRATION — payment-gated. Customer plan chunta hai,
//   Razorpay checkout khulta hai, aur SIRF payment successful hone ke
//   baad hi registration DB mein save hoke Admin ke pending-approval
//   queue mein jaata hai. Plan ki price hamesha server par (Admin ke
//   asli mem_plans se) check hoti hai — client jo bheje uska koi
//   matlab nahi, tamper-proof hai.
// ══════════════════════════════════════════════════════════════════
app.post('/api/customer-registrations/order', async (req, res) => {
    if (!process.env.PAYMENT_API_KEY || !process.env.PAYMENT_API_SECRET) {
        return res.status(501).json({ error: 'Payment keys Render Environment mein set nahi hain (PAYMENT_API_KEY / PAYMENT_API_SECRET).' });
    }
    const { name, mobile, email, address, note, agentId, planId } = req.body || {};
    if (!name || !mobile) return res.status(400).json({ error: 'Naam aur mobile zaroori hain.' });
    if (!/^\d{10}$/.test(String(mobile))) return res.status(400).json({ error: 'Sahi 10-digit mobile number likhein.' });
    if (!agentId) return res.status(400).json({ error: 'agentId zaroori hai.' });
    if (!planId) return res.status(400).json({ error: 'Membership plan chunna zaroori hai.' });

    db.query("SELECT value FROM kv_blob WHERE \"key\"='mem_plans'", (pErr, pRows) => {
        if (pErr) return res.status(500).json({ error: 'DB error: ' + pErr.message });
        let plans = [];
        try { plans = pRows && pRows.length ? JSON.parse(pRows[0].value) : []; } catch (e) {}
        const plan = plans.find(p => p && p.id === planId);
        if (!plan) return res.status(404).json({ error: 'Yeh membership plan Admin ke paas set nahi hai.' });
        razorpayRequest('/v1/orders', {
            amount: Math.round(Number(plan.price) * 100),
            currency: 'INR',
            receipt: 'custreg_' + mobile + '_' + Date.now()
        }).then((order) => {
            db.query(
                'INSERT INTO customer_registration_orders (orderId, name, mobile, email, address, note, agentId, planId, planName, amount) VALUES (?,?,?,?,?,?,?,?,?,?)',
                [order.id, name, mobile, email || '', address || '', note || '', agentId, plan.id, plan.name || '', plan.price],
                (err) => {
                    if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
                    res.json({ orderId: order.id, amount: order.amount, currency: order.currency, key: process.env.PAYMENT_API_KEY, plan: plan });
                }
            );
        }).catch((e) => res.status(502).json({ error: 'Razorpay order banane mein error: ' + e.message }));
    });
});

app.post('/api/customer-registrations/verify', (req, res) => {
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
    db.query("SELECT * FROM customer_registration_orders WHERE orderId=? AND status='created'", [razorpay_order_id], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        if (!rows || !rows.length) return res.status(404).json({ error: 'Yeh order pehle se process ho chuka hai ya mila nahi.' });
        const o = rows[0];
        db.query("UPDATE customer_registration_orders SET status='paid' WHERE orderId=?", [razorpay_order_id], () => {
            db.query("SELECT value FROM kv_blob WHERE \"key\"='customer_pending_registrations'", (cErr, cRows) => {
                if (cErr) return res.status(500).json({ error: 'DB error: ' + cErr.message });
                let pending = [];
                try { pending = cRows && cRows.length ? JSON.parse(cRows[0].value) : []; } catch (e) {}
                const rec = {
                    id: 'CREG' + Date.now(), name: o.name, mobile: o.mobile, email: o.email || '',
                    address: o.address || '', note: o.note || '', agentId: o.agentId,
                    planId: o.planId, planName: o.planName, amount: o.amount,
                    paymentRef: razorpay_payment_id, status: 'pending',
                    submittedOn: new Date().toISOString()
                };
                pending.push(rec);
                db.query(
                    "INSERT INTO kv_blob (\"key\", value) VALUES ('customer_pending_registrations', ?) ON CONFLICT (\"key\") DO UPDATE SET value = EXCLUDED.value",
                    [JSON.stringify(pending)],
                    (insErr) => {
                        if (insErr) return res.status(500).json({ error: 'DB error: ' + insErr.message });
                        res.status(201).json({ success: true, id: rec.id });
                    }
                );
            });
        });
    });
});


app.get('/api/students/next-id', (req, res) => {
    db.query("SELECT value FROM kv_admin_entities WHERE \"key\"='students'", (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        let students = [];
        try { students = rows && rows.length ? JSON.parse(rows[0].value) : []; } catch (e) {}
        let maxNum = 0;
        (students || []).forEach(s => {
            const sid = (s && (s.studentId || s.id)) || '';
            const m = /SHL-(\d+)/i.exec(sid);
            if (m) { const n = parseInt(m[1], 10); if (n > maxNum) maxNum = n; }
        });
        res.json({ nextId: 'SHL-' + String(maxNum + 1).padStart(3, '0') });
    });
});
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
        insertWithIdHeal(
            `INSERT INTO attendance_records (date, batch, records, selfies, markedBy, savedAt)
             VALUES (?,?,?,?,?,?)
             ON CONFLICT (date, batch) DO UPDATE SET records=EXCLUDED.records, selfies=EXCLUDED.selfies, markedBy=EXCLUDED.markedBy, savedAt=EXCLUDED.savedAt`,
            [date, batch, JSON.stringify(mergedRecords), JSON.stringify(mergedSelfies), markedBy || '', savedAt || new Date().toISOString()],
            'attendance_records',
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
    // 🔒 FIX: Student_Attendance.html ka SUBMIT_FEE_PAYMENT() 'method' aur
    // 'monthKey' bhejta tha (mode/note nahi) aur response mein poora
    // 'payment' object expect karta tha (receipt PDF banane ke liye —
    // date/time/studentName/method/monthKey). Backend sirf 'mode'/'note'
    // padhta tha aur sirf {id} return karta tha, isliye 'result.payment'
    // hamesha undefined aata tha aur fee receipt kabhi sahi se nahi banta
    // tha. Ab dono field-naam accept hote hain aur poora payment object
    // wapas jaata hai (DB schema badle bina).
    const { studentId, amount, mode, method, note, status, monthKey } = req.body || {};
    if (!studentId || !(amount > 0)) return res.status(400).json({ error: 'studentId aur amount zaroori hain.' });
    const paymentMode = mode || method || 'cash';
    insertWithIdHeal(
        'INSERT INTO fee_payments (studentId, amount, mode, note, status) VALUES (?,?,?,?,?)',
        [studentId, amount, paymentMode, note || '', status || 'paid'],
        'fee_payments',
        (err, result) => {
            if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
            db.query("SELECT value FROM kv_admin_entities WHERE `key`='students'", (sErr, sRows) => {
                let studentInfo = {};
                try {
                    const students = sRows && sRows.length ? JSON.parse(sRows[0].value) : [];
                    const s = students.find(x => x && (x.id === studentId || x.studentId === studentId));
                    if (s) studentInfo = { studentName: s.name, studentClass: s.cls || s.addr || '', batch: s.batch || '' };
                } catch (e) {}
                const now = new Date();
                res.status(201).json({
                    id: result.insertId,
                    payment: Object.assign({
                        id: result.insertId,
                        studentId, amount, mode: paymentMode, method: paymentMode,
                        note: note || '', status: status || 'paid',
                        monthKey: monthKey || (now.getFullYear() + '-' + String(now.getMonth() + 1).padStart(2, '0')),
                        date: now.toLocaleDateString('en-IN'),
                        time: now.toLocaleTimeString('en-IN')
                    }, studentInfo)
                });
            });
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
// 🎓 STUDENT SUBSCRIPTION PAYMENT — Student_Attendance.html ka
//   "Ab Payment Karein" button ab seedha in dono routes se judta hai
//   (pehle yeh Admin Panel mein manually daale gaye ek alag Firebase
//   'razorpay_config.orderEndpoint' URL ko call karta tha, aur payment
//   verify + subscription-activate ek Firebase Cloud Function ke bharose
//   chhod diya gaya tha jiska is codebase mein kahin naamo-nishaan nahi
//   hai — isi wajah se payment ho jaane ke baad bhi student ka
//   subscription kabhi activate nahi hota tha aur paisa kahin record
//   bhi nahi hota tha).
//   Ab: order isi backend (PAYMENT_API_KEY/SECRET) se banta hai, plan/
//   days/amount yahin DB mein save hote hain (client dobara nahi bhej
//   sakta — tamper-proof), aur verify step signature check karne ke
//   baad seedha (1) student ka subscription_status/expiry activate
//   karta hai aur (2) fee_payments mein record daalta hai taaki Admin
//   ke Fee Payment History mein turant dikhe.
// ══════════════════════════════════════════════════════════════════
app.post('/api/payments/student-subscription/order', async (req, res) => {
    if (!process.env.PAYMENT_API_KEY || !process.env.PAYMENT_API_SECRET) {
        return res.status(501).json({ error: 'Payment keys Render Environment mein set nahi hain (PAYMENT_API_KEY / PAYMENT_API_SECRET).' });
    }
    const { studentId, amount, planId, planName, days } = req.body || {};
    if (!studentId) return res.status(400).json({ error: 'studentId zaroori hai.' });
    if (!(amount > 0)) return res.status(400).json({ error: 'Sahi amount bhejein.' });
    if (!(Number(days) > 0)) return res.status(400).json({ error: 'Plan ke days zaroori hain.' });
    try {
        const order = await razorpayRequest('/v1/orders', {
            amount: Math.round(amount * 100),
            currency: 'INR',
            receipt: 'sub_' + studentId + '_' + Date.now()
        });
        db.query(
            'INSERT INTO student_subscription_orders (orderId, studentId, planId, planName, days, amount) VALUES (?,?,?,?,?,?)',
            [order.id, studentId, planId || '', planName || '', days, amount],
            (err) => {
                if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
                res.json({ orderId: order.id, amount: order.amount, currency: order.currency, key: process.env.PAYMENT_API_KEY });
            }
        );
    } catch (e) {
        res.status(502).json({ error: 'Razorpay order banane mein error: ' + e.message });
    }
});

app.post('/api/payments/student-subscription/verify', (req, res) => {
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
    db.query("SELECT * FROM student_subscription_orders WHERE orderId=? AND status='created'", [razorpay_order_id], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        if (!rows || !rows.length) return res.status(404).json({ error: 'Yeh order pehle se process ho chuka hai ya mila nahi.' });
        const o = rows[0];
        db.query("UPDATE student_subscription_orders SET status='paid' WHERE orderId=?", [razorpay_order_id], () => {
            // ── Student ka subscription_status/expiry activate karo (kv_admin_entities.students) ──
            db.query("SELECT value FROM kv_admin_entities WHERE `key`='students'", (sErr, sRows) => {
                if (sErr) return res.status(500).json({ error: 'DB error: ' + sErr.message });
                let students = [];
                try { students = sRows && sRows.length ? JSON.parse(sRows[0].value) : []; } catch (e) {}
                const idx = students.findIndex(s => s && (s.id === o.studentId || s.studentId === o.studentId));
                const today = new Date(); today.setHours(0, 0, 0, 0);
                const curExp = (idx !== -1 && students[idx].subscription_expiry) ? new Date(students[idx].subscription_expiry) : null;
                const base = (curExp && curExp > today) ? curExp : today;
                const newExp = new Date(base); newExp.setDate(newExp.getDate() + Number(o.days));
                const newExpStr = newExp.toISOString().split('T')[0];
                if (idx !== -1) {
                    students[idx] = Object.assign({}, students[idx], { subscription_status: 'active', subscription_expiry: newExpStr });
                }
                const saveStudents = (cb) => {
                    if (idx === -1) return cb(); // student record admin-entities mein na mile to bhi payment record safe rahega
                    db.query("UPDATE kv_admin_entities SET value=? WHERE `key`='students'", [JSON.stringify(students)], (uErr) => cb(uErr));
                };
                saveStudents((studentsSaveErr) => {
                    if (studentsSaveErr) {
                        // 🔒 CRITICAL FIX: pehle yahan error discard ho jaati thi — student ka
                        // payment safal ho jaata, par subscription_status DB mein kabhi
                        // 'active' save hi nahi hota tha, phir bhi response {success:true}
                        // bhej deta tha. Ab is galti ko chhupaya nahi jaata — turant, saaf
                        // error return hoti hai taaki payment safal hone ke bawajood
                        // "subscription active nahi ho rahi" jaisi silent-fail kabhi na ho.
                        console.error('❌ CRITICAL: Payment ho gaya (Ref: ' + razorpay_payment_id + ') par student subscription_status save nahi ho paya:', studentsSaveErr.message);
                        return res.status(500).json({ error: 'Payment safal hua, par subscription activate karte waqt DB error aayi: ' + studentsSaveErr.message + '. Support se contact karein, payment record surakshit hai (Ref: ' + razorpay_payment_id + ').' });
                    }
                    // ── fee_payments mein log karo — Admin Fee History mein turant dikhega ──
                    insertWithIdHeal(
                        'INSERT INTO fee_payments (studentId, amount, mode, note, status) VALUES (?,?,?,?,?)',
                        [o.studentId, o.amount, 'Razorpay', (o.planName || 'Subscription') + ' — Ref: ' + razorpay_payment_id, 'paid'],
                        'fee_payments',
                        (fErr) => {
                            if (fErr) return res.status(500).json({ error: 'DB error: ' + fErr.message });
                            res.json({ success: true, subscription_status: 'active', subscription_expiry: newExpStr });
                        }
                    );
                });
            });
        });
    });
});

// ══════════════════════════════════════════════════════════════════
// 🧑‍💼 AGENT SUBSCRIPTION PAYMENT — Agent App ke "Renew" button ko
//   ab bhi seedha isse jodna hai (dekhein PAY_AGENT_SUBSCRIPTION()).
//   Pehle yeh Razorpay checkout bina kisi order_id ke khulta tha, aur
//   payment 'successful' hote hi client seedha browser se Firebase
//   likh deta tha — koi server-side verification nahi thi. Iska matlab
//   koi bhi browser console se AGENT_APPLY_RENEWAL() ko fake refId ke
//   saath call karke, bina paisa diye, apni subscription "renew" dikha
//   sakta tha. Ab: order backend par plan ke SAHI price se banta hai
//   (client jo amount bheje uska koi matlab nahi — plan seedha DB se
//   padha jaata hai), payment signature server par verify hoti hai,
//   aur tabhi jaake agent ki subscription + uske sabhi students ka
//   subscription_status backend khud activate karta hai.
// ══════════════════════════════════════════════════════════════════
app.post('/api/payments/agent-subscription/order', async (req, res) => {
    if (!process.env.PAYMENT_API_KEY || !process.env.PAYMENT_API_SECRET) {
        return res.status(501).json({ error: 'Payment keys Render Environment mein set nahi hain (PAYMENT_API_KEY / PAYMENT_API_SECRET).' });
    }
    const { username, planId } = req.body || {};
    if (!username) return res.status(400).json({ error: 'username zaroori hai.' });
    if (!planId) return res.status(400).json({ error: 'planId zaroori hai.' });
    db.query("SELECT value FROM kv_blob WHERE `key`='agent_plans'", (pErr, pRows) => {
        if (pErr) return res.status(500).json({ error: 'DB error: ' + pErr.message });
        let plans = [];
        try { plans = pRows && pRows.length ? JSON.parse(pRows[0].value) : []; } catch (e) {}
        const plan = plans.find(p => p && p.id === planId);
        if (!plan) return res.status(404).json({ error: 'Yeh plan Admin ke paas set nahi hai.' });
        razorpayRequest('/v1/orders', {
            amount: Math.round(Number(plan.price) * 100),
            currency: 'INR',
            receipt: 'agentsub_' + username + '_' + Date.now()
        }).then((order) => {
            db.query(
                'INSERT INTO agent_subscription_orders (orderId, username, planId, planName, days, amount) VALUES (?,?,?,?,?,?)',
                [order.id, username, plan.id, plan.name || '', plan.days, plan.price],
                (err) => {
                    if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
                    res.json({ orderId: order.id, amount: order.amount, currency: order.currency, key: process.env.PAYMENT_API_KEY, plan: plan });
                }
            );
        }).catch((e) => res.status(502).json({ error: 'Razorpay order banane mein error: ' + e.message }));
    });
});

app.post('/api/payments/agent-subscription/verify', (req, res) => {
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
    db.query("SELECT * FROM agent_subscription_orders WHERE orderId=? AND status='created'", [razorpay_order_id], (oErr, oRows) => {
        if (oErr) return res.status(500).json({ error: 'DB error: ' + oErr.message });
        if (!oRows || !oRows.length) return res.status(404).json({ error: 'Yeh order pehle se process ho chuka hai ya mila nahi.' });
        const o = oRows[0];
        db.query("UPDATE agent_subscription_orders SET status='paid' WHERE orderId=?", [razorpay_order_id], () => {
            db.query("SELECT value FROM kv_admin_entities WHERE `key`='agents'", (aErr, aRows) => {
                if (aErr) return res.status(500).json({ error: 'DB error: ' + aErr.message });
                let agents = [];
                try { agents = aRows && aRows.length ? JSON.parse(aRows[0].value) : []; } catch (e) {}
                const idx = agents.findIndex(a => a && a.username && a.username.toLowerCase() === (o.username || '').toLowerCase());
                if (idx === -1) return res.status(404).json({ error: 'Agent record nahi mila.' });
                const agent = agents[idx];
                const today = new Date(); today.setHours(0, 0, 0, 0);
                const curExp = agent.subExpiry ? new Date(agent.subExpiry) : null;
                const base = (curExp && curExp > today) ? curExp : today;
                const newExp = new Date(base); newExp.setDate(newExp.getDate() + Number(o.days));
                const newExpStr = newExp.toISOString().split('T')[0];
                const newStartStr = today.toISOString().split('T')[0];
                agents[idx] = Object.assign({}, agent, { planId: o.planId, subStart: newStartStr, subExpiry: newExpStr });
                db.query("UPDATE kv_admin_entities SET value=? WHERE `key`='agents'", [JSON.stringify(agents)], (uErr) => {
                    if (uErr) return res.status(500).json({ error: 'DB error: ' + uErr.message });
                    // ── Is agent ke sabhi students ka subscription bhi turant activate karo ──
                    db.query("SELECT value FROM kv_admin_entities WHERE `key`='students'", (sErr, sRows) => {
                        if (sErr) {
                            console.error('❌ Agent subscription renew ho gaya, par students list padhne mein DB error:', sErr.message);
                            return res.status(500).json({ error: 'Agent subscription renew ho gayi, par students activate karte waqt DB error aayi: ' + sErr.message + '. Agent ki subscription safe hai, dobara try karein.' });
                        }
                        let students = [];
                        try { students = sRows && sRows.length ? JSON.parse(sRows[0].value) : []; } catch (e) {}
                        let activatedCount = 0;
                        students = students.map(s => {
                            if (s && s.agentId === agent.agentId) {
                                activatedCount++;
                                return Object.assign({}, s, { subscription_status: 'active', subscription_expiry: newExpStr });
                            }
                            return s;
                        });
                        const saveStudents = (cb) => {
                            if (!activatedCount) return cb();
                            db.query("UPDATE kv_admin_entities SET value=? WHERE `key`='students'", [JSON.stringify(students)], (uErr2) => cb(uErr2));
                        };
                        saveStudents((studentsSaveErr) => {
                            // 🔒 CRITICAL FIX: yeh error pehle discard ho jaati thi — agent ki
                            // apni subscription to save ho jaati thi, par uske students ka
                            // subscription silently activate nahi hota tha, phir bhi response
                            // 'studentsActivated' mein galat count bhej deta tha.
                            if (studentsSaveErr) {
                                console.error('❌ Agent subscription renew ho gaya, par students activate karne mein DB error:', studentsSaveErr.message);
                                return res.status(500).json({ error: 'Agent subscription renew ho gayi, par students activate karte waqt DB error aayi: ' + studentsSaveErr.message + '. Agent ki subscription safe hai, dobara try karein.' });
                            }
                            // ── Payment history log karo (Admin Panel isi 'agent_payments' blob ko dekhta hai) ──
                            db.query("SELECT value FROM kv_blob WHERE `key`='agent_payments'", (payErr, payRows) => {
                                if (payErr) {
                                    console.error('❌ Agent subscription + students activate ho gaye, par payment history save nahi ho payi:', payErr.message);
                                    // Yeh sirf history/record-keeping hai — subscription khud pehle
                                    // hi safal ho chuki hai, isliye request fail nahi karte, par
                                    // clearly Render logs mein flag zaroor karte hain.
                                }
                                let payments = [];
                                try { payments = payRows && payRows.length ? JSON.parse(payRows[0].value) : []; } catch (e) {}
                                const paymentRecord = {
                                    id: 'pay' + Date.now(), agentId: agent.id, agentDbId: agent.agentId, agentName: agent.name,
                                    planId: o.planId, planName: o.planName, amount: o.amount, mode: 'Razorpay',
                                    note: 'Ref: ' + razorpay_payment_id,
                                    date: new Date().toLocaleString('hi-IN'), newExpiry: newExpStr
                                };
                                payments.push(paymentRecord);
                                db.query(
                                    "INSERT INTO kv_blob (\"key\", value) VALUES ('agent_payments', ?) ON CONFLICT (\"key\") DO UPDATE SET value = EXCLUDED.value",
                                    [JSON.stringify(payments)],
                                    (finalErr) => {
                                        if (finalErr) console.error('❌ agent_payments log save nahi hui:', finalErr.message);
                                        res.json({
                                            success: true, planId: o.planId, planName: o.planName,
                                            subStart: newStartStr, subExpiry: newExpStr,
                                            studentsActivated: activatedCount, paymentRecord: paymentRecord, agent: agents[idx]
                                        });
                                    }
                                );
                            });
                        });
                    });
                });
            });
        });
    });
});

// ══════════════════════════════════════════════════════════════════
// 🔒 SUBSCRIPTION & ACCESS CONTROL SYSTEM
//   Ek hi jagah se poore system (Agent/HRMS/Student teeno portals) ke
//   liye subscription status calculate hota hai, taaki teeno jagah
//   EXACT same rules follow hon:
//     > 5 din baaki         → 'active'  (kuch nahi dikhta)
//     0 se 5 din baaki      → 'warning' (banner dikhta hai, kaam chalu rehta hai)
//     expiry ke baad, <=5 din → 'grace' (still kaam chalta hai, urgent warning)
//     expiry ke 5 din baad  → 'locked' (portal disable, dynamic message)
//   🛡️ FAIL-OPEN BY DESIGN: agar agent record hi na mile, ya usme
//   subExpiry set hi na ho (jaise purane/legacy agents jinke liye yeh
//   feature kabhi setup nahi hua), to kabhi lock NAHI karte — 'active'
//   maan lete hain. Isse koi bhi agent achanak, bina wajah, lock nahi ho
//   jaata jab yeh feature pehli baar deploy ho.
// ══════════════════════════════════════════════════════════════════
function computeAgentSubStatus(agent) {
    if (!agent || !agent.subExpiry) return { status: 'active', daysLeft: null };
    const today = new Date(); today.setHours(0, 0, 0, 0);
    const exp = new Date(agent.subExpiry);
    if (isNaN(exp.getTime())) return { status: 'active', daysLeft: null };
    const daysLeft = Math.ceil((exp - today) / 86400000);
    if (daysLeft > 5) return { status: 'active', daysLeft };
    if (daysLeft >= 0) return { status: 'warning', daysLeft };
    if (daysLeft >= -5) return { status: 'grace', daysLeft };
    return { status: 'locked', daysLeft };
}

function findAgentByIdOrUsername(idOrUsername, cb) {
    db.query("SELECT value FROM kv_admin_entities WHERE \"key\"='agents'", (err, rows) => {
        if (err) return cb(err);
        let agents = [];
        try { agents = rows && rows[0] ? JSON.parse(rows[0].value) : []; } catch (e) {}
        const needle = String(idOrUsername || '').toLowerCase();
        const agent = agents.find(a => a && (
            (a.agentId && String(a.agentId).toLowerCase() === needle) ||
            (a.username && String(a.username).toLowerCase() === needle)
        ));
        cb(null, agent || null, agents);
    });
}

// GET /api/subscription-status/AGT001  ya  /api/subscription-status/agentusername
// Agent App, HRMS Portal, aur Student Portal — teeno isi ek route se apna
// (ya apne linked agent ka) status check karte hain, taaki rules kabhi
// alag-alag jagah mismatch na hon.
// ══════════════════════════════════════════════════════════════════
// 🔔 GLOBAL NOTIFICATION SYSTEM — Admin → Agent → HRMS/Student
//   Backend mein persist hoti hain, isliye refresh/naya login par bhi
//   dikhti hain (pehle jo bell icons the woh sirf usi browser tak
//   simit the — koi doosre device/session ko kabhi nahi dikhta tha).
// ══════════════════════════════════════════════════════════════════

// Bhejna — Admin (agentId ya 'all_agents') / Agent (studentId ya
// 'all_students' apne under ke, empId ya 'all_employees' apne under ke)
app.post('/api/notifications', (req, res) => {
    const { fromRole, fromName, targetScope, targetId, scopeAgentId, title, message, urgency } = req.body || {};
    const validScopes = ['agent', 'all_agents', 'student', 'all_students', 'employee', 'all_employees'];
    if (!title) return res.status(400).json({ error: 'Title zaroori hai.' });
    if (!validScopes.includes(targetScope)) return res.status(400).json({ error: 'Invalid targetScope.' });
    db.query(
        'INSERT INTO notifications (from_role, from_name, target_scope, target_id, scope_agent_id, title, message, urgency) VALUES (?,?,?,?,?,?,?,?)',
        [fromRole || '', fromName || '', targetScope, targetId || null, scopeAgentId || null, title, message || '', urgency || 'info'],
        (err, result) => {
            if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
            res.status(201).json({ success: true, id: result.insertId });
        }
    );
});

// Padhna — viewer apni identity/scope batata hai, backend match karke
// relevant notifications deta hai (naye pehle).
//   Agent dekhega:    ?role=agent&id=AGT001
//   Student dekhega:  ?role=student&id=SHL-001&agentId=AGT001
//   Employee dekhega: ?role=employee&id=EMP001&agentId=AGT001
//   Admin dekhega:    ?role=admin  (koi bhejta nahi Admin ko, sirf apni bheji hui dekh sakta hai — abhi ke liye khaali)
app.get('/api/notifications', (req, res) => {
    const { role, id, agentId } = req.query || {};
    let where = '1=0';
    const params = [];
    if (role === 'agent' && id) {
        where = "(target_scope='agent' AND target_id=?) OR target_scope='all_agents'";
        params.push(id);
    } else if (role === 'student' && id) {
        where = "(target_scope='student' AND target_id=?) OR (target_scope='all_students' AND scope_agent_id=?)";
        params.push(id, agentId || '');
    } else if (role === 'employee' && id) {
        where = "(target_scope='employee' AND target_id=?) OR (target_scope='all_employees' AND scope_agent_id=?)";
        params.push(id, agentId || '');
    } else {
        return res.json([]);
    }
    db.query(`SELECT * FROM notifications WHERE ${where} ORDER BY created_at DESC LIMIT 50`, params, (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        const myId = id || '';
        const result = (rows || []).map(r => {
            let readBy = [];
            try { readBy = JSON.parse(r.read_by || '[]'); } catch (e) {}
            return {
                id: r.id, fromRole: r.from_role, fromName: r.from_name,
                title: r.title, message: r.message, urgency: r.urgency,
                createdAt: r.created_at, isRead: readBy.includes(myId)
            };
        });
        res.json(result);
    });
});

// Padh liya mark karna — viewer apni id bhejta hai, backend read_by
// array mein add kar deta hai (agar pehle se nahi hai).
app.post('/api/notifications/:id/read', (req, res) => {
    const { viewerId } = req.body || {};
    if (!viewerId) return res.status(400).json({ error: 'viewerId zaroori hai.' });
    db.query('SELECT read_by FROM notifications WHERE id=?', [req.params.id], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        if (!rows || !rows.length) return res.status(404).json({ error: 'Notification nahi mili.' });
        let readBy = [];
        try { readBy = JSON.parse(rows[0].read_by || '[]'); } catch (e) {}
        if (!readBy.includes(viewerId)) readBy.push(viewerId);
        db.query('UPDATE notifications SET read_by=? WHERE id=?', [JSON.stringify(readBy), req.params.id], (uErr) => {
            if (uErr) return res.status(500).json({ error: 'DB error: ' + uErr.message });
            res.json({ success: true });
        });
    });
});


app.get('/api/subscription-status/:identifier', (req, res) => {
    findAgentByIdOrUsername(req.params.identifier, (err, agent) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        if (!agent) return res.json({ status: 'active', daysLeft: null, company: '', mobile: '', name: '' }); // fail-open
        const info = computeAgentSubStatus(agent);
        res.json({
            status: info.status,
            daysLeft: info.daysLeft,
            company: agent.company || agent.name || '',
            mobile: agent.mobile || '',
            name: agent.name || ''
        });
    });
});

// 🆕 GRACE PERIOD (Admin Override) — Admin Panel ka "Extend Validity"
// button isi route ko call karta hai. Payment ke bina bhi subExpiry ko
// aage badha deta hai (5-10 din request par) — kisi bhi data ko chhuta
// nahi, sirf yeh ek date field update hoti hai.
app.post('/api/admin/extend-agent-validity', (req, res) => {
    const { agentId, days } = req.body || {};
    if (!agentId) return res.status(400).json({ error: 'agentId zaroori hai.' });
    const extendDays = Math.min(Math.max(parseInt(days, 10) || 7, 1), 30); // 1-30 din ke beech, safety cap
    findAgentByIdOrUsername(agentId, (err, agent, agents) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        if (!agent) return res.status(404).json({ error: 'Agent nahi mila.' });
        const idx = agents.findIndex(a => a === agent);
        const today = new Date(); today.setHours(0, 0, 0, 0);
        const curExp = agent.subExpiry ? new Date(agent.subExpiry) : null;
        const base = (curExp && !isNaN(curExp.getTime()) && curExp > today) ? curExp : today;
        const newExp = new Date(base); newExp.setDate(newExp.getDate() + extendDays);
        const newExpStr = newExp.toISOString().split('T')[0];
        agents[idx] = Object.assign({}, agent, {
            subExpiry: newExpStr,
            lastExtendedBy: 'admin',
            lastExtendedOn: today.toISOString().split('T')[0],
            lastExtendedDays: extendDays
        });
        db.query("UPDATE kv_admin_entities SET value=? WHERE \"key\"='agents'", [JSON.stringify(agents)], (uErr) => {
            if (uErr) return res.status(500).json({ error: 'DB error: ' + uErr.message });
            res.json({ success: true, subExpiry: newExpStr, extendedDays: extendDays });
        });
    });
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
                 ON CONFLICT (agentId) DO UPDATE SET approved_balance = agent_wallets.approved_balance + EXCLUDED.approved_balance,
                                          total_earned = agent_wallets.total_earned + EXCLUDED.total_earned`,
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
                if (sErr) {
                    console.error('❌ Agent subscription renew ho gaya, par students list padhne mein DB error:', sErr.message);
                    return res.status(500).json({ error: 'Agent subscription renew ho gayi, par students activate karte waqt DB error aayi: ' + sErr.message + '. Agent ki subscription safe hai, dobara try karein.' });
                }
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
                    db.query("UPDATE kv_admin_entities SET value=? WHERE `key`='students'", [JSON.stringify(students)], (uErr2) => cb(uErr2));
                };

                // 🔒 CRITICAL FIX: yeh error pehle discard ho jaati thi — agent ki apni
                // subscription to save ho jaati thi, par uske students ka subscription
                // silently activate nahi hota tha, phir bhi response mein galat
                // 'studentsActivated' count bhej diya jaata tha.
                saveStudents((studentsSaveErr) => {
                    if (studentsSaveErr) {
                        console.error('❌ Agent subscription renew ho gaya, par students activate karne mein DB error:', studentsSaveErr.message);
                        return res.status(500).json({ error: 'Agent subscription renew ho gayi, par students activate karte waqt DB error aayi: ' + studentsSaveErr.message + '. Agent ki subscription safe hai, dobara try karein.' });
                    }
                    // ── Payment history log karo ──
                    db.query("SELECT value FROM kv_blob WHERE `key`='agent_payments'", (pErr, pRows) => {
                        if (pErr) console.error('❌ Agent subscription + students activate ho gaye, par payment history save nahi ho payi:', pErr.message);
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
                            "INSERT INTO kv_blob (\"key\", value) VALUES ('agent_payments', ?) ON CONFLICT (\"key\") DO UPDATE SET value = EXCLUDED.value",
                            [paymentsJson],
                            (finalErr) => {
                                if (finalErr) console.error('❌ agent_payments log save nahi hui:', finalErr.message);
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
            insertWithIdHeal(
                'INSERT INTO wallet_withdrawals (agentId, agentName, amount, accName, bankName, accNo, ifsc, status) VALUES (?,?,?,?,?,?,?,\'pending\')',
                [agentId, agentName || '', amount, accName, bankName, accNo, ifsc],
                'wallet_withdrawals',
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
            SUM(CASE WHEN created_at::date = CURRENT_DATE THEN amount ELSE 0 END) AS today_total,
            SUM(CASE WHEN created_at::date = CURRENT_DATE THEN 1 ELSE 0 END) AS today_count,
            SUM(CASE WHEN EXTRACT(YEAR FROM created_at) = EXTRACT(YEAR FROM CURRENT_DATE) AND EXTRACT(MONTH FROM created_at) = EXTRACT(MONTH FROM CURRENT_DATE) THEN amount ELSE 0 END) AS month_total,
            SUM(CASE WHEN EXTRACT(YEAR FROM created_at) = EXTRACT(YEAR FROM CURRENT_DATE) AND EXTRACT(MONTH FROM created_at) = EXTRACT(MONTH FROM CURRENT_DATE) THEN 1 ELSE 0 END) AS month_count
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
app.post('/api/material/bills', requireActiveMaterialUser, (req, res) => {
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
            "SELECT id FROM material_bills WHERE ownerUserId=? AND (data::json->>'billNo')=? LIMIT 1",
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
            db.query('INSERT INTO material_bills (ownerUserId, data) VALUES (?,?)', [ownerUserId, JSON.stringify(body)], (err, result) => {
                if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
                res.status(201).json({ id: result.insertId, updated: false });
            });
        }
    });
});
app.get('/api/material/bills', (req, res) => {
    const ownerUserId = req.query.ownerUserId;
    // 🆕 MULTI-USER INVOICE + ADMIN VIEW: jab ownerUserId diya gaya ho, wahi
    // (self-service) behavior pehle jaisa hai — material user apne khud ke
    // bills dekh sakta hai. Lekin jab ownerUserId NAHI diya jaata (matlab
    // "sabhi users ke sabhi invoices" wali request — Admin Panel ka naya
    // 'All Invoices' page), tab yeh sirf logged-in Admin session (JWT
    // role='admin') ko hi allow karta hai, taaki koi bhi random request
    // saare users ka invoice data na khींच sake.
    if (!ownerUserId) {
        const auth = getAuthUser(req);
        if (!auth || String(auth.role).toLowerCase() !== 'admin') {
            return res.status(401).json({ error: 'Sirf Admin login se hi sabhi users ke invoices dekhe ja sakte hain.' });
        }
    }
    const sql = ownerUserId ? 'SELECT * FROM material_bills WHERE ownerUserId=? ORDER BY savedAt DESC' : 'SELECT * FROM material_bills ORDER BY savedAt DESC';
    db.query(sql, ownerUserId ? [ownerUserId] : [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error: ' + err.message });
        res.json((rows || []).map(r => { try { return Object.assign(JSON.parse(r.data), { id: r.id, savedAt: r.savedAt }); } catch (e) { return { id: r.id, savedAt: r.savedAt }; } }));
    });
});
app.put('/api/material/bills/:id', requireActiveMaterialUser, (req, res) => {
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
app.delete('/api/material/bills/:id', requireActiveMaterialUser, (req, res) => {
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
// 🛡️ Process-level crash-protection (uncaughtException/unhandledRejection)
// ab file ke bilkul shuru mein register hoti hai — dekhein sabse upar,
// requires ke turant baad. Yahan dobara likhne ki zaroorat nahi.

// Start Server
app.listen(PORT, () => {
    console.log(`🚀 Server chalu hua port ${PORT} par`);
});
