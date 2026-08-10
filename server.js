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
            connection.release();
        });
    }
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
