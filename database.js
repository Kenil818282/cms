const { Pool } = require('pg');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');

dotenv.config();

// --- DEBUGGING START ---
const dbUrl = process.env.DATABASE_URL;
console.log("----------------------------------------------------------------");
if (!dbUrl) {
    console.error("CRITICAL ERROR: DATABASE_URL is undefined.");
    console.error("Action Required: Go to Render Dashboard -> Environment.");
    console.error("Ensure Key is 'DATABASE_URL' and Value is your Neon connection string.");
} else {
    console.log("DATABASE_URL found. Length:", dbUrl.length);
    // Do not log the full URL to protect your password
}
console.log("----------------------------------------------------------------");
// --- DEBUGGING END ---

// Fix SSL for Neon
let connectionString = dbUrl;
if (connectionString && !connectionString.includes('sslmode=require')) {
    connectionString += '?sslmode=require';
}

// Create Pool (only if URL exists)
const pool = new Pool({
    connectionString: connectionString,
    ssl: { rejectUnauthorized: false },
    connectionTimeoutMillis: 5000 // Fail fast if connection is bad
});

async function initDb() {
    if (!connectionString) {
        console.error("Skipping DB init because connection string is missing.");
        return;
    }

    let client;
    try {
        console.log("Attempting to connect to Neon...");
        client = await pool.connect();
        console.log("SUCCESS: Connected to Neon Database.");

        // Create Tables
        await client.query(`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, is_superadmin BOOLEAN DEFAULT false, can_add BOOLEAN DEFAULT false, can_delete BOOLEAN DEFAULT false, can_view_analytics BOOLEAN DEFAULT false)`);
        await client.query(`CREATE TABLE IF NOT EXISTS stones (id SERIAL PRIMARY KEY, stock_id TEXT UNIQUE, video_url TEXT, lab TEXT, certificate_number TEXT, certificate_pdf_url TEXT)`);
        await client.query(`CREATE TABLE IF NOT EXISTS history_logs (id SERIAL PRIMARY KEY, timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP, user_id INTEGER, username TEXT, action_type TEXT, details TEXT)`);
        await client.query(`CREATE TABLE IF NOT EXISTS link_clicks (id SERIAL PRIMARY KEY, timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP, stock_id TEXT, ip_address TEXT, social_source TEXT, referrer_domain TEXT, user_agent TEXT, country TEXT, country_code TEXT, city TEXT, isp TEXT, browser TEXT, os TEXT, utm_source TEXT, utm_medium TEXT, utm_campaign TEXT)`);
        
        // Session Table
        await client.query(`CREATE TABLE IF NOT EXISTS "session" ("sid" varchar NOT NULL COLLATE "default", "sess" json NOT NULL, "expire" timestamp(6) NOT NULL) WITH (OIDS=FALSE)`);
        try { await client.query(`ALTER TABLE "session" ADD CONSTRAINT "session_pkey" PRIMARY KEY ("sid") NOT DEFERRABLE INITIALLY IMMEDIATE`); } catch (e) {}

        // Create Admin
        const res = await client.query("SELECT * FROM users WHERE username = 'admin'");
        if (res.rows.length === 0) {
            const hash = await bcrypt.hash('admin123', 10);
            await client.query("INSERT INTO users (username, password_hash, is_superadmin, can_add, can_delete, can_view_analytics) VALUES ('admin', $1, true, true, true, true)", [hash]);
            console.log("Default admin user created.");
        }
    } catch (err) {
        console.error("DB INIT ERROR:", err.message);
    } finally {
        if (client) client.release();
    }
}

module.exports = { pool, initDb };
