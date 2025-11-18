const { Pool } = require('pg');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');

dotenv.config();

// --- DEBUGGING: Check if DATABASE_URL is loaded ---
if (!process.env.DATABASE_URL) {
    console.error("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    console.error("CRITICAL ERROR: DATABASE_URL is missing!");
    console.error("Please go to Render Dashboard -> Environment and add DATABASE_URL.");
    console.error("The app will crash because it has no database to connect to.");
    console.error("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
}

// --- FIX: Force SSL for Neon Database ---
let connectionString = process.env.DATABASE_URL;
if (connectionString && !connectionString.includes('sslmode=require')) {
    connectionString += '?sslmode=require';
}

const pool = new Pool({
    connectionString: connectionString,
    ssl: {
        rejectUnauthorized: false // Required for Neon
    }
});

async function initDb() {
    try {
        // Users Table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_superadmin BOOLEAN DEFAULT false,
                can_add BOOLEAN DEFAULT false,
                can_delete BOOLEAN DEFAULT false,
                can_view_analytics BOOLEAN DEFAULT false
            );
        `);

        // Stones Table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS stones (
                id SERIAL PRIMARY KEY,
                stock_id TEXT UNIQUE NOT NULL,
                video_url TEXT,
                lab TEXT,
                certificate_number TEXT,
                certificate_pdf_url TEXT 
            );
        `);

        // History Table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS history_logs (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                username TEXT,
                action_type TEXT,
                details TEXT
            );
        `);

        // Analytics Table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS link_clicks (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                stock_id TEXT NOT NULL,
                ip_address TEXT,
                social_source TEXT,
                referrer_domain TEXT,
                user_agent TEXT,
                country TEXT,
                country_code TEXT,
                city TEXT,
                isp TEXT,
                browser TEXT,
                os TEXT,
                utm_source TEXT,
                utm_medium TEXT,
                utm_campaign TEXT
            );
        `);

        // Session Table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS "session" (
              "sid" varchar NOT NULL COLLATE "default",
              "sess" json NOT NULL,
              "expire" timestamp(6) NOT NULL
            )
            WITH (OIDS=FALSE);
        `);
        
        try {
            await pool.query(`ALTER TABLE "session" ADD CONSTRAINT "session_pkey" PRIMARY KEY ("sid") NOT DEFERRABLE INITIALLY IMMEDIATE;`);
        } catch (e) { /* Ignore if exists */ }

        console.log("Database initialized successfully.");

        // Create Admin User
        const adminRes = await pool.query("SELECT * FROM users WHERE username = 'admin'");
        if (adminRes.rows.length === 0) {
            const hash = await bcrypt.hash('admin123', 10);
            await pool.query(`INSERT INTO users (username, password_hash, is_superadmin, can_add, can_delete, can_view_analytics)
                              VALUES ('admin', $1, true, true, true, true)`, [hash]);
            console.log("Default admin created.");
        }

    } catch (err) {
        console.error("DB Init Error:", err);
    }
}

module.exports = { pool, initDb };
