// --- Import Libraries ---
const { Pool } = require('pg'); // Use the 'pg' library for
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');

// --- Load Environment Variables ---
// This reads the .env file OR your Render Environment Variables
dotenv.config();

// --- Create Database Connection Pool ---
// It automatically uses the 'DATABASE_URL' variable we set in Render
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false // Required for Neon
    }
});

// --- Initialize Database ---
// This function runs the SQL commands to create your tables if they don't exist
async function initDb() {
    try {
        // Create the users table (with PostgreSQL syntax)
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

        // Create the stones table (with PostgreSQL syntax)
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

        // Create History Log Table
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

        // Create Link Click/Analytics Table
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

        console.log("All tables created or already exist.");

        // --- Create Default Admin User (on startup) ---
        const adminUsername = 'admin';
        const adminPassword = 'admin123';
        
        const checkUser = await pool.query("SELECT * FROM users WHERE username = $1", [adminUsername]);
        
        if (checkUser.rows.length === 0) {
            console.log("No admin user found. Creating one...");
            const saltRounds = 10;
            const hash = await bcrypt.hash(adminPassword, saltRounds);
            const sql = `INSERT INTO users (username, password_hash, is_superadmin, can_add, can_delete, can_view_analytics)
                         VALUES ($1, $2, true, true, true, true)`;
            await pool.query(sql, [adminUsername, hash]);
            console.log("Default admin user created successfully.");
        } else {
            console.log("Admin user already exists.");
        }

    } catch (err) {
        console.error("Error initializing database:", err.stack);
    }
}

// Export the pool (for index.js to use) and the init function
module.exports = { pool, initDb };
