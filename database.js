// Import the sqlite3 library
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

// --- NEW: Define a persistent data directory ---
const dataDir = '/var/data';
// Ensure this directory exists
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}
const dbPath = path.join(dataDir, 'diamonds.db');
console.log(`Database path set to: ${dbPath}`);
// --- END NEW ---

// Connect to or create a database file named 'diamonds.db' IN THE DATA DIR
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error(err.message);
    }
    console.log('Connected to the persistent diamonds.db database.');
});

// --- Initialize Database ---
function initDb() {
    db.serialize(() => {
        // --- Users table (with permissions) ---
        db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_superadmin BOOLEAN DEFAULT 0,
                can_add BOOLEAN DEFAULT 0,
                can_delete BOOLEAN DEFAULT 0,
                can_view_analytics BOOLEAN DEFAULT 0
            )
        `, (err) => {
            if (err) return console.error("Error creating users table:", err.message);
            
            db.get("SELECT * FROM users WHERE username = ?", ['admin'], (err, row) => {
                if (err) return console.error("Error checking for admin user:", err.message);
                if (!row) {
                    console.log("No admin user found. Will attempt to create one.");
                } else {
                    console.log("Admin user already exists.");
                }
            });
        });

        // --- UPDATED: Stones table (FINAL) ---
        db.run(`
            CREATE TABLE IF NOT EXISTS stones (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stock_id TEXT UNIQUE NOT NULL,
                video_url TEXT,
                lab TEXT,
                certificate_number TEXT,
                certificate_pdf_path TEXT
            )
        `, (err) => {
            if (err) {
                console.error("Error creating stones table:", err.message);
            }
        });

        // --- History Log Table ---
        db.run(`
            CREATE TABLE IF NOT EXISTS history_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                username TEXT,
                action_type TEXT,
                details TEXT
            )
        `, (err) => {
            if (err) {
                console.error("Error creating history_logs table:", err.message);
            }
        });

        // --- Analytics Table (FINAL) ---
        db.run(`
            CREATE TABLE IF NOT EXISTS link_clicks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                stock_id TEXT NOT NULL,
                ip_address TEXT,
                social_source TEXT,
                referrer_domain TEXT,
                user_agent TEXT(1024),
                country TEXT,
                country_code TEXT,
                city TEXT,
                isp TEXT,
                browser TEXT,
                os TEXT,
                utm_source TEXT,
                utm_medium TEXT,
                utm_campaign TEXT
            )
        `, (err) => {
            if (err) {
                console.error("Error creating link_clicks table:", err.message);
            }
        });
    });
}

// Export the database connection and the init function
module.exports = { db, initDb };
