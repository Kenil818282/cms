// Import the sqlite3 library
const sqlite3 = require('sqlite3').verbose();

// Connect to or create a database file named 'diamonds.db'
const db = new sqlite3.Database('./diamonds.db', (err) => {
    if (err) {
        console.error(err.message);
    }
    console.log('Connected to the diamonds.db database.');
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

        // --- Stones table (no changes) ---
        db.run(`
            CREATE TABLE IF NOT EXISTS stones (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stock_id TEXT UNIQUE NOT NULL,
                video_url TEXT,
                certificate_url TEXT
            )
        `, (err) => {
            if (err) {
                console.error("Error creating stones table:", err.message);
            }
        });

        // --- History Log Table (no changes) ---
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

        // --- ================================== ---
        // --- UPDATED: Analytics Table ---
        // --- ================================== ---
        // We are adding new columns for powerful analytics!
        db.run(`
            CREATE TABLE IF NOT EXISTS link_clicks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                stock_id TEXT NOT NULL,
                ip_address TEXT,

                -- NEW: Automatic Source Detection --
                social_source TEXT,  -- e.g., "Facebook", "Google", "Direct"
                referrer_domain TEXT, -- e.g., "facebook.com", "google.com"

                user_agent TEXT(1024),

                -- Location Data --
                country TEXT,
                country_code TEXT,
                city TEXT,
                isp TEXT,

                -- Device Data (from ua-parser-js) --
                browser TEXT,
                os TEXT,

                -- Marketing Data (for WhatsApp, QR, etc.) --
                utm_source TEXT,
                utm_medium TEXT,
                utm_campaign TEXT
            )
        `, (err) => {
            if (err) {
                console.error("Error creating link_clicks table:", err.message);
            }
        });
        // --- END UPDATED ---
    });
}

// Export the database connection and the init function
module.exports = { db, initDb };