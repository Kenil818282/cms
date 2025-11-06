// --- Import Libraries ---
const express = require('express');
const path = require('path');
const multer = require('multer');
const xlsx = require('xlsx');
const bcrypt = require('bcrypt');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const QRCode = require('qrcode');
const fetch = require('node-fetch'); // For API calls
const UAParser = require('ua-parser-js'); // For Browser/OS detection

// --- Database Setup ---
const { db, initDb } = require('./database.js'); // Import
initDb(); // <-- Call it here to set up tables

// --- Main App Setup ---
const app = express();
const port = 3000;
const saltRounds = 10;
app.set('trust proxy', 1); // CRITICAL for getting real IP on Replit

// --- EJS Template Engine ---
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// --- Middleware ---
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public')); // For future static files

// --- Session Middleware (for Logins) ---
app.use(
    session({
        store: new SQLiteStore({
            db: 'sessions.db',
            dir: '.',
            concurrentDB: true
        }),
        secret: 'your_secret_key_12345', // Change this!
        resave: false,
        saveUninitialized: false,
        cookie: { maxAge: 24 * 60 * 60 * 1000 } // 1 day
    })
);

// --- Create Default Admin User (on startup) ---
async function createDefaultAdmin() {
    const adminUsername = 'admin';
    const adminPassword = 'admin123';
    db.get("SELECT * FROM users WHERE username = ?", [adminUsername], async (err, row) => {
        if (err) return console.error("Error checking for admin:", err.message);
        if (!row) {
            console.log("Creating default 'admin' user with password 'admin123'...");
            try {
                const hash = await bcrypt.hash(adminPassword, saltRounds);
                // Create admin as a superadmin with all permissions
                const sql = `INSERT INTO users (username, password_hash, is_superadmin, can_add, can_delete, can_view_analytics)
                             VALUES (?, ?, 1, 1, 1, 1)`;
                db.run(sql, [adminUsername, hash], (err) => {
                    if (err) console.error("Error creating admin user:", err.message);
                    else console.log("Default admin user created successfully.");
                });
            } catch (hashErr) {
                console.error("Error hashing password:", hashErr);
            }
        }
    });
}
createDefaultAdmin();

// --- ================================== ---
// --- PERMISSION MIDDLEWARE ---
// --- ================================== ---

// Base check: Is the user logged in?
function isAuthenticated(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    
    // Fetch *current* permissions from DB on every secure request
    db.get("SELECT * FROM users WHERE id = ?", [req.session.user.id], (err, user) => {
        if (err || !user) {
            return req.session.destroy(() => {
                res.redirect('/login');
            });
        }
        // Attach full, up-to-date user object to req and res.locals
        req.user = user; 
        res.locals.user = user; // Makes 'user' variable available in ALL EJS templates
        next();
    });
}

// Is the user a Super Admin?
function isSuperAdmin(req, res, next) {
    if (req.user.is_superadmin) {
        next();
    } else {
        res.status(403).send("Forbidden: You do not have Super Admin permissions.");
    }
}

// Can the user add/upload? (NOW ALSO USED FOR EDITING)
function canAdd(req, res, next) {
    if (req.user.is_superadmin || req.user.can_add) {
        next();
    } else {
        res.status(403).send("Forbidden: You do not have permission to add or edit data.");
    }
}

// Can the user delete?
function canDelete(req, res, next) {
    if (req.user.is_superadmin || req.user.can_delete) {
        next();
    } else {
        res.status(403).send("Forbidden: You do not have permission to delete data.");
    }
}

// Can the user view analytics?
function canViewAnalytics(req, res, next) {
    if (req.user.is_superadmin || req.user.can_view_analytics) {
        next();
    } else {
        res.status(403).send("Forbidden: You do not have permission to view analytics.");
    }
}

// --- ================================== ---
// --- HELPER FUNCTIONS ---
// --- ================================== ---

// HELPER: Log Admin Actions
function logAction(user, action_type, details) {
    const userId = user ? user.id : null;
    const username = user ? user.username : 'SYSTEM';
    const sql = `INSERT INTO history_logs (user_id, username, action_type, details) VALUES (?, ?, ?, ?)`;
    db.run(sql, [userId, username, action_type, details], (err) => {
        if (err) console.error("Failed to log action:", err.message);
    });
}

// HELPER: Get Video HTML
function getVideoEmbedHtml(video_url) {
    // (This function is unchanged)
    if (!video_url) {
        return '<div class="w-full h-full flex items-center justify-center bg-gray-200 text-gray-500 rounded-lg">No Video Available</div>';
    }
    const url_low = String(video_url).toLowerCase();
    if (url_low.includes("v360")) {
        let embed_url = video_url;
        if (embed_url.includes("/view/")) {
            embed_url = embed_url.replace("/view/", "/embed/");
        }
        return `
        <iframe
            class="w-full h-full"
            src="${embed_url}"
            frameborder="0"
            allow="autoplay; encrypted-media; gyroscope; picture-in-picture"
            allowfullscreen
            title="V3A0 Diamond Viewer"
        ></iframe>`;
    } else {
        return `
        <video
            controls
            class="w-full h-full object-contain"
            preload="metadata"
            title="Diamond Video"
        >
            <source src="${video_url}" type="video/mp4">
            Your browser does not support the video tag.
        </video>`;
    }
}

// HELPER: Automatic social media/referrer parser
function parseReferrer(referrer) {
    if (!referrer || referrer === 'Direct') {
        return { source: 'Direct', domain: null };
    }
    try {
        const url = new URL(referrer);
        const domain = url.hostname.replace('www.', '');
        if (domain.includes('google.com')) return { source: 'Google', domain: 'google.com' };
        if (domain.includes('facebook.com')) return { source: 'Facebook', domain: 'facebook.com' };
        if (domain.includes('t.co')) return { source: 'X / Twitter', domain: 't.co' };
        if (domain.includes('instagram.com')) return { source: 'Instagram', domain: 'instagram.com' };
        if (domain.includes('linkedin.com')) return { source: 'LinkedIn', domain: 'linkedin.com' };
        if (domain.includes('wa.me') || domain.includes('whatsapp.com')) return { source: 'WhatsApp', domain: domain };
        return { source: 'Other', domain: domain };
    } catch (error) {
        return { source: 'Other', domain: referrer };
    }
}

// HELPER: Asynchronously Get and Update Location Data (with test fix)
async function logClickAnalytics(clickId, ipAddress) {
    let locationData = {};
    const testIPs = ['::1', '127.0.0.1', '::ffff:127.0.0.1'];

    if (testIPs.includes(ipAddress)) {
        console.log(`Detected test IP (${ipAddress}). Simulating location.`);
        locationData = {
            country: 'United States',
            country_code: 'US', // <-- This will show the US flag
            city: 'Test Location',
            isp: 'Test ISP'
        };
    } else {
        try {
            const response = await fetch(`http://ip-api.com/json/${ipAddress}?fields=status,country,countryCode,city,isp`);
            const data = await response.json();
            if (data && data.status === 'success') {
                locationData = {
                    country: data.country,
                    country_code: data.countryCode,
                    city: data.city,
                    isp: data.isp
                };
            } else {
                locationData = { country: 'Unknown', city: 'N/A', country_code: null, isp: 'N/A' };
            }
        } catch (error) {
            console.error("Error fetching location data:", error);
            locationData = { country: 'Error', city: 'N/A', country_code: null, isp: 'Error' };
        }
    }

    try {
        const sql = `UPDATE link_clicks 
                     SET country = ?, country_code = ?, city = ?, isp = ?
                     WHERE id = ?`;
        
        db.run(sql, [
            locationData.country,
            locationData.country_code,
            locationData.city,
            locationData.isp,
            clickId
        ], (err) => {
            if (err) console.error("Error updating analytics location data:", err.message);
        });
    } catch (error) {
        console.error("Error saving analytics location data:", error);
    }
}

// --- ================================== ---
// --- PUBLIC ROUTE ---
// --- ================================== ---

// GET /diamonds/:stockId - Public page (NOW WITH POWERFUL TRACKING)
app.get('/diamonds/:stockId', (req, res) => {
    const stock_id = req.params.stockId;
    
    db.get("SELECT * FROM stones WHERE stock_id = ?", [stock_id], (err, row) => {
        if (err) {
            console.error(err);
            return res.status(500).send("Server error");
        }
        if (!row) {
            return res.status(404).render('404', { stock_id: stock_id });
        }
        
        const ipAddress = req.ip; 
        const referrerString = req.get('Referrer') || 'Direct';
        const uaString = req.get('User-Agent');
        const referrerInfo = parseReferrer(referrerString);
        const parser = new UAParser(uaString);
        const device = parser.getResult();
        const utmParams = {
            source: req.query.utm_source || null,
            medium: req.query.utm_medium || null,
            campaign: req.query.utm_campaign || null
        };
        
        const sql = `INSERT INTO link_clicks (
                        stock_id, ip_address, 
                        social_source, referrer_domain, 
                        user_agent, browser, os,
                        utm_source, utm_medium, utm_campaign
                     ) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
        
        db.run(sql, [
            stock_id, ipAddress,
            referrerInfo.source, referrerInfo.domain,
            uaString, device.browser.name, device.os.name,
            utmParams.source, utmParams.medium, utmParams.campaign
        ], function(err) {
            if (err) {
                console.error("Error logging click:", err.message);
            } else {
                const clickId = this.lastID;
                logClickAnalytics(clickId, ipAddress);
            }
        });

        const baseUrl = req.protocol + '://' + req.get('host');
        const publicUrl = `${baseUrl}/diamonds/${row.stock_id}`;
        const video_html = getVideoEmbedHtml(row.video_url);

        res.render('diamond', {
            stock_id: row.stock_id,
            video_html: video_html,
            certificate_url: row.certificate_url,
            video_url: row.video_url,
            publicUrl: publicUrl
        });
    });
});

// --- ================================== ---
// --- AUTH ROUTES (No permission checks needed) ---
// --- ================================== ---

// GET /login
app.get('/login', (req, res) => {
    res.render('login', { message: null });
});

// POST /login
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (err || !user) {
            return res.render('login', { message: { type: 'error', text: 'Invalid username or password.' } });
        }
        const match = await bcrypt.compare(password, user.password_hash);
        if (match) {
            req.session.user = { id: user.id, username: user.username };
            logAction(req.session.user, 'LOGIN', 'User logged in.');
            res.redirect('/admin?login=true'); // <-- Redirect with login=true flag
        } else {
            return res.render('login', { message: { type: 'error', text: 'Invalid username or password.' } });
        }
    });
});

// GET /logout
app.get('/logout', (req, res) => {
    if(req.session.user) {
        logAction(req.session.user, 'LOGOUT', 'User logged out.');
    }
    req.session.destroy((err) => {
        if (err) console.error("Error destroying session:", err);
        res.redirect('/login');
    });
});


// --- ================================== ---
// --- ADMIN ROUTES (All require login) ---
// --- ================================== ---
// All routes from here use the 'isAuthenticated' middleware first

// GET /admin - Dashboard
app.get('/admin', isAuthenticated, (req, res) => {
    const showDisclaimer = req.query.login === 'true';
    res.render('admin/dashboard', { 
        message: null, 
        showDisclaimer: showDisclaimer // Pass flag to template
    });
});

// GET /admin/manage - Manage Stones
app.get('/admin/manage', isAuthenticated, (req, res) => {
    const baseUrl = req.protocol + '://' + req.get('host');
    const searchQuery = req.query.search || '';
    
    let sql = "SELECT * FROM stones";
    let params = [];
    if (searchQuery) {
        const searchTerms = searchQuery.split(',').map(term => term.trim()).filter(term => term.length > 0);
        if (searchTerms.length > 0) {
            const placeholders = searchTerms.map(() => '?').join(',');
            sql += ` WHERE stock_id IN (${placeholders})`;
            params = searchTerms;
        }
    }
    sql += " ORDER BY id DESC";

    db.all(sql, params, (err, stones) => {
        if (err) return res.status(500).send("Server error");
        res.render('admin/manage', { 
            stones: stones, 
            message: null,
            baseUrl: baseUrl,
            searchQuery: searchQuery
        });
    });
});

// GET /admin/qr/:stockId
app.get('/admin/qr/:stockId', isAuthenticated, (req, res) => {
    const stock_id = req.params.stockId;
    const baseUrl = req.protocol + '://' + req.get('host');
    const publicUrl = `${baseUrl}/diamonds/${stock_id}?utm_source=qrcode&utm_medium=print`;

    db.get("SELECT * FROM stones WHERE stock_id = ?", [stock_id], (err, stone) => {
        if (err || !stone) return res.status(404).send("Stone not found");

        QRCode.toDataURL(publicUrl, { width: 300, margin: 2 }, (err, qrCodeDataUrl) => {
            if (err) return res.status(500).send("Error generating QR code");
            
            res.render('admin/qr_code', {
                stock_id: stock_id,
                publicUrl: publicUrl,
                baseUrl: baseUrl,
                qrCodeDataUrl: qrCodeDataUrl
            });
        });
    });
});

// POST /admin/add-single (Protected by canAdd)
app.post('/admin/add-single', isAuthenticated, canAdd, (req, res) => {
    const { stock_id, video_url, certificate_url } = req.body;
    if (!stock_id) {
        return res.render('admin/dashboard', { message: { type: 'error', text: 'Stock ID is required.' }, showDisclaimer: false });
    }
    const sql = "INSERT OR IGNORE INTO stones (stock_id, video_url, certificate_url) VALUES (?, ?, ?)";
    db.run(sql, [stock_id, video_url, certificate_url], function(err) {
        if (err) return res.render('admin/dashboard', { message: { type: 'error', text: 'Database error.' }, showDisclaimer: false });
        if (this.changes === 0) {
            return res.render('admin/dashboard', { message: { type: 'error', text: `Stock ID '${stock_id}' already exists.` }, showDisclaimer: false });
        }
        logAction(req.user, 'ADD_SINGLE', `Added stone: ${stock_id}`);
        res.render('admin/dashboard', { message: { type: 'success', text: `Stone '${stock_id}' added successfully!` }, showDisclaimer: false });
    });
});

// POST /admin/upload-bulk (Protected by canAdd)
const upload = multer({ storage: multer.memoryStorage() });
app.post('/admin/upload-bulk', isAuthenticated, canAdd, upload.single('diamondFile'), (req, res) => {
    if (!req.file) {
        return res.render('admin/dashboard', { message: { type: 'error', text: 'No file uploaded.' }, showDisclaimer: false });
    }
    try {
        const workbook = xlsx.read(req.file.buffer, { type: "buffer" });
        const sheetName = workbook.SheetNames[0];
        const sheet = workbook.Sheets[sheetName];
        const jsonData = xlsx.utils.sheet_to_json(sheet);
        const sql = "INSERT OR IGNORE INTO stones (stock_id, video_url, certificate_url) VALUES (?, ?, ?)";
        let stonesAdded = 0;
        let stonesIgnored = 0;
        db.serialize(() => {
            const stmt = db.prepare(sql);
            for (const row of jsonData) {
                const stock_id = String(row.stock_id || '').trim();
                if (stock_id) {
                    stmt.run(stock_id, row.video_url, row.certificate_url, function() {
                        if (this.changes > 0) stonesAdded++;
                        else stonesIgnored++;
                    });
                }
            }
            stmt.finalize((err) => {
                if (err) return res.render('admin/dashboard', { message: { type: 'error', text: 'Error processing file.' }, showDisclaimer: false });
                const details = `Bulk upload: Added ${stonesAdded}, Ignored ${stonesIgnored}.`;
                logAction(req.user, 'ADD_BULK', details);
                res.render('admin/dashboard', { message: { type: 'success', text: `Bulk upload complete! Added: ${stonesAdded}, Ignored (duplicates): ${stonesIgnored}` }, showDisclaimer: false });
            });
        });
    } catch (error) {
        console.error(error);
        res.render('admin/dashboard', { message: { type: 'error', text: 'Invalid file format. Please use .xlsx or .csv' }, showDisclaimer: false });
    }
});

// --- NEW: EDIT STONE ROUTES (Protected by canAdd) ---
// GET /admin/edit-stone/:id
app.get('/admin/edit-stone/:id', isAuthenticated, canAdd, (req, res) => {
    const stoneIdToEdit = req.params.id;
    db.get("SELECT * FROM stones WHERE id = ?", [stoneIdToEdit], (err, stone) => {
        if (err || !stone) {
            return res.redirect('/admin/manage');
        }
        res.render('admin/edit_stone', { stone: stone, message: null });
    });
});

// POST /admin/update-stone
app.post('/admin/update-stone', isAuthenticated, canAdd, (req, res) => {
    const { id, stock_id, video_url, certificate_url } = req.body;

    if (!stock_id) {
        // Need to refetch stone data to render edit page again
        db.get("SELECT * FROM stones WHERE id = ?", [id], (err, stone) => {
            res.render('admin/edit_stone', { 
                stone: stone, 
                message: { type: 'error', text: 'Stock ID cannot be empty.' }
            });
        });
        return;
    }

    const sql = `UPDATE stones SET 
                    stock_id = ?,
                    video_url = ?,
                    certificate_url = ?
                 WHERE id = ?`;
    
    db.run(sql, [stock_id, video_url, certificate_url, id], function(err) {
        if (err) {
            // Check for UNIQUE constraint error
            if (err.code === 'SQLITE_CONSTRAINT') {
                db.get("SELECT * FROM stones WHERE id = ?", [id], (err_fetch, stone) => {
                    res.render('admin/edit_stone', { 
                        stone: stone, 
                        message: { type: 'error', text: `Error: Stock ID '${stock_id}' already exists.` }
                    });
                });
                return;
            }
            // Other error
            console.error(err);
            return res.redirect('/admin/manage');
        }
        
        logAction(req.user, 'EDIT_STONE', `Updated stone: ${stock_id} (ID: ${id})`);
        res.redirect('/admin/manage');
    });
});
// --- END: EDIT STONE ROUTES ---

// POST /admin/delete-stone (Protected by canDelete)
app.post('/admin/delete-stone', isAuthenticated, canDelete, (req, res) => {
    const { id, stock_id } = req.body;
    db.run("DELETE FROM stones WHERE id = ?", [id], (err) => {
        if (err) console.error(err);
        else logAction(req.user, 'DELETE_STONE', `Deleted stone: ${stock_id} (ID: ${id})`);
        res.redirect('/admin/manage');
    });
});

// --- UPDATED USER MANAGEMENT (Protected by isSuperAdmin) ---

// GET /admin/users
app.get('/admin/users', isAuthenticated, isSuperAdmin, (req, res) => {
    db.all("SELECT * FROM users", [], (err, users) => {
        if (err) return res.status(500).send("Server error");
        res.render('admin/users', { users: users, message: null });
    });
});

// POST /admin/add-user
app.post('/admin/add-user', isAuthenticated, isSuperAdmin, async (req, res) => {
    const { username, password } = req.body;
    const is_superadmin = req.body.is_superadmin === 'on' ? 1 : 0;
    const can_add = req.body.can_add === 'on' ? 1 : 0;
    const can_delete = req.body.can_delete === 'on' ? 1 : 0;
    const can_view_analytics = req.body.can_view_analytics === 'on' ? 1 : 0;
    
    if (!username || !password) {
        db.all("SELECT * FROM users", [], (err, users) => {
             res.render('admin/users', { users: users, message: {type: 'error', text: 'Username and password are required.'} });
        });
        return;
    }
    try {
        const hash = await bcrypt.hash(password, saltRounds);
        const sql = `INSERT INTO users (username, password_hash, is_superadmin, can_add, can_delete, can_view_analytics) 
                     VALUES (?, ?, ?, ?, ?, ?)`;
        db.run(sql, [username, hash, is_superadmin, can_add, can_delete, can_view_analytics], (err) => {
            if (err) {
                 db.all("SELECT * FROM users", [], (err, users) => {
                    res.render('admin/users', { users: users, message: {type: 'error', text: 'Username already exists.'} });
                 });
                 return;
            }
            logAction(req.user, 'ADD_USER', `Created new user: ${username}`);
            res.redirect('/admin/users');
        });
    } catch (hashErr) {
        db.all("SELECT * FROM users", [], (err, users) => {
            res.render('admin/users', { users: users, message: {type: 'error', text: 'Error hashing password.'} });
        });
    }
});

// GET /admin/edit-user/:id
app.get('/admin/edit-user/:id', isAuthenticated, isSuperAdmin, (req, res) => {
    const userIdToEdit = req.params.id;
    db.get("SELECT * FROM users WHERE id = ?", [userIdToEdit], (err, userToEdit) => {
        if (err || !userToEdit) {
            return res.redirect('/admin/users');
        }
        res.render('admin/edit_user', { userToEdit: userToEdit, message: null });
    });
});

// POST /admin/update-user
app.post('/admin/update-user', isAuthenticated, isSuperAdmin, async (req, res) => {
    const { id, new_password, is_superadmin, can_add, can_delete, can_view_analytics } = req.body;
    
    // Prevent superadmin from removing their own superadmin status
    if (id == req.user.id && !is_superadmin) {
        db.get("SELECT * FROM users WHERE id = ?", [id], (err, userToEdit) => {
             res.render('admin/edit_user', { 
                userToEdit: userToEdit,
                message: { type: 'error', text: 'Error: You cannot remove your own Super Admin status.' }
            });
        });
        return;
    }
    
    // --- NEW: Handle Password Change ---
    let passwordSql = "";
    let passwordParams = [];
    if (new_password) {
        try {
            const hash = await bcrypt.hash(new_password, saltRounds);
            passwordSql = ", password_hash = ?";
            passwordParams.push(hash);
            logAction(req.user, 'EDIT_USER_PASSWORD', `Changed password for user ID: ${id}`);
        } catch (hashErr) {
            // Handle hash error
             db.get("SELECT * FROM users WHERE id = ?", [id], (err, userToEdit) => {
                 res.render('admin/edit_user', { 
                    userToEdit: userToEdit,
                    message: { type: 'error', text: 'Error hashing new password.' }
                });
             });
             return;
        }
    }
    // --- END: Password Change ---

    const sql = `UPDATE users SET
                    is_superadmin = ?,
                    can_add = ?,
                    can_delete = ?,
                    can_view_analytics = ?
                    ${passwordSql}
                 WHERE id = ?`;
                 
    const params = [
        is_superadmin === 'on' ? 1 : 0,
        can_add === 'on' ? 1 : 0,
        can_delete === 'on' ? 1 : 0,
        can_view_analytics === 'on' ? 1 : 0,
        ...passwordParams, // Add the hashed password if it exists
        id
    ];

    db.run(sql, params, function(err) {
        if (err) {
            console.error(err);
            return res.redirect(`/admin/edit-user/${id}`);
        }
        logAction(req.user, 'EDIT_USER_PERMS', `Updated permissions for user ID: ${id}`);
        res.redirect('/admin/users');
    });
});

// POST /admin/delete-user
app.post('/admin/delete-user', isAuthenticated, isSuperAdmin, (req, res) => {
    const { id } = req.body;
    if (id == req.user.id) {
        db.all("SELECT * FROM users", [], (err, users) => {
            res.render('admin/users', { users: users, message: {type: 'error', text: 'Error: You cannot delete yourself.'} });
        });
        return;
    }
    db.get("SELECT username FROM users WHERE id = ?", [id], (err, row) => {
        if (err) return res.redirect('/admin/users');
        const deletedUsername = row ? row.username : `ID ${id}`;
        
        db.run("DELETE FROM users WHERE id = ?", [id], (err) => {
            if (err) console.error(err);
            else logAction(req.user, 'DELETE_USER', `Deleted user: ${deletedUsername}`);
            res.redirect('/admin/users');
        });
    });
});

// GET /admin/history (Base admin page)
app.get('/admin/history', isAuthenticated, (req, res) => {
    db.all("SELECT * FROM history_logs ORDER BY timestamp DESC LIMIT 100", [], (err, logs) => {
        if (err) return res.status(500).send("Server error");
        res.render('admin/history', { logs: logs });
    });
});

// --- UPDATED ANALYTICS ROUTE (Now with full search & pagination) ---
app.get('/admin/analytics', isAuthenticated, canViewAnalytics, (req, res) => {
    const { stock_id, country, social_source, utm_source, browser, os } = req.query;
    const page = parseInt(req.query.page) || 1;
    const limit = 25;
    const offset = (page - 1) * limit;

    let sql = "SELECT * FROM link_clicks";
    let countSql = "SELECT COUNT(*) AS count FROM link_clicks";
    let whereClauses = [];
    let params = [];
    let searchParams = { stock_id, country, social_source, utm_source, browser, os };

    if (stock_id) { whereClauses.push("stock_id LIKE ?"); params.push(`%${stock_id}%`); }
    if (country) { whereClauses.push("country LIKE ?"); params.push(`%${country}%`); }
    if (social_source) { whereClauses.push("social_source LIKE ?"); params.push(`%${social_source}%`); }
    if (utm_source) { whereClauses.push("utm_source LIKE ?"); params.push(`%${utm_source}%`); }
    if (browser) { whereClauses.push("browser LIKE ?"); params.push(`%${browser}%`); }
    if (os) { whereClauses.push("os LIKE ?"); params.push(`%${os}%`); }

    if (whereClauses.length > 0) {
        const whereString = " WHERE " + whereClauses.join(" AND ");
        sql += whereString;
        countSql += whereString;
    }

    db.get(countSql, params, (err, row) => {
        if (err) {
            console.error(err);
            return res.status(500).send("Server error");
        }

        const totalClicks = row.count;
        const totalPages = Math.ceil(totalClicks / limit) || 1;

        sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?";
        params.push(limit, offset);
        
        db.all(sql, params, (err, clicks) => {
            if (err) {
                console.error(err);
                return res.status(500).send("Server error");
            }
            res.render('admin/analytics', { 
                clicks: clicks,
                totalPages: totalPages,
                currentPage: page,
                searchParams: searchParams
            });
        });
    });
});


// --- ================================== ---
// --- HOME ROUTE ---
// --- ================================== ---

app.get('/', (req, res) => {
    if (req.session.user) {
        res.redirect('/admin');
    } else {
        res.redirect('/login');
    }
});

// --- Start Server ---
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
    console.log(`Admin Login: http://localhost:${port}/login`);
});
