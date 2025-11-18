// --- Import Libraries ---
require('dotenv').config(); // Load environment variables FIRST
const express = require('express');
const path = require('path');
const fs = require('fs'); // For File System operations
const multer = require('multer');
const xlsx = require('xlsx');
const bcrypt = require('bcrypt');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session); // Postgres session store
const QRCode = require('qrcode');
const fetch = require('node-fetch'); // For API calls
const UAParser = require('ua-parser-js'); // For Browser/OS detection

// --- Database Setup ---
const { pool, initDb } = require('./database.js'); // Import Postgres pool
// --- DO NOT CALL initDb() here ---

// --- Cloudinary Setup ---
cloudinary.config({ 
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME, 
  api_key: process.env.CLOUDINARY_API_KEY, 
  api_secret: process.env.CLOUDINARY_API_SECRET 
});

// --- Main App Setup ---
const app = express();
const port = process.env.PORT || 3000; // Use Render's port
const saltRounds = 10;
app.set('trust proxy', 1); // CRITICAL for getting real IP on Render

// --- EJS Template Engine ---
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// --- Middleware ---
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public')); // For future static files

// --- Create 'uploads' folder (This is now for temp files only) ---
const localUploadDir = path.join(__dirname, 'temp_uploads');
if (!fs.existsSync(localUploadDir)){
    fs.mkdirSync(localUploadDir, { recursive: true });
}
// We don't make this public, Cloudinary will host
// --- END NEW ---

// --- Session Middleware (NOW FOR POSTGRES) ---
app.use(
    session({
        store: new pgSession({
            pool: pool, // Use our Neon database pool
            tableName: 'session' // A new table to store sessions
        }),
        secret: process.env.SESSION_SECRET || 'your_secret_key_12345', // Read from Render env
        resave: false,
        saveUninitialized: false,
        cookie: { maxAge: 24 * 60 * 60 * 1000 } // 1 day
    })
);

// --- ================================== ---
// --- PERMISSION MIDDLEWARE ---
// --- ================================== ---

// Base check: Is the user logged in?
async function isAuthenticated(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    
    // Fetch *current* permissions from DB on every secure request
    try {
        const result = await pool.query("SELECT * FROM users WHERE id = $1", [req.session.user.id]);
        if (result.rows.length === 0) {
            return req.session.destroy(() => {
                res.redirect('/login');
            });
        }
        // Attach full, up-to-date user object to req and res.locals
        req.user = result.rows[0]; 
        res.locals.user = result.rows[0]; // Makes 'user' variable available in ALL EJS templates
        next();
    } catch (err) {
        return res.redirect('/login');
    }
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
    const sql = `INSERT INTO history_logs (user_id, username, action_type, details) VALUES ($1, $2, $3, $4)`;
    pool.query(sql, [userId, username, action_type, details], (err) => {
        if (err) console.error("Failed to log action:", err.stack);
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

// HELPER: Build Certificate URL (This is now the FALLBACK)
function buildCertificateUrl(lab, certificate_number) {
    if (!lab || !certificate_number) {
        return null;
    }
    
    const labUpper = String(lab).toUpperCase();
    
    if (labUpper === 'GIA') {
        return `https://www.gia.edu/report-check?locale=en_US&reportno=${certificate_number}`;
    } else if (labUpper === 'IGI') {
        return `https://www.igi.org/Verify-Your-Report/?r=${certificate_number}`;
    }
    
    return null; // Return null if lab is not recognized
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
            country_code: 'US',
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
                     SET country = $1, country_code = $2, city = $3, isp = $4
                     WHERE id = $5`;
        
        await pool.query(sql, [
            locationData.country,
            locationData.country_code,
            locationData.city,
            locationData.isp,
            clickId
        ]);
    } catch (error) {
        console.error("Error saving analytics location data:", error.stack);
    }
}

// --- ================================== ---
// --- PUBLIC ROUTE ---
// --- ================================== ---

// GET /diamonds/:stockId - Public page (NOW WITH HYBRID CERTIFICATE LOGIC)
app.get('/diamonds/:stockId', async (req, res) => {
    // --- CASE-INSENSITIVE FIX ---
    const stock_id_from_url = (req.params.stockId || '').toUpperCase();
    
    try {
        const result = await pool.query("SELECT * FROM stones WHERE stock_id = $1", [stock_id_from_url]);
        
        if (result.rows.length === 0) {
            return res.status(404).render('404', { stock_id: req.params.stockId });
        }
        
        const row = result.rows[0];

        // --- Full Analytics Tracking ---
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
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                     RETURNING id`; // Get the ID of the new row
        
        const analyticsResult = await pool.query(sql, [
            row.stock_id, ipAddress,
            referrerInfo.source, referrerInfo.domain,
            uaString, device.browser.name, device.os.name,
            utmParams.source, utmParams.medium, utmParams.campaign
        ]);
        
        const clickId = analyticsResult.rows[0].id;
        logClickAnalytics(clickId, ipAddress); // Run this in the background
        // --- END: Analytics Tracking ---

        const baseUrl = req.protocol + '://' + req.get('host');
        const publicUrl = `${baseUrl}/diamonds/${row.stock_id}`;
        const video_html = getVideoEmbedHtml(row.video_url);

        // --- HYBRID CERTIFICATE LOGIC ---
        let cert_type = 'none';
        let certificate_url_to_show = null;

        if (row.certificate_pdf_url) { // Use new "pdf_url" column
            // 1. PDF is uploaded! This is the "perfect" experience.
            cert_type = 'pdf';
            certificate_url_to_show = row.certificate_pdf_url; // This is a full Cloudinary URL
        } else if (row.lab && row.certificate_number) {
            // 2. No PDF. Fallback to building the link automatically.
            cert_type = 'link';
            certificate_url_to_show = buildCertificateUrl(row.lab, row.certificate_number);
        }
        // 3. If neither, both remain null/none.
        // --- END NEW ---

        res.render('diamond', {
            stock_id: row.stock_id,
            video_html: video_html,
            cert_type: cert_type, // Pass the type ('pdf', 'link', 'none')
            certificate_url: certificate_url_to_show, // Pass the correct URL
            video_url: row.video_url,
            publicUrl: publicUrl
        });

    } catch (err) {
        console.error("Error fetching diamond:", err.stack);
        return res.status(500).send("Server error");
    }
});

// --- ================================== ---
// --- AUTH ROUTES (No permission checks needed) ---
// --- ================================== ---

// GET /login
app.get('/login', (req, res) => {
    res.render('login', { message: null });
});

// POST /login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
        if (result.rows.length === 0) {
            return res.render('login', { message: { type: 'error', text: 'Invalid username or password.' } });
        }
        
        const user = result.rows[0];
        const match = await bcrypt.compare(password, user.password_hash);

        if (match) {
            req.session.user = { id: user.id, username: user.username };
            logAction(req.session.user, 'LOGIN', 'User logged in.');
            res.redirect('/admin?login=true'); // Redirect with login=true flag
        } else {
            return res.render('login', { message: { type: 'error', text: 'Invalid username or password.' } });
        }
    } catch (err) {
        console.error("Login error:", err.stack);
        return res.render('login', { message: { type: 'error', text: 'Server error.' } });
    }
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
        showDisclaimer: showDisclaimer
    });
});

// GET /admin/manage - Manage Stones
app.get('/admin/manage', isAuthenticated, async (req, res) => {
    const baseUrl = req.protocol + '://' + req.get('host');
    const searchQuery = req.query.search || '';
    
    let message = null;
    if (req.query.success === 'delete_all_success') {
        message = { type: 'success', text: 'All stones have been successfully deleted.' };
    }
    if (req.query.error === 'delete_all_failed') {
        message = { type: 'error', text: 'An error occurred while deleting stones.' };
    }
    if (req.query.success === 'pdf_upload') {
        message = { type: 'success', text: `Successfully matched ${req.query.matched} PDFs. Ignored ${req.query.unmatched} PDFs.` };
    }
    if (req.query.error === 'pdf_upload_failed') {
        message = { type: 'error', text: 'PDF upload failed. Please check the file and try again.' };
    }
    if (req.query.error === 'link_gen_failed') {
        message = { type: 'error', text: 'Link Generator failed. Please check your file.' };
    }

    let sql = "SELECT * FROM stones";
    let params = [];
    if (searchQuery) {
        const searchTerms = searchQuery.split(',').map(term => term.trim().toUpperCase()).filter(term => term.length > 0);
        if (searchTerms.length > 0) {
            const placeholders = searchTerms.map((_, i) => `$${i + 1}`).join(',');
            sql += ` WHERE stock_id IN (${placeholders})`;
            params = searchTerms;
        }
    }
    sql += " ORDER BY id DESC";

    try {
        const result = await pool.query(sql, params);
        res.render('admin/manage', { 
            stones: result.rows, 
            message: message,
            baseUrl: baseUrl,
            searchQuery: searchQuery
        });
    } catch (err) {
        console.error("Error fetching stones for manage page:", err.stack);
        return res.status(500).send("Server error");
    }
});

// GET /admin/qr/:stockId
app.get('/admin/qr/:stockId', isAuthenticated, async (req, res) => {
    const stock_id_from_url = (req.params.stockId || '').toUpperCase();
    const baseUrl = req.protocol + '://' + req.get('host');
    const publicUrl = `${baseUrl}/diamonds/${stock_id_from_url}?utm_source=qrcode&utm_medium=print`;

    try {
        const result = await pool.query("SELECT * FROM stones WHERE stock_id = $1", [stock_id_from_url]);
        if (result.rows.length === 0) return res.status(404).send("Stone not found");
        
        const stone = result.rows[0];
        const qrCodeDataUrl = await QRCode.toDataURL(publicUrl, { width: 300, margin: 2 });
            
        res.render('admin/qr_code', {
            stock_id: stone.stock_id,
            publicUrl: publicUrl,
            baseUrl: baseUrl,
            qrCodeDataUrl: qrCodeDataUrl
        });
    } catch (err) {
        console.error("Error generating QR code:", err.stack);
        return res.status(500).send("Error generating QR code");
    }
});

// POST /admin/add-single (UPDATED for Postgres)
app.post('/admin/add-single', isAuthenticated, canAdd, async (req, res) => {
    const stock_id = (req.body.stock_id || '').trim().toUpperCase();
    const { video_url, lab, certificate_number } = req.body;
    
    if (!stock_id) {
        return res.render('admin/dashboard', { message: { type: 'error', text: 'Stock ID is required.' }, showDisclaimer: false });
    }
    
    try {
        const sql = `INSERT INTO stones (stock_id, video_url, lab, certificate_number) 
                     VALUES ($1, $2, $3, $4)
                     ON CONFLICT (stock_id) DO NOTHING`;
        const result = await pool.query(sql, [stock_id, video_url, lab, (certificate_number || null)]);

        if (result.rowCount === 0) {
            return res.render('admin/dashboard', { message: { type: 'error', text: `Stock ID '${stock_id}' already exists.` }, showDisclaimer: false });
        }
        
        logAction(req.user, 'ADD_SINGLE', `Added stone: ${stock_id}`);
        res.render('admin/dashboard', { message: { type: 'success', text: `Stone '${stock_id}' added successfully!` }, showDisclaimer: false });
    
    } catch (err) {
        console.error("Error adding single stone:", err.stack);
        return res.render('admin/dashboard', { message: { type: 'error', text: 'Database error.' }, showDisclaimer: false });
    }
});

// POST /admin/upload-bulk (UPDATED for Postgres)
const excelUpload = multer({ storage: multer.memoryStorage() }); // For Excel
app.post('/admin/upload-bulk', isAuthenticated, canAdd, excelUpload.single('diamondFile'), async (req, res) => {
    if (!req.file) {
        return res.render('admin/dashboard', { message: { type: 'error', text: 'No file uploaded.' }, showDisclaimer: false });
    }
    try {
        const workbook = xlsx.read(req.file.buffer, { type: "buffer" });
        const sheetName = workbook.SheetNames[0];
        const sheet = workbook.Sheets[sheetName];
        const jsonData = xlsx.utils.sheet_to_json(sheet);
        
        let stonesAdded = 0;
        let stonesIgnored = 0;

        // Use a client for transaction
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            const sql = `INSERT INTO stones (stock_id, video_url, lab, certificate_number) 
                         VALUES ($1, $2, $3, $4)
                         ON CONFLICT (stock_id) DO NOTHING`;

            for (const row of jsonData) {
                const stockIdKey = Object.keys(row).find(k => k.trim().toLowerCase() === 'stock_id');
                const videoUrlKey = Object.keys(row).find(k => k.trim().toLowerCase() === 'video_url');
                const labKey = Object.keys(row).find(k => k.trim().toLowerCase() === 'lab');
                const certNumKey = Object.keys(row).find(k => k.trim().toLowerCase() === 'certificate_number');
                
                const stock_id = String(row[stockIdKey] || '').trim().toUpperCase();
                const video_url = row[videoUrlKey] || null;
                const lab = row[labKey] || null;
                const certificate_number = row[certNumKey] || null;
                
                if (stock_id) {
                    const result = await client.query(sql, [stock_id, video_url, lab, certificate_number]);
                    if (result.rowCount > 0) stonesAdded++;
                    else stonesIgnored++;
                }
            }
            await client.query('COMMIT');
        } catch (e) {
            await client.query('ROLLBACK');
            throw e;
        } finally {
            client.release();
        }

        const details = `Bulk upload: Added ${stonesAdded}, Ignored ${stonesIgnored}.`;
        logAction(req.user, 'ADD_BULK', details);
        res.render('admin/dashboard', { message: { type: 'success', text: `Bulk upload complete! Added: ${stonesAdded}, Ignored (duplicates): ${stonesIgnored}` }, showDisclaimer: false });

    } catch (error) {
        console.error("Error in bulk upload:", error.stack);
        res.render('admin/dashboard', { message: { type: 'error', text: 'Invalid file format. Please use .xlsx or .csv' }, showDisclaimer: false });
    }
});

// --- NEW: SMART PDF BULK UPLOADER (NOW FOR CLOUDINARY) ---
const pdfUpload = multer({ 
    storage: multer.memoryStorage(), // Use memory storage
    fileFilter: (req, file, cb) => {
        if (path.extname(file.originalname).toLowerCase() !== '.pdf') {
            return cb(new Error('Only .pdf files are allowed'), false);
        }
        cb(null, true);
    }
});

app.post('/admin/upload-pdf', isAuthenticated, canAdd, pdfUpload.array('pdfFiles'), async (req, res) => {
    if (!req.files || req.files.length === 0) {
        return res.redirect('/admin/manage');
    }

    let filesMatched = 0;
    let filesUnmatched = 0;

    const uploadPromises = req.files.map(file => {
        return new Promise((resolve, reject) => {
            const certNumber = path.basename(file.originalname, '.pdf');
            
            // Upload the file buffer to Cloudinary
            const uploadStream = cloudinary.uploader.upload_stream(
                {
                    resource_type: 'raw', // Treat as a raw file, not an image
                    public_id: certNumber, // Use cert number as the file name
                    folder: 'certificates' // Put in a 'certificates' folder
                },
                async (error, result) => {
                    if (error) {
                        console.error("Cloudinary upload error:", error);
                        filesUnmatched++;
                        return reject(error);
                    }

                    // Upload success! Now update the database
                    const pdfUrl = result.secure_url;
                    try {
                        const dbResult = await pool.query(
                            "UPDATE stones SET certificate_pdf_url = $1 WHERE certificate_number = $2",
                            [pdfUrl, certNumber]
                        );
                        if (dbResult.rowCount > 0) {
                            filesMatched++;
                        } else {
                            filesUnmatched++;
                            // If no match, delete the file we just uploaded
                            await cloudinary.uploader.destroy(`certificates/${certNumber}`, { resource_type: 'raw' });
                        }
                        resolve();
                    } catch (dbError) {
                        console.error("DB update error after PDF upload:", dbError);
                        filesUnmatched++;
                        // Try to delete the orphaned file
                        await cloudinary.uploader.destroy(`certificates/${certNumber}`, { resource_type: 'raw' });
                        reject(dbError);
                    }
                }
            );
            uploadStream.end(file.buffer);
        });
    });

    // Wait for all uploads and DB updates to finish
    try {
        await Promise.all(uploadPromises);
        logAction(req.user, 'UPLOAD_PDF', `Matched ${filesMatched} PDFs, Unmatched ${filesUnmatched}.`);
        res.redirect(`/admin/manage?success=pdf_upload&matched=${filesMatched}&unmatched=${filesUnmatched}`);
    } catch (err) {
        console.error("PDF Upload batch failed", err);
        res.redirect('/admin/manage?error=pdf_upload_failed');
    }
});
// --- END: SMART PDF UPLOADER ---


// --- NEW: LINK GENERATOR ROUTE (Protected by canAdd) ---
const linkGenUpload = multer({ storage: multer.memoryStorage() }); // Separate multer instance
app.post('/admin/generate-links', isAuthenticated, canAdd, linkGenUpload.single('stockFile'), (req, res) => {
    if (!req.file) {
        return res.redirect('/admin/manage?error=link_gen_failed');
    }
    try {
        const workbook = xlsx.read(req.file.buffer, { type: "buffer" });
        const sheetName = workbook.SheetNames[0];
        const sheet = workbook.Sheets[sheetName];
        const jsonData = xlsx.utils.sheet_to_json(sheet);
        
        const baseUrl = req.protocol + '://' + req.get('host');
        let outputData = [];

        for (const row of jsonData) {
            const firstKey = Object.keys(row)[0];
            if (firstKey) {
                const stock_id = String(row[firstKey] || '').trim().toUpperCase();
                if (stock_id) {
                    outputData.push({
                        stock_id: stock_id,
                        public_link: `${baseUrl}/diamonds/${stock_id}`
                    });
                }
            }
        }
        
        const newSheet = xlsx.utils.json_to_sheet(outputData);
        const newWorkbook = xlsx.utils.book_new();
        xlsx.utils.book_append_sheet(newWorkbook, newSheet, 'Generated Links');
        
        const buffer = xlsx.write(newWorkbook, { type: 'buffer', bookType: 'xlsx' });
        logAction(req.user, 'GENERATE_LINKS', `Generated ${outputData.length} stock links.`);
        
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', 'attachment; filename=generated_links.xlsx');
        res.send(buffer);

    } catch (error) {
        console.error(error);
        res.redirect('/admin/manage?error=generation_failed');
    }
});

// GET /admin/edit-stone/:id (UPDATED for Postgres)
app.get('/admin/edit-stone/:id', isAuthenticated, canAdd, async (req, res) => {
    const stoneIdToEdit = req.params.id;
    try {
        const result = await pool.query("SELECT * FROM stones WHERE id = $1", [stoneIdToEdit]);
        if (result.rows.length === 0) {
            return res.redirect('/admin/manage');
        }
        res.render('admin/edit_stone', { stone: result.rows[0], message: null });
    } catch (err) {
        console.error("Error fetching stone for edit:", err.stack);
        return res.redirect('/admin/manage');
    }
});

// POST /admin/update-stone (UPDATED for Postgres)
app.post('/admin/update-stone', isAuthenticated, canAdd, async (req, res) => {
    const { id, video_url, lab, certificate_number } = req.body;
    const stock_id = (req.body.stock_id || '').trim().toUpperCase();

    let stone;
    try {
        // Get the current stone data in case we need to re-render
        const stoneResult = await pool.query("SELECT * FROM stones WHERE id = $1", [id]);
        stone = stoneResult.rows[0];

        if (!stock_id) {
            return res.render('admin/edit_stone', { 
                stone: stone, 
                message: { type: 'error', text: 'Stock ID cannot be empty.' }
            });
        }

        const sql = `UPDATE stones SET 
                        stock_id = $1,
                        video_url = $2,
                        lab = $3,
                        certificate_number = $4
                     WHERE id = $5`;
        
        await pool.query(sql, [stock_id, video_url, lab, certificate_number, id]);
        
        logAction(req.user, 'EDIT_STONE', `Updated stone: ${stock_id} (ID: ${id})`);
        res.redirect('/admin/manage');

    } catch (err) {
        // Check for UNIQUE constraint error (code '23505' in Postgres)
        if (err.code === '23505') {
            return res.render('admin/edit_stone', { 
                stone: stone, 
                message: { type: 'error', text: `Error: Stock ID '${stock_id}' already exists.` }
            });
        }
        console.error("Error updating stone:", err.stack);
        return res.redirect('/admin/manage');
    }
});

// --- NEW: DELETE PDF ROUTE (FOR CLOUDINARY) ---
app.post('/admin/delete-pdf', isAuthenticated, canAdd, async (req, res) => {
    const { id } = req.body;
    
    try {
        // 1. Find the stone to get its PDF URL
        const result = await pool.query("SELECT * FROM stones WHERE id = $1", [id]);
        const stone = result.rows[0];

        if (stone && stone.certificate_pdf_url) {
            // 2. Delete the PDF from Cloudinary
            const urlParts = stone.certificate_pdf_url.split('/');
            const public_id_with_ext = urlParts.slice(urlParts.indexOf('certificates')).join('/');
            const public_id = `certificates/${path.parse(public_id_with_ext).name}`;
            
            await cloudinary.uploader.destroy(public_id, { resource_type: 'raw' });
            
            // 3. Set the PDF path to NULL in the database
            await pool.query("UPDATE stones SET certificate_pdf_url = NULL WHERE id = $1", [id]);
            logAction(req.user, 'DELETE_PDF', `Deleted PDF for stone: ${stone.stock_id}`);
            
            // 4. Redirect back to the edit page with a success message
            const updatedStone = (await pool.query("SELECT * FROM stones WHERE id = $1", [id])).rows[0];
            return res.render('admin/edit_stone', { 
                stone: updatedStone, 
                message: { type: 'success', text: 'PDF successfully deleted.' }
            });
        } else {
            // No PDF to delete, just go back
            res.redirect(`/admin/edit-stone/${id}`);
        }
    } catch (err) {
        console.error("Error deleting PDF:", err.stack);
        res.redirect(`/admin/edit-stone/${id}`);
    }
});
// --- END: DELETE PDF ROUTE ---


// POST /admin/delete-stone (UPDATED to delete PDF from Cloudinary)
app.post('/admin/delete-stone', isAuthenticated, canDelete, async (req, res) => {
    const { id, stock_id } = req.body;

    try {
        // 1. Find the stone to get its PDF path
        const result = await pool.query("SELECT certificate_pdf_url FROM stones WHERE id = $1", [id]);
        
        if (result.rows.length > 0 && result.rows[0].certificate_pdf_url) {
            // 2. Delete the PDF from Cloudinary
            const url = result.rows[0].certificate_pdf_url;
            const urlParts = url.split('/');
            const public_id_with_ext = urlParts.slice(urlParts.indexOf('certificates')).join('/');
            const public_id = `certificates/${path.parse(public_id_with_ext).name}`;
            
            await cloudinary.uploader.destroy(public_id, { resource_type: 'raw' });
        }
        
        // 3. Delete the stone from database
        await pool.query("DELETE FROM stones WHERE id = $1", [id]);
        logAction(req.user, 'DELETE_STONE', `Deleted stone: ${stock_id} (ID: ${id})`);
        res.redirect('/admin/manage');

    } catch (err) {
        console.error("Error deleting stone:", err.stack);
        res.redirect('/admin/manage');
    }
});

// POST /admin/delete-all-stones (UPDATED to delete all PDFs from Cloudinary)
app.post('/admin/delete-all-stones', isAuthenticated, isSuperAdmin, async (req, res) => {
    try {
        // 1. Get all PDF public_ids from the database
        const result = await pool.query("SELECT certificate_pdf_url FROM stones WHERE certificate_pdf_url IS NOT NULL");
        
        if (result.rows.length > 0) {
            // 2. Extract Cloudinary public_ids
            const public_ids = result.rows.map(row => {
                const urlParts = row.certificate_pdf_url.split('/');
                const public_id_with_ext = urlParts.slice(urlParts.indexOf('certificates')).join('/');
                return `certificates/${path.parse(public_id_with_ext).name}`;
            });

            // 3. Delete all files from Cloudinary in one batch
            await cloudinary.api.delete_resources(public_ids, { resource_type: 'raw' });
        }

        // 4. Delete all rows from 'stones' table
        await pool.query("DELETE FROM stones");
        
        logAction(req.user, 'DELETE_ALL_STONES', 'User successfully deleted all stones and associated PDFs.');
        res.redirect('/admin/manage?success=delete_all_success');
        
    } catch (err) {
        console.error(err);
        logAction(req.user, 'DELETE_ALL_STONES_FAIL', `Error: ${err.message}`);
        return res.redirect('/admin/manage?error=delete_all_failed');
    }
});

// --- UPDATED USER MANAGEMENT (Protected by isSuperAdmin) ---

// GET /admin/users
app.get('/admin/users', isAuthenticated, isSuperAdmin, async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM users");
        res.render('admin/users', { users: result.rows, message: null });
    } catch (err) {
        return res.status(500).send("Server error");
    }
});

// POST /admin/add-user
app.post('/admin/add-user', isAuthenticated, isSuperAdmin, async (req, res) => {
    const { username, password } = req.body;
    const is_superadmin = req.body.is_superadmin === 'on' ? 1 : 0;
    const can_add = req.body.can_add === 'on' ? 1 : 0;
    const can_delete = req.body.can_delete === 'on' ? 1 : 0;
    const can_view_analytics = req.body.can_view_analytics === 'on' ? 1 : 0;
    
    let users = [];
    try {
        users = (await pool.query("SELECT * FROM users")).rows;

        if (!username || !password) {
             return res.render('admin/users', { users: users, message: {type: 'error', text: 'Username and password are required.'} });
        }
        if (password.length < 8) {
            return res.render('admin/users', { users: users, message: {type: 'error', text: 'Password must be at least 8 characters.'} });
        }

        const hash = await bcrypt.hash(password, saltRounds);
        const sql = `INSERT INTO users (username, password_hash, is_superadmin, can_add, can_delete, can_view_analytics) 
                     VALUES ($1, $2, $3, $4, $5, $6)`;
        await pool.query(sql, [username, hash, is_superadmin, can_add, can_delete, can_view_analytics]);
        
        logAction(req.user, 'ADD_USER', `Created new user: ${username}`);
        res.redirect('/admin/users');

    } catch (err) {
        if (err.code === '23505') { // Postgres unique violation
             return res.render('admin/users', { users: users, message: {type: 'error', text: 'Username already exists.'} });
        }
        console.error("Error adding user:", err.stack);
        return res.render('admin/users', { users: users, message: {type: 'error', text: 'Error hashing password or database error.'} });
    }
});

// GET /admin/edit-user/:id
app.get('/admin/edit-user/:id', isAuthenticated, isSuperAdmin, async (req, res) => {
    const userIdToEdit = req.params.id;
    try {
        const result = await pool.query("SELECT * FROM users WHERE id = $1", [userIdToEdit]);
        if (result.rows.length === 0) {
            return res.redirect('/admin/users');
        }
        res.render('admin/edit_user', { userToEdit: result.rows[0], message: null });
    } catch (err) {
        return res.redirect('/admin/users');
    }
});

// POST /admin/update-user
app.post('/admin/update-user', isAuthenticated, isSuperAdmin, async (req, res) => {
    const { id, new_password, is_superadmin, can_add, can_delete, can_view_analytics } = req.body;
    let userToEdit;
    
    try {
        const userResult = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
        userToEdit = userResult.rows[0];

        if (id == req.user.id && !is_superadmin) {
             return res.render('admin/edit_user', { 
                userToEdit: userToEdit,
                message: { type: 'error', text: 'Error: You cannot remove your own Super Admin status.' }
            });
        }
        
        let passwordSql = "";
        let passwordParams = [];
        if (new_password) {
            if (new_password.length < 8) {
                 return res.render('admin/edit_user', { 
                    userToEdit: userToEdit,
                    message: { type: 'error', text: 'Password must be at least 8 characters.' }
                });
            }
            const hash = await bcrypt.hash(new_password, saltRounds);
            passwordSql = ", password_hash = $6"; // Will be the 6th parameter
            passwordParams.push(hash);
            logAction(req.user, 'EDIT_USER_PASSWORD', `Changed password for user ID: ${id}`);
        }

        const sql = `UPDATE users SET
                        is_superadmin = $1,
                        can_add = $2,
                        can_delete = $3,
                        can_view_analytics = $4
                        ${passwordSql}
                     WHERE id = $5`;
                     
        const params = [
            is_superadmin === 'on' ? 1 : 0,
            can_add === 'on' ? 1 : 0,
            can_delete === 'on' ? 1 : 0,
            can_view_analytics === 'on' ? 1 : 0,
            id
        ];
        
        // Add password to the end of the params list *if it exists*
        if (new_password) {
            params.splice(4, 0, ...passwordParams); // Insert password hash before id
        }

        await pool.query(sql, params);
        logAction(req.user, 'EDIT_USER_PERMS', `Updated permissions for user ID: ${id}`);
        res.redirect('/admin/users');

    } catch (err) {
        console.error("Error updating user:", err.stack);
        return res.render('admin/edit_user', { 
            userToEdit: userToEdit || { ...req.body, id: id },
            message: { type: 'error', text: 'Error updating user.' }
        });
    }
});

// POST /admin/delete-user
app.post('/admin/delete-user', isAuthenticated, isSuperAdmin, async (req, res) => {
    const { id } = req.body;
    let users = [];
    try {
        users = (await pool.query("SELECT * FROM users")).rows;

        if (id == req.user.id) {
            return res.render('admin/users', { users: users, message: {type: 'error', text: 'Error: You cannot delete yourself.'} });
        }
        
        const userResult = await pool.query("SELECT username FROM users WHERE id = $1", [id]);
        const deletedUsername = userResult.rows.length > 0 ? userResult.rows[0].username : `ID ${id}`;
            
        await pool.query("DELETE FROM users WHERE id = $1", [id]);
        logAction(req.user, 'DELETE_USER', `Deleted user: ${deletedUsername}`);
        res.redirect('/admin/users');

    } catch (err) {
        console.error("Error deleting user:", err.stack);
        return res.render('admin/users', { users: users, message: {type: 'error', text: 'Error deleting user.'} });
    }
});

// GET /admin/history (Base admin page)
app.get('/admin/history', isAuthenticated, async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM history_logs ORDER BY timestamp DESC LIMIT 100");
        res.render('admin/history', { logs: result.rows });
    } catch (err) {
        return res.status(500).send("Server error");
    }
});

// --- NEW: Download History Route ---
app.get('/admin/download-history', isAuthenticated, async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM history_logs ORDER BY timestamp DESC");
        const logs = result.rows;
        
        const data = logs.map(log => ({
            timestamp: new Date(log.timestamp).toLocaleString(),
            username: log.username,
            action_type: log.action_type,
            details: log.details
        }));

        const newSheet = xlsx.utils.json_to_sheet(data);
        const newWorkbook = xlsx.utils.book_new();
        xlsx.utils.book_append_sheet(newWorkbook, newSheet, 'Action History');
        
        const buffer = xlsx.write(newWorkbook, { type: 'buffer', bookType: 'xlsx' });
        
        logAction(req.user, 'DOWNLOAD_HISTORY', `Downloaded ${data.length} history logs.`);
        
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', 'attachment; filename=action_history.xlsx');
        res.send(buffer);
    } catch (err) {
        console.error("Error downloading history:", err.stack);
        return res.status(500).send("Error fetching logs.");
    }
});

// --- NEW: Download Stones Route ---
app.get('/admin/download-stones', isAuthenticated, async (req, res) => {
    const baseUrl = req.protocol + '://' + req.get('host');
    
    try {
        const result = await pool.query("SELECT * FROM stones ORDER BY stock_id ASC");
        const stones = result.rows;
        
        const data = stones.map(stone => {
            let final_link = '';
            if (stone.certificate_pdf_url) { // Use new 'pdf_url'
                final_link = stone.certificate_pdf_url;
            } else {
                final_link = buildCertificateUrl(stone.lab, stone.certificate_number) || 'N/A';
            }
            
            return {
                stock_id: stone.stock_id,
                video_url: stone.video_url,
                lab: stone.lab,
                certificate_number: stone.certificate_number,
                final_certificate_link: final_link
            };
        });

        const newSheet = xlsx.utils.json_to_sheet(data);
        const newWorkbook = xlsx.utils.book_new();
        xlsx.utils.book_append_sheet(newWorkbook, newSheet, 'Stone Inventory');
        
        const buffer = xlsx.write(newWorkbook, { type: 'buffer', bookType: 'xlsx' });
        
        logAction(req.user, 'DOWNLOAD_STONES', `Downloaded ${data.length} stone records.`);
        
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', 'attachment; filename=stone_inventory.xlsx');
        res.send(buffer);
    } catch (err) {
        console.error("Error downloading stones:", err.stack);
        return res.status(500).send("Error fetching stones.");
    }
});

// --- UPDATED ANALYTICS ROUTE (Now with full search & pagination) ---
app.get('/admin/analytics', isAuthenticated, canViewAnalytics, async (req, res) => {
    const { stock_id, country, social_source, utm_source, browser, os } = req.query;
    const page = parseInt(req.query.page) || 1;
    const limit = 25;
    const offset = (page - 1) * limit;

    let whereClauses = [];
    let params = [];
    let searchParams = { stock_id, country, social_source, utm_source, browser, os };
    let paramIndex = 1;

    // Build WHERE clauses for search
    if (stock_id) { whereClauses.push(`stock_id ILIKE $${paramIndex++}`); params.push(`%${stock_id}%`); }
    if (country) { whereClauses.push(`country ILIKE $${paramIndex++}`); params.push(`%${country}%`); }
    if (social_source) { whereClauses.push(`social_source ILIKE $${paramIndex++}`); params.push(`%${social_source}%`); }
    if (utm_source) { whereClauses.push(`utm_source ILIKE $${paramIndex++}`); params.push(`%${utm_source}%`); }
    if (browser) { whereClauses.push(`browser ILIKE $${paramIndex++}`); params.push(`%${browser}%`); }
    if (os) { whereClauses.push(`os ILIKE $${paramIndex++}`); params.push(`%${os}%`); }

    const whereString = whereClauses.length > 0 ? " WHERE " + whereClauses.join(" AND ") : "";

    try {
        // First, get the total count for pagination
        const countSql = "SELECT COUNT(*) AS count FROM link_clicks" + whereString;
        const countResult = await pool.query(countSql, params);
        const totalClicks = parseInt(countResult.rows[0].count);
        const totalPages = Math.ceil(totalClicks / limit) || 1;

        // Now, get the paginated data
        let dataSql = "SELECT * FROM link_clicks" + whereString;
        dataSql += ` ORDER BY timestamp DESC LIMIT $${paramIndex++} OFFSET $${paramIndex++}`;
        params.push(limit, offset);
        
        const dataResult = await pool.query(dataSql, params);
        
        res.render('admin/analytics', { 
            clicks: dataResult.rows,
            totalPages: totalPages,
            currentPage: page,
            searchParams: searchParams
        });
    } catch (err) {
        console.error("Error fetching analytics:", err.stack);
        return res.status(500).send("Server error");
    }
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
// --- THIS IS THE FIX ---
// We start the server *first*, then initialize the database.
// This prevents the app from crashing if Neon is "asleep".
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
    console.log(`Admin Login: /login`);
    
    // NOW, initialize the database
    initDb().catch(console.error);
});
