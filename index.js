require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const xlsx = require('xlsx');
const bcrypt = require('bcrypt');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const QRCode = require('qrcode');
const fetch = require('node-fetch');
const UAParser = require('ua-parser-js');
const cloudinary = require('cloudinary').v2;

// --- Database Setup ---
const { pool, initDb } = require('./database.js');

// --- Cloudinary Config ---
cloudinary.config({ 
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME, 
  api_key: process.env.CLOUDINARY_API_KEY, 
  api_secret: process.env.CLOUDINARY_API_SECRET 
});

const app = express();
const port = process.env.PORT || 3000;
app.set('trust proxy', 1); // Required for Render to get real IPs
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// --- FIX: Use /tmp for temp uploads (Allowed on Render Free Tier) ---
const tempUploadDir = path.join('/tmp', 'uploads');
if (!fs.existsSync(tempUploadDir)){
    try {
        fs.mkdirSync(tempUploadDir, { recursive: true });
    } catch (e) {
        console.error("Error creating temp dir:", e);
    }
}

// --- Session Middleware (Stores sessions in Neon DB) ---
app.use(
    session({
        store: new pgSession({
            pool: pool,
            tableName: 'session',
            createTableIfMissing: true
        }),
        secret: process.env.SESSION_SECRET || 'secret_key_replace_me',
        resave: false,
        saveUninitialized: false,
        cookie: { maxAge: 24 * 60 * 60 * 1000 } // 1 day
    })
);

// --- Permission Middleware ---
async function isAuthenticated(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    try {
        const result = await pool.query("SELECT * FROM users WHERE id = $1", [req.session.user.id]);
        if (result.rows.length === 0) {
            return req.session.destroy(() => {
                res.redirect('/login');
            });
        }
        req.user = result.rows[0]; 
        res.locals.user = result.rows[0]; 
        next();
    } catch (err) {
        console.error("Auth Error:", err);
        return res.redirect('/login');
    }
}

function isSuperAdmin(req, res, next) {
    if (req.user.is_superadmin) { next(); } else { res.status(403).send("Forbidden: Super Admin required."); }
}
function canAdd(req, res, next) {
    if (req.user.is_superadmin || req.user.can_add) { next(); } else { res.status(403).send("Forbidden: Add/Edit permission required."); }
}
function canDelete(req, res, next) {
    if (req.user.is_superadmin || req.user.can_delete) { next(); } else { res.status(403).send("Forbidden: Delete permission required."); }
}
function canViewAnalytics(req, res, next) {
    if (req.user.is_superadmin || req.user.can_view_analytics) { next(); } else { res.status(403).send("Forbidden: Analytics permission required."); }
}

// --- Helper Functions ---
function logAction(user, action_type, details) {
    const userId = user ? user.id : null;
    const username = user ? user.username : 'SYSTEM';
    pool.query("INSERT INTO history_logs (user_id, username, action_type, details) VALUES ($1, $2, $3, $4)", 
        [userId, username, action_type, details]).catch(err => console.error("Log Error:", err));
}

function getVideoEmbedHtml(video_url) {
    if (!video_url) return '<div class="w-full h-full flex items-center justify-center bg-gray-200 text-gray-500 rounded-lg">No Video Available</div>';
    const url_low = String(video_url).toLowerCase();
    if (url_low.includes("v360")) {
        let embed_url = video_url.replace("/view/", "/embed/");
        return `<iframe class="w-full h-full" src="${embed_url}" frameborder="0" allow="autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>`;
    } else {
        return `<video controls class="w-full h-full object-contain" preload="metadata"><source src="${video_url}" type="video/mp4"></video>`;
    }
}

function buildCertificateUrl(lab, certificate_number) {
    if (!lab || !certificate_number) return null;
    const labUpper = String(lab).toUpperCase();
    if (labUpper === 'GIA') return `https://www.gia.edu/report-check?locale=en_US&reportno=${certificate_number}`;
    if (labUpper === 'IGI') return `https://www.igi.org/Verify-Your-Report/?r=${certificate_number}`;
    return null;
}

function parseReferrer(referrer) {
    if (!referrer || referrer === 'Direct') return { source: 'Direct', domain: null };
    try {
        const url = new URL(referrer);
        const domain = url.hostname.replace('www.', '');
        if (domain.includes('google.com')) return { source: 'Google', domain: 'google.com' };
        if (domain.includes('facebook.com')) return { source: 'Facebook', domain: 'facebook.com' };
        if (domain.includes('t.co') || domain.includes('twitter.com')) return { source: 'X / Twitter', domain: 'twitter.com' };
        if (domain.includes('instagram.com')) return { source: 'Instagram', domain: 'instagram.com' };
        if (domain.includes('linkedin.com')) return { source: 'LinkedIn', domain: 'linkedin.com' };
        if (domain.includes('wa.me') || domain.includes('whatsapp.com')) return { source: 'WhatsApp', domain: domain };
        return { source: 'Other', domain: domain };
    } catch (error) { return { source: 'Other', domain: referrer }; }
}

async function logClickAnalytics(clickId, ipAddress) {
    let locationData = {};
    // Test IPs for local dev or proxies
    if (ipAddress === '::1' || ipAddress === '127.0.0.1' || ipAddress.startsWith('10.')) {
        locationData = { country: 'United States', country_code: 'US', city: 'Test Location', isp: 'Test ISP' };
    } else {
        try {
            const response = await fetch(`http://ip-api.com/json/${ipAddress}?fields=status,country,countryCode,city,isp`);
            const data = await response.json();
            if (data && data.status === 'success') {
                locationData = { country: data.country, country_code: data.countryCode, city: data.city, isp: data.isp };
            } else {
                locationData = { country: 'Unknown', city: 'N/A', country_code: null, isp: 'N/A' };
            }
        } catch (error) {
            console.error("GeoIP Error:", error);
            locationData = { country: 'Error', city: 'N/A', country_code: null, isp: 'Error' };
        }
    }

    try {
        await pool.query("UPDATE link_clicks SET country = $1, country_code = $2, city = $3, isp = $4 WHERE id = $5", 
            [locationData.country, locationData.country_code, locationData.city, locationData.isp, clickId]);
    } catch (error) { console.error("Analytics Update Error:", error); }
}

// --- PUBLIC ROUTE ---
app.get('/diamonds/:stockId', async (req, res) => {
    const stock_id_from_url = (req.params.stockId || '').toUpperCase();
    try {
        const result = await pool.query("SELECT * FROM stones WHERE stock_id = $1", [stock_id_from_url]);
        if (result.rows.length === 0) return res.status(404).render('404', { stock_id: req.params.stockId });
        
        const row = result.rows[0];
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
        
        const clickRes = await pool.query(`INSERT INTO link_clicks (stock_id, ip_address, social_source, referrer_domain, user_agent, browser, os, utm_source, utm_medium, utm_campaign) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`, 
            [row.stock_id, ipAddress, referrerInfo.source, referrerInfo.domain, uaString, device.browser.name, device.os.name, utmParams.source, utmParams.medium, utmParams.campaign]);
            
        logClickAnalytics(clickRes.rows[0].id, ipAddress);

        const baseUrl = `${req.protocol}://${req.get('host')}`;
        const publicUrl = `${baseUrl}/diamonds/${row.stock_id}`;
        let cert_type = 'none';
        let certificate_url_to_show = null;

        if (row.certificate_pdf_url) { 
            cert_type = 'pdf';
            certificate_url_to_show = row.certificate_pdf_url; 
        } else if (row.lab && row.certificate_number) {
            cert_type = 'link';
            certificate_url_to_show = buildCertificateUrl(row.lab, row.certificate_number);
        }

        res.render('diamond', {
            stock_id: row.stock_id,
            video_html: getVideoEmbedHtml(row.video_url),
            cert_type: cert_type,
            certificate_url: certificate_url_to_show,
            video_url: row.video_url,
            publicUrl: publicUrl
        });
    } catch (err) {
        console.error(err);
        res.status(500).send("Server Error");
    }
});

// --- AUTH ROUTES ---
app.get('/login', (req, res) => res.render('login', { message: null }));
app.post('/login', async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM users WHERE username = $1", [req.body.username]);
        if (result.rows.length === 0) return res.render('login', { message: { type: 'error', text: 'Invalid login' } });
        const match = await bcrypt.compare(req.body.password, result.rows[0].password_hash);
        if (match) {
            req.session.user = { id: result.rows[0].id, username: result.rows[0].username };
            logAction(req.session.user, 'LOGIN', 'Logged in');
            res.redirect('/admin?login=true');
        } else {
            res.render('login', { message: { type: 'error', text: 'Invalid login' } });
        }
    } catch (e) { res.render('login', { message: { type: 'error', text: 'Server Error' } }); }
});
app.get('/logout', (req, res) => {
    if(req.session.user) logAction(req.session.user, 'LOGOUT', 'Logged out');
    req.session.destroy(() => res.redirect('/login'));
});

// --- ADMIN ROUTES ---
app.get('/admin', isAuthenticated, (req, res) => res.render('admin/dashboard', { message: null, showDisclaimer: req.query.login === 'true' }));

// MANAGE STONES (With Search)
app.get('/admin/manage', isAuthenticated, async (req, res) => {
    const search = req.query.search || '';
    let sql = "SELECT * FROM stones";
    let params = [];
    if (search) {
        const terms = search.split(',').map(t => t.trim().toUpperCase()).filter(t => t);
        if (terms.length > 0) {
            sql += " WHERE stock_id IN (" + terms.map((_,i) => `$${i+1}`).join(',') + ")";
            params = terms;
        }
    }
    sql += " ORDER BY id DESC";

    let message = null;
    if (req.query.success) message = { type: 'success', text: req.query.success.replace(/_/g, ' ') };
    if (req.query.error) message = { type: 'error', text: req.query.error.replace(/_/g, ' ') };

    try {
        const r = await pool.query(sql, params);
        res.render('admin/manage', { 
            stones: r.rows, 
            message: message, 
            baseUrl: `${req.protocol}://${req.get('host')}`, 
            searchQuery: search 
        });
    } catch (e) { res.status(500).send("Error loading stones"); }
});

// --- DOWNLOAD ROUTES (Stones & History) ---
app.get('/admin/download-stones', isAuthenticated, async (req, res) => {
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    try {
        const r = await pool.query("SELECT * FROM stones ORDER BY stock_id ASC");
        const data = r.rows.map(s => ({
            stock_id: s.stock_id,
            video_url: s.video_url,
            lab: s.lab,
            certificate_number: s.certificate_number,
            final_link: s.certificate_pdf_url || buildCertificateUrl(s.lab, s.certificate_number) || 'N/A',
            public_page: `${baseUrl}/diamonds/${s.stock_id}`
        }));
        const wb = xlsx.utils.book_new();
        xlsx.utils.book_append_sheet(wb, xlsx.utils.json_to_sheet(data), "Inventory");
        res.setHeader('Content-Disposition', 'attachment; filename=inventory.xlsx');
        res.send(xlsx.write(wb, { type: 'buffer', bookType: 'xlsx' }));
    } catch (e) { res.status(500).send("Error downloading"); }
});

app.get('/admin/download-history', isAuthenticated, async (req, res) => {
    try {
        const r = await pool.query("SELECT timestamp, username, action_type, details FROM history_logs ORDER BY timestamp DESC");
        const data = r.rows.map(l => ({
            time: new Date(l.timestamp).toLocaleString(),
            user: l.username,
            action: l.action_type,
            details: l.details
        }));
        const wb = xlsx.utils.book_new();
        xlsx.utils.book_append_sheet(wb, xlsx.utils.json_to_sheet(data), "History");
        res.setHeader('Content-Disposition', 'attachment; filename=history.xlsx');
        res.send(xlsx.write(wb, { type: 'buffer', bookType: 'xlsx' }));
    } catch (e) { res.status(500).send("Error downloading"); }
});

// --- UPLOAD HANDLERS ---
const memUpload = multer({ storage: multer.memoryStorage() });

app.post('/admin/add-single', isAuthenticated, canAdd, async (req, res) => {
    try {
        await pool.query("INSERT INTO stones (stock_id, video_url, lab, certificate_number) VALUES ($1, $2, $3, $4) ON CONFLICT (stock_id) DO NOTHING", 
            [req.body.stock_id.toUpperCase(), req.body.video_url, req.body.lab, req.body.certificate_number]);
        logAction(req.user, 'ADD_SINGLE', `Added ${req.body.stock_id}`);
        res.render('admin/dashboard', { message: { type: 'success', text: 'Stone added' }, showDisclaimer: false });
    } catch (e) { res.render('admin/dashboard', { message: { type: 'error', text: 'Error' }, showDisclaimer: false }); }
});

app.post('/admin/upload-bulk', isAuthenticated, canAdd, memUpload.single('diamondFile'), async (req, res) => {
    if (!req.file) return res.redirect('/admin');
    try {
        const wb = xlsx.read(req.file.buffer, { type: 'buffer' });
        const data = xlsx.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]]);
        let added = 0;
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            for (const row of data) {
                const stockIdKey = Object.keys(row).find(k => k.trim().toLowerCase() === 'stock_id');
                const vidKey = Object.keys(row).find(k => k.trim().toLowerCase() === 'video_url');
                const labKey = Object.keys(row).find(k => k.trim().toLowerCase() === 'lab');
                const certKey = Object.keys(row).find(k => k.trim().toLowerCase() === 'certificate_number');
                
                const id = row[stockIdKey] ? String(row[stockIdKey]).trim().toUpperCase() : null;
                const vid = row[vidKey] || null;
                const lab = row[labKey] || null;
                const cert = row[certKey] || null;

                if (id) {
                    await client.query("INSERT INTO stones (stock_id, video_url, lab, certificate_number) VALUES ($1, $2, $3, $4) ON CONFLICT (stock_id) DO NOTHING", 
                    [id, vid, lab, cert]);
                    added++;
                }
            }
            await client.query('COMMIT');
        } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
        logAction(req.user, 'BULK_UPLOAD', `Processed ${added} rows`);
        res.render('admin/dashboard', { message: { type: 'success', text: 'Bulk upload complete' }, showDisclaimer: false });
    } catch (e) { res.render('admin/dashboard', { message: { type: 'error', text: 'Error processing file' }, showDisclaimer: false }); }
});

// --- PDF Upload (Disk Storage -> Cloudinary) ---
const diskStorage = multer.diskStorage({
    destination: tempUploadDir,
    filename: (req, file, cb) => cb(null, file.originalname)
});
const diskUpload = multer({ storage: diskStorage });

app.post('/admin/upload-pdf', isAuthenticated, canAdd, diskUpload.array('pdfFiles'), async (req, res) => {
    if(!req.files) return res.redirect('/admin/manage');
    let matched = 0;
    for (const file of req.files) {
        const certNum = path.basename(file.originalname, '.pdf');
        try {
            const result = await cloudinary.uploader.upload(file.path, { resource_type: 'raw', public_id: `certificates/${certNum}`, overwrite: true });
            if (result) {
                const update = await pool.query("UPDATE stones SET certificate_pdf_url = $1 WHERE certificate_number = $2", [result.secure_url, certNum]);
                if(update.rowCount > 0) matched++;
            }
            fs.unlinkSync(file.path); // Delete temp file
        } catch (e) { console.error("Cloudinary error", e); }
    }
    logAction(req.user, 'UPLOAD_PDF', `Uploaded ${matched} PDFs`);
    res.redirect('/admin/manage?success=pdf_upload');
});

// --- Link Gen ---
app.post('/admin/generate-links', isAuthenticated, canAdd, memUpload.single('stockFile'), (req, res) => {
    if(!req.file) return res.redirect('/admin/manage');
    try {
        const wb = xlsx.read(req.file.buffer, { type: 'buffer' });
        const data = xlsx.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]]);
        const base = `${req.protocol}://${req.get('host')}`;
        const out = [];
        for (const row of data) {
            const key = Object.keys(row)[0];
            if (key) {
                const id = String(row[key]).trim().toUpperCase();
                if (id) out.push({ stock_id: id, link: `${base}/diamonds/${id}` });
            }
        }
        const newWb = xlsx.utils.book_new();
        xlsx.utils.book_append_sheet(newWb, xlsx.utils.json_to_sheet(out), "Links");
        res.setHeader('Content-Disposition', 'attachment; filename=links.xlsx');
        res.send(xlsx.write(newWb, { type: 'buffer', bookType: 'xlsx' }));
    } catch (e) { res.redirect('/admin/manage?error=gen_fail'); }
});

// --- Edit/Delete/Update ---
app.get('/admin/edit-stone/:id', isAuthenticated, canAdd, async (req, res) => {
    const r = await pool.query("SELECT * FROM stones WHERE id = $1", [req.params.id]);
    if (r.rows.length === 0) return res.redirect('/admin/manage');
    res.render('admin/edit_stone', { stone: r.rows[0], message: null });
});
app.post('/admin/update-stone', isAuthenticated, canAdd, async (req, res) => {
    try {
        await pool.query("UPDATE stones SET stock_id=$1, video_url=$2, lab=$3, certificate_number=$4 WHERE id=$5", 
        [req.body.stock_id.toUpperCase(), req.body.video_url, req.body.lab, req.body.certificate_number, req.body.id]);
        logAction(req.user, 'EDIT_STONE', `Updated ${req.body.stock_id}`);
        res.redirect('/admin/manage');
    } catch (e) { res.redirect('/admin/manage'); }
});
app.post('/admin/delete-stone', isAuthenticated, canDelete, async (req, res) => {
    try {
        const r = await pool.query("SELECT certificate_pdf_url FROM stones WHERE id = $1", [req.body.id]);
        if (r.rows[0]?.certificate_pdf_url) {
            const parts = r.rows[0].certificate_pdf_url.split('/');
            const pubId = `certificates/${path.parse(parts[parts.length-1]).name}`;
            cloudinary.uploader.destroy(pubId, { resource_type: 'raw' }).catch(console.error);
        }
        await pool.query("DELETE FROM stones WHERE id = $1", [req.body.id]);
        logAction(req.user, 'DELETE_STONE', `Deleted ID ${req.body.id}`);
        res.redirect('/admin/manage');
    } catch (e) { res.redirect('/admin/manage'); }
});
app.post('/admin/delete-pdf', isAuthenticated, canAdd, async (req, res) => {
    try {
         const r = await pool.query("SELECT * FROM stones WHERE id = $1", [req.body.id]);
         if (r.rows[0]?.certificate_pdf_url) {
             const parts = r.rows[0].certificate_pdf_url.split('/');
             const pubId = `certificates/${path.parse(parts[parts.length-1]).name}`;
             await cloudinary.uploader.destroy(pubId, { resource_type: 'raw' });
             await pool.query("UPDATE stones SET certificate_pdf_url = NULL WHERE id = $1", [req.body.id]);
             logAction(req.user, 'DELETE_PDF', `Deleted PDF for ${r.rows[0].stock_id}`);
         }
         const updated = await pool.query("SELECT * FROM stones WHERE id = $1", [req.body.id]);
         res.render('admin/edit_stone', { stone: updated.rows[0], message: { type: 'success', text: 'PDF Deleted' } });
    } catch (e) { res.redirect('/admin/manage'); }
});
app.post('/admin/delete-all-stones', isAuthenticated, isSuperAdmin, async (req, res) => {
    try {
        const r = await pool.query("SELECT certificate_pdf_url FROM stones WHERE certificate_pdf_url IS NOT NULL");
        // Clean up Cloudinary
        if (r.rows.length > 0) {
            // For simplicity in this block, we iterate. Batch delete is better for production scaling.
            for (const row of r.rows) {
                const parts = row.certificate_pdf_url.split('/');
                const pubId = `certificates/${path.parse(parts[parts.length-1]).name}`;
                cloudinary.uploader.destroy(pubId, { resource_type: 'raw' }).catch(console.error);
            }
        }
        await pool.query("DELETE FROM stones");
        logAction(req.user, 'DELETE_ALL', 'Deleted all stones');
        res.redirect('/admin/manage?success=delete_all_success');
    } catch (e) { res.redirect('/admin/manage?error=delete_all_failed'); }
});

// --- User Management ---
app.get('/admin/users', isAuthenticated, isSuperAdmin, async (req, res) => {
    const r = await pool.query("SELECT * FROM users");
    res.render('admin/users', { users: r.rows, message: null });
});
app.post('/admin/add-user', isAuthenticated, isSuperAdmin, async (req, res) => {
    const { username, password } = req.body;
    const perms = [req.body.is_superadmin === 'on', req.body.can_add === 'on', req.body.can_delete === 'on', req.body.can_view_analytics === 'on'];
    try {
        const hash = await bcrypt.hash(password, saltRounds);
        await pool.query("INSERT INTO users (username, password_hash, is_superadmin, can_add, can_delete, can_view_analytics) VALUES ($1, $2, $3, $4, $5, $6)", 
            [username, hash, ...perms]);
        res.redirect('/admin/users');
    } catch (e) { res.render('admin/users', { users: [], message: {type: 'error', text: 'Error'} }); }
});
app.get('/admin/edit-user/:id', isAuthenticated, isSuperAdmin, async (req, res) => {
    const r = await pool.query("SELECT * FROM users WHERE id = $1", [req.params.id]);
    res.render('admin/edit_user', { userToEdit: r.rows[0], message: null });
});
app.post('/admin/update-user', isAuthenticated, isSuperAdmin, async (req, res) => {
     const { id, new_password } = req.body;
     const perms = [req.body.is_superadmin === 'on', req.body.can_add === 'on', req.body.can_delete === 'on', req.body.can_view_analytics === 'on', id];
     try {
        if (new_password) {
            const hash = await bcrypt.hash(new_password, saltRounds);
            await pool.query("UPDATE users SET is_superadmin=$1, can_add=$2, can_delete=$3, can_view_analytics=$4, password_hash=$5 WHERE id=$6", [...perms.slice(0,4), hash, id]);
        } else {
            await pool.query("UPDATE users SET is_superadmin=$1, can_add=$2, can_delete=$3, can_view_analytics=$4 WHERE id=$5", perms);
        }
        res.redirect('/admin/users');
     } catch (e) { res.redirect('/admin/users'); }
});
app.post('/admin/delete-user', isAuthenticated, isSuperAdmin, async (req, res) => {
    if (req.body.id != req.user.id) await pool.query("DELETE FROM users WHERE id = $1", [req.body.id]);
    res.redirect('/admin/users');
});

// --- Analytics ---
app.get('/admin/analytics', isAuthenticated, canViewAnalytics, async (req, res) => {
    const { stock_id, country, social_source, utm_source, browser, os } = req.query;
    const page = parseInt(req.query.page) || 1;
    const offset = (page - 1) * 25;
    
    let where = [];
    let params = [];
    let idx = 1;

    if (stock_id) { where.push(`stock_id ILIKE $${idx++}`); params.push(`%${stock_id}%`); }
    if (country) { where.push(`country ILIKE $${idx++}`); params.push(`%${country}%`); }
    if (social_source) { where.push(`social_source ILIKE $${idx++}`); params.push(`%${social_source}%`); }
    if (utm_source) { where.push(`utm_source ILIKE $${idx++}`); params.push(`%${utm_source}%`); }
    if (browser) { where.push(`browser ILIKE $${idx++}`); params.push(`%${browser}%`); }
    if (os) { where.push(`os ILIKE $${idx++}`); params.push(`%${os}%`); }

    const whereSql = where.length > 0 ? " WHERE " + where.join(" AND ") : "";

    try {
        const countRes = await pool.query("SELECT COUNT(*) FROM link_clicks" + whereSql, params);
        const totalItems = parseInt(countRes.rows[0].count);
        const totalPages = Math.ceil(totalItems / 25) || 1;

        const sql = "SELECT * FROM link_clicks" + whereSql + ` ORDER BY timestamp DESC LIMIT 25 OFFSET $${idx}`;
        params.push(offset);
        
        const r = await pool.query(sql, params);
        res.render('admin/analytics', { 
            clicks: r.rows, 
            totalPages, currentPage: page, 
            searchParams: req.query 
        });
    } catch (e) { res.status(500).send("Error"); }
});

// --- Start ---
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
    initDb().catch(console.error);
});
