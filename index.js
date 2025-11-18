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

// --- Database ---
const { pool, initDb } = require('./database.js');

// --- Cloudinary ---
if (process.env.CLOUDINARY_CLOUD_NAME) {
    cloudinary.config({ 
      cloud_name: process.env.CLOUDINARY_CLOUD_NAME, 
      api_key: process.env.CLOUDINARY_API_KEY, 
      api_secret: process.env.CLOUDINARY_API_SECRET 
    });
} else {
    console.warn("WARNING: Cloudinary keys are missing.");
}

const app = express();
const port = process.env.PORT || 3000;
app.set('trust proxy', 1);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// --- Temp Storage (Memory/Tmp) ---
const tempUploadDir = path.join('/tmp', 'uploads');
if (!fs.existsSync(tempUploadDir)){
    try { fs.mkdirSync(tempUploadDir, { recursive: true }); } 
    catch (e) { console.error("Temp dir error:", e); }
}

// --- Session ---
app.use(session({
    store: new pgSession({ pool: pool, tableName: 'session', createTableIfMissing: true }),
    secret: process.env.SESSION_SECRET || 'secret',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 86400000 } 
}));

// --- Middleware ---
async function isAuthenticated(req, res, next) {
    if (!req.session.user) return res.redirect('/login');
    try {
        const r = await pool.query("SELECT * FROM users WHERE id = $1", [req.session.user.id]);
        if (r.rows.length === 0) return req.session.destroy(() => res.redirect('/login'));
        req.user = r.rows[0];
        res.locals.user = r.rows[0];
        next();
    } catch (e) { res.redirect('/login'); }
}
function isSuperAdmin(req, res, next) { req.user.is_superadmin ? next() : res.status(403).send("Forbidden"); }
function canAdd(req, res, next) { (req.user.is_superadmin || req.user.can_add) ? next() : res.status(403).send("Forbidden"); }
function canDelete(req, res, next) { (req.user.is_superadmin || req.user.can_delete) ? next() : res.status(403).send("Forbidden"); }
function canViewAnalytics(req, res, next) { (req.user.is_superadmin || req.user.can_view_analytics) ? next() : res.status(403).send("Forbidden"); }

function logAction(user, action, details) {
    pool.query("INSERT INTO history_logs (user_id, username, action_type, details) VALUES ($1, $2, $3, $4)", 
    [user ? user.id : null, user ? user.username : 'SYSTEM', action, details]).catch(console.error);
}

// --- Helpers ---
function buildCertificateUrl(lab, num) {
    if (!lab || !num) return null;
    const l = String(lab).toUpperCase();
    if (l === 'GIA') return `https://www.gia.edu/report-check?locale=en_US&reportno=${num}`;
    if (l === 'IGI') return `https://www.igi.org/Verify-Your-Report/?r=${num}`;
    return null;
}

function parseReferrer(referrer) {
    if (!referrer || referrer === 'Direct') return { source: 'Direct', domain: null };
    try {
        const url = new URL(referrer);
        const domain = url.hostname.replace('www.', '');
        if (domain.includes('google.com')) return { source: 'Google', domain: 'google.com' };
        if (domain.includes('facebook.com')) return { source: 'Facebook', domain: 'facebook.com' };
        if (domain.includes('t.co')) return { source: 'X / Twitter', domain: 't.co' };
        if (domain.includes('instagram.com')) return { source: 'Instagram', domain: 'instagram.com' };
        if (domain.includes('wa.me')) return { source: 'WhatsApp', domain: domain };
        return { source: 'Other', domain: domain };
    } catch (error) { return { source: 'Other', domain: referrer }; }
}

// --- Routes ---
app.get('/diamonds/:stockId', async (req, res) => {
    try {
        const r = await pool.query("SELECT * FROM stones WHERE stock_id = $1", [req.params.stockId.toUpperCase()]);
        if (r.rows.length === 0) return res.status(404).render('404', { stock_id: req.params.stockId });
        
        const row = r.rows[0];
        const ip = req.ip;
        const refInfo = parseReferrer(req.get('Referrer') || 'Direct');
        const ua = new UAParser(req.get('User-Agent'));
        const utm = { source: req.query.utm_source, medium: req.query.utm_medium, campaign: req.query.utm_campaign };

        // Log Click
        const clickRes = await pool.query(`INSERT INTO link_clicks (stock_id, ip_address, social_source, referrer_domain, user_agent, browser, os, utm_source, utm_medium, utm_campaign) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`, 
            [row.stock_id, ip, refInfo.source, refInfo.domain, req.get('User-Agent'), ua.getBrowser().name, ua.getOS().name, utm.source, utm.medium, utm.campaign]);

        // Async Location
        fetch(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,city,isp`).then(res => res.json()).then(geo => {
            if(geo.status === 'success') {
                pool.query("UPDATE link_clicks SET country=$1, country_code=$2, city=$3, isp=$4 WHERE id=$5",
                [geo.country, geo.countryCode, geo.city, geo.isp, clickRes.rows[0].id]);
            }
        }).catch(console.error);

        let cert_type = 'none', cert_url = null;
        if (row.certificate_pdf_url) { cert_type = 'pdf'; cert_url = row.certificate_pdf_url; }
        else if (row.lab && row.certificate_number) { cert_type = 'link'; cert_url = buildCertificateUrl(row.lab, row.certificate_number); }

        const embedVideo = row.video_url ? (row.video_url.toLowerCase().includes('v360') ? `<iframe class="w-full h-full" src="${row.video_url.replace('/view/', '/embed/')}" frameborder="0" allowfullscreen></iframe>` : `<video controls class="w-full h-full object-contain"><source src="${row.video_url}" type="video/mp4"></video>`) : 'No Video';

        res.render('diamond', { stock_id: row.stock_id, video_html: embedVideo, cert_type, certificate_url: cert_url, video_url: row.video_url, publicUrl: `${req.protocol}://${req.get('host')}/diamonds/${row.stock_id}` });
    } catch (e) { console.error(e); res.status(500).send("Server Error"); }
});

app.get('/login', (req, res) => res.render('login', { message: null }));
app.post('/login', async (req, res) => {
    try {
        const r = await pool.query("SELECT * FROM users WHERE username = $1", [req.body.username]);
        if (r.rows.length > 0 && await bcrypt.compare(req.body.password, r.rows[0].password_hash)) {
            req.session.user = { id: r.rows[0].id, username: r.rows[0].username };
            logAction(req.session.user, 'LOGIN', 'Logged in');
            res.redirect('/admin?login=true');
        } else { res.render('login', { message: { type: 'error', text: 'Invalid login' } }); }
    } catch (e) { res.render('login', { message: { type: 'error', text: 'Error' } }); }
});
app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));

app.get('/admin', isAuthenticated, (req, res) => res.render('admin/dashboard', { message: null, showDisclaimer: req.query.login === 'true' }));

// --- MANAGE PAGE ---
app.get('/admin/manage', isAuthenticated, async (req, res) => {
    const search = req.query.search || '';
    let sql = "SELECT * FROM stones";
    let params = [];
    if (search) { sql += " WHERE stock_id ILIKE $1"; params.push(`%${search}%`); }
    sql += " ORDER BY id DESC";
    try {
        const r = await pool.query(sql, params);
        res.render('admin/manage', { stones: r.rows, message: null, baseUrl: `${req.protocol}://${req.get('host')}`, searchQuery: search });
    } catch (e) { res.status(500).send("Error"); }
});

// --- DOWNLOAD ROUTES ---
app.get('/admin/download-stones', isAuthenticated, async (req, res) => {
    try {
        const r = await pool.query("SELECT stock_id, video_url, lab, certificate_number, certificate_pdf_url FROM stones");
        const wb = xlsx.utils.book_new();
        xlsx.utils.book_append_sheet(wb, xlsx.utils.json_to_sheet(r.rows), "Stones");
        res.setHeader('Content-Disposition', 'attachment; filename=stones.xlsx');
        res.send(xlsx.write(wb, { type: 'buffer', bookType: 'xlsx' }));
    } catch(e) { res.redirect('/admin/manage'); }
});

app.get('/admin/download-history', isAuthenticated, async (req, res) => {
    try {
        const r = await pool.query("SELECT timestamp, username, action_type, details FROM history_logs ORDER BY timestamp DESC");
        const wb = xlsx.utils.book_new();
        xlsx.utils.book_append_sheet(wb, xlsx.utils.json_to_sheet(r.rows), "History");
        res.setHeader('Content-Disposition', 'attachment; filename=history.xlsx');
        res.send(xlsx.write(wb, { type: 'buffer', bookType: 'xlsx' }));
    } catch(e) { res.redirect('/admin/history'); }
});

// --- UPLOAD ROUTES ---
const memUpload = multer({ storage: multer.memoryStorage() });

app.post('/admin/add-single', isAuthenticated, canAdd, async (req, res) => {
    try {
        await pool.query("INSERT INTO stones (stock_id, video_url, lab, certificate_number) VALUES ($1, $2, $3, $4) ON CONFLICT (stock_id) DO NOTHING", 
            [req.body.stock_id.toUpperCase(), req.body.video_url, req.body.lab, req.body.certificate_number]);
        res.render('admin/dashboard', { message: { type: 'success', text: 'Stone added' }, showDisclaimer: false });
    } catch (e) { res.render('admin/dashboard', { message: { type: 'error', text: 'Error adding' }, showDisclaimer: false }); }
});

app.post('/admin/upload-bulk', isAuthenticated, canAdd, memUpload.single('diamondFile'), async (req, res) => {
    if (!req.file) return res.redirect('/admin');
    try {
        const wb = xlsx.read(req.file.buffer, { type: 'buffer' });
        const data = xlsx.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]]);
        let added = 0;
        for (const row of data) {
             const id = String(row['stock_id'] || row['Stock ID'] || '').trim().toUpperCase();
             if (id) {
                 const vid = row['video_url'] || row['Video URL'];
                 const lab = row['lab'] || row['Lab'];
                 const cert = row['certificate_number'] || row['Certificate Number'];
                 const res = await pool.query("INSERT INTO stones (stock_id, video_url, lab, certificate_number) VALUES ($1, $2, $3, $4) ON CONFLICT (stock_id) DO NOTHING", [id, vid, lab, cert]);
                 if(res.rowCount > 0) added++;
             }
        }
        logAction(req.user, 'BULK_UPLOAD', `Added ${added} stones`);
        res.render('admin/dashboard', { message: { type: 'success', text: 'Bulk upload processed' }, showDisclaimer: false });
    } catch (e) { res.render('admin/dashboard', { message: { type: 'error', text: 'File error' }, showDisclaimer: false }); }
});

// PDF Upload (Disk -> Cloudinary)
const diskStorage = multer.diskStorage({ destination: tempUploadDir, filename: (req, file, cb) => cb(null, file.originalname) });
const diskUpload = multer({ storage: diskStorage });

app.post('/admin/upload-pdf', isAuthenticated, canAdd, diskUpload.array('pdfFiles'), async (req, res) => {
    if(!req.files) return res.redirect('/admin/manage');
    let matched = 0;
    for (const file of req.files) {
        const certNum = path.basename(file.originalname, '.pdf');
        try {
            const result = await cloudinary.uploader.upload(file.path, { resource_type: 'raw', public_id: `certificates/${certNum}`, overwrite: true });
            if (result) {
                const up = await pool.query("UPDATE stones SET certificate_pdf_url = $1 WHERE certificate_number = $2", [result.secure_url, certNum]);
                if(up.rowCount > 0) matched++;
            }
            fs.unlinkSync(file.path);
        } catch (e) { console.error(e); }
    }
    res.redirect(`/admin/manage?success=pdf_upload&matched=${matched}`);
});

// --- Link Gen ---
app.post('/admin/generate-links', isAuthenticated, canAdd, memUpload.single('stockFile'), (req, res) => {
    if(!req.file) return res.redirect('/admin/manage');
    try {
        const wb = xlsx.read(req.file.buffer, { type: 'buffer' });
        const data = xlsx.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]]);
        const base = `${req.protocol}://${req.get('host')}`;
        const out = data.map(r => {
            const id = String(Object.values(r)[0]).trim().toUpperCase();
            return { stock_id: id, link: `${base}/diamonds/${id}` };
        });
        const newWb = xlsx.utils.book_new();
        xlsx.utils.book_append_sheet(newWb, xlsx.utils.json_to_sheet(out), "Links");
        res.setHeader('Content-Disposition', 'attachment; filename=links.xlsx');
        res.send(xlsx.write(newWb, { type: 'buffer', bookType: 'xlsx' }));
    } catch (e) { res.redirect('/admin/manage'); }
});

// --- Edit/Delete ---
app.get('/admin/edit-stone/:id', isAuthenticated, canAdd, async (req, res) => {
    const r = await pool.query("SELECT * FROM stones WHERE id = $1", [req.params.id]);
    res.render('admin/edit_stone', { stone: r.rows[0], message: null });
});
app.post('/admin/update-stone', isAuthenticated, canAdd, async (req, res) => {
    await pool.query("UPDATE stones SET stock_id=$1, video_url=$2, lab=$3, certificate_number=$4 WHERE id=$5", 
        [req.body.stock_id.toUpperCase(), req.body.video_url, req.body.lab, req.body.certificate_number, req.body.id]);
    res.redirect('/admin/manage');
});
app.post('/admin/delete-stone', isAuthenticated, canDelete, async (req, res) => {
    const r = await pool.query("DELETE FROM stones WHERE id = $1 RETURNING certificate_pdf_url", [req.body.id]);
    if (r.rows.length > 0 && r.rows[0].certificate_pdf_url) {
        // Clean up Cloudinary
        const parts = r.rows[0].certificate_pdf_url.split('/');
        cloudinary.uploader.destroy(`certificates/${path.basename(parts[parts.length-1], '.pdf')}`, { resource_type: 'raw' }).catch(()=>{});
    }
    res.redirect('/admin/manage');
});
app.post('/admin/delete-pdf', isAuthenticated, canAdd, async (req, res) => {
    const r = await pool.query("UPDATE stones SET certificate_pdf_url = NULL WHERE id = $1 RETURNING certificate_pdf_url", [req.body.id]);
    if (r.rows.length > 0 && r.rows[0].certificate_pdf_url) {
        const parts = r.rows[0].certificate_pdf_url.split('/');
        cloudinary.uploader.destroy(`certificates/${path.basename(parts[parts.length-1], '.pdf')}`, { resource_type: 'raw' }).catch(()=>{});
    }
    res.redirect(`/admin/edit-stone/${req.body.id}`);
});
app.post('/admin/delete-all-stones', isAuthenticated, isSuperAdmin, async (req, res) => {
    await pool.query("DELETE FROM stones"); // Simplified
    res.redirect('/admin/manage');
});

// --- Users ---
app.get('/admin/users', isAuthenticated, isSuperAdmin, async (req, res) => {
    const r = await pool.query("SELECT * FROM users");
    res.render('admin/users', { users: r.rows, message: null });
});
app.post('/admin/add-user', isAuthenticated, isSuperAdmin, async (req, res) => {
    try {
        const hash = await bcrypt.hash(req.body.password, saltRounds);
        await pool.query("INSERT INTO users (username, password_hash, is_superadmin, can_add, can_delete, can_view_analytics) VALUES ($1, $2, $3, $4, $5, $6)",
        [req.body.username, hash, req.body.is_superadmin==='on', req.body.can_add==='on', req.body.can_delete==='on', req.body.can_view_analytics==='on']);
        res.redirect('/admin/users');
    } catch(e) { res.render('admin/users', { users: [], message: { type: 'error', text: 'Error' }}); }
});
app.get('/admin/edit-user/:id', isAuthenticated, isSuperAdmin, async (req, res) => {
    const r = await pool.query("SELECT * FROM users WHERE id = $1", [req.params.id]);
    res.render('admin/edit_user', { userToEdit: r.rows[0], message: null });
});
app.post('/admin/update-user', isAuthenticated, isSuperAdmin, async (req, res) => {
    const perms = [req.body.is_superadmin==='on', req.body.can_add==='on', req.body.can_delete==='on', req.body.can_view_analytics==='on', req.body.id];
    if (req.body.new_password) {
        const hash = await bcrypt.hash(req.body.new_password, saltRounds);
        await pool.query("UPDATE users SET is_superadmin=$1, can_add=$2, can_delete=$3, can_view_analytics=$4, password_hash=$5 WHERE id=$6", 
        [...perms.slice(0,4), hash, req.body.id]);
    } else {
        await pool.query("UPDATE users SET is_superadmin=$1, can_add=$2, can_delete=$3, can_view_analytics=$4 WHERE id=$5", perms);
    }
    res.redirect('/admin/users');
});
app.post('/admin/delete-user', isAuthenticated, isSuperAdmin, async (req, res) => {
    if (req.body.id != req.user.id) await pool.query("DELETE FROM users WHERE id = $1", [req.body.id]);
    res.redirect('/admin/users');
});

// --- History & Analytics ---
app.get('/admin/history', isAuthenticated, async (req, res) => {
    const r = await pool.query("SELECT * FROM history_logs ORDER BY timestamp DESC LIMIT 100");
    res.render('admin/history', { logs: r.rows });
});

app.get('/admin/analytics', isAuthenticated, canViewAnalytics, async (req, res) => {
    const { stock_id, country } = req.query;
    let sql = "SELECT * FROM link_clicks";
    let params = [];
    if (stock_id) { sql += " WHERE stock_id ILIKE $1"; params.push(`%${stock_id}%`); }
    sql += " ORDER BY timestamp DESC LIMIT 50";
    
    const r = await pool.query(sql, params);
    res.render('admin/analytics', { 
        clicks: r.rows, 
        totalPages: 1, currentPage: 1, searchParams: req.query 
    });
});

app.get('/admin/qr/:stockId', isAuthenticated, async (req, res) => {
    const id = req.params.stockId.toUpperCase();
    const base = `${req.protocol}://${req.get('host')}`;
    const pubUrl = `${base}/diamonds/${id}?utm_source=qrcode`;
    const qr = await QRCode.toDataURL(pubUrl);
    res.render('admin/qr_code', { stock_id: id, publicUrl: pubUrl, baseUrl: base, qrCodeDataUrl: qr });
});


app.listen(port, () => {
    console.log(`Server running on port ${port}`);
    initDb().catch(console.error);
});
