// Namuna private viewer: login -> signed session -> short-lived page tokens -> server-watermarked JPEG.
// The PDF and the source page images live in ./private and are never served statically.
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const sharp = require('sharp');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');          // persistent: clients, admin pw, secret
const PRIVATE = process.env.PRIVATE_DIR || path.join(__dirname, 'private'); // source page images, never served statically
const SF = path.join(DATA, 'secret');
fs.mkdirSync(DATA, { recursive: true });
const SECRET = process.env.SESSION_SECRET || (() => {   // persisted so restarts don't log everyone out
  try { return fs.readFileSync(SF, 'utf8'); } catch (_) {}
  const k = crypto.randomBytes(32).toString('hex'); fs.writeFileSync(SF, k, { mode: 0o600 }); return k;
})();
const TOTAL = +process.env.TOTAL_PAGES || 26;
const SESSION_MS = 4 * 60 * 60 * 1000;   // 4 h
const TOKEN_MS = 2 * 60 * 1000;          // page token life: 2 min
const CF = path.join(DATA, 'clients.json'), AF = path.join(DATA, 'admin.json');
const CODE_TTL = 24 * 60 * 60 * 1000;                       // access codes regenerate every 24 h
const ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';           // no look-alike characters
const newCode = () => { const b = crypto.randomBytes(8); let c = ''; for (const x of b) c += ALPHA[x % ALPHA.length]; return c.slice(0, 4) + '-' + c.slice(4); };
let clients = [];
try { clients = JSON.parse(fs.readFileSync(CF, 'utf8')); } catch (_) {}
const save = () => fs.writeFileSync(CF, JSON.stringify(clients, null, 2));
function rotate() {                                          // lazily rotate any expired code
  let ch = false; const now = Date.now();
  for (const c of clients) if (!c.issuedAt || now - c.issuedAt >= CODE_TTL) { c.code = newCode(); c.issuedAt = now; ch = true; }
  if (ch) save();
}
setInterval(rotate, 60 * 1000).unref(); rotate();
// admin password: ADMIN_PASSWORD env, else generated once and stored in data/admin.json
let ADMIN_PW = process.env.ADMIN_PASSWORD;
if (!ADMIN_PW) {
  try { ADMIN_PW = JSON.parse(fs.readFileSync(AF, 'utf8')).password; } catch (_) {}
  if (!ADMIN_PW) { ADMIN_PW = crypto.randomBytes(9).toString('base64url'); fs.writeFileSync(AF, JSON.stringify({ password: ADMIN_PW }, null, 2)); console.log('Admin password created:', ADMIN_PW); }
}

const sign = s => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');
const safeEq = (a, b) => { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && crypto.timingSafeEqual(x, y); };

function makeSession(c) {
  const body = Buffer.from(JSON.stringify({ id: c.id, name: c.name, email: c.email, exp: Date.now() + SESSION_MS })).toString('base64url');
  return body + '.' + sign(body);
}
function readSession(raw) {
  if (!raw) return null;
  const [body, sig] = raw.split('.');
  if (!body || !sig || !safeEq(sig, sign(body))) return null;
  const s = JSON.parse(Buffer.from(body, 'base64url').toString());
  return s.exp > Date.now() ? s : null;
}
const auth = (req, res, next) => {
  const s = readSession(req.cookies.nm);
  if (!s) return res.status(401).json({ error: 'auth' });
  req.user = s; next();
};
const pageToken = (sid, n, exp) => exp + '.' + sign(`${sid}|${n}|${exp}`);

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: { directives: {
    defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'"], styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
    fontSrc: ['https://fonts.gstatic.com'], imgSrc: ["'self'", 'blob:', 'data:'], connectSrc: ["'self'"], frameAncestors: ["'none'"], upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null } },
  referrerPolicy: { policy: 'no-referrer' },
}));
app.use(express.json({ limit: '2kb' }));
app.use(cookieParser());
app.use((req, res, next) => { res.set('X-Robots-Tag', 'noindex, nofollow, noarchive, noimageindex'); next(); });

// ---- login ----
app.post('/api/login', rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false }), (req, res) => {
  rotate();
  const code = String(req.body.code || '').trim().toUpperCase();
  const h = v => crypto.createHash('sha256').update(v).digest('base64url');
  const c = clients.find(x => safeEq(h(x.code.toUpperCase()), h(code)));
  if (!c) return res.status(401).json({ error: 'Invalid access code' });
  res.cookie('nm', makeSession(c), { httpOnly: true, secure: req.secure, sameSite: 'strict', maxAge: SESSION_MS });
  console.log(new Date().toISOString(), 'login', c.id, c.email);
  res.json({ name: c.name });
});
app.post('/api/logout', (req, res) => { res.clearCookie('nm'); res.json({ ok: true }); });

// ---- manifest: fresh short-lived token per page ----
app.get('/api/manifest', auth, (req, res) => {
  const exp = Date.now() + TOKEN_MS;
  res.set('Cache-Control', 'no-store');
  res.json({ total: TOTAL, name: req.user.name, tokens: Array.from({ length: TOTAL }, (_, i) => pageToken(req.user.id, i + 1, exp)) });
});

// ---- one watermarked page ----
const pageLimit = rateLimit({ windowMs: 60 * 1000, limit: 120, keyGenerator: r => (readSession(r.cookies.nm) || {}).id || r.ip, standardHeaders: true, legacyHeaders: false });
app.get('/api/page/:n', auth, pageLimit, async (req, res) => {
  const n = parseInt(req.params.n, 10);
  const [exp, sig] = String(req.query.t || '').split('.');
  if (!(n >= 1 && n <= TOTAL) || !exp || +exp < Date.now() || !sig || !safeEq(sig, sign(`${req.user.id}|${n}|${exp}`)))
    return res.status(403).json({ error: 'token' });
  try {
    const file = path.join(PRIVATE, 'pages', `p-${String(n).padStart(2, '0')}.jpg`);
    const meta = await sharp(file).metadata();
    const w = meta.width, h = meta.height, fs_ = Math.round(w / 80);
    const esc = t => t.replace(/&/g, '&amp;').replace(/</g, '&lt;');
    const mark = 'Designed by adihuman.', big = Math.round(w / 38);
    // three fixed marks per page, plus one near-invisible per-client trace in the corner
    const spots = [[0.07, 0.30], [0.40, 0.58], [0.20, 0.88]];
    const marks = spots.map(([x, y]) => `<text x="${Math.round(w * x)}" y="${Math.round(h * y)}" transform="rotate(-18 ${Math.round(w * x)} ${Math.round(h * y)})">${mark}</text>`).join('');
    const trace = esc(`${req.user.name} · ${req.user.email} · ${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC`);
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}">
      <g font-family="Helvetica,Arial,sans-serif" font-size="${big}" font-weight="600" letter-spacing="2" fill="#2a1b18" fill-opacity="0.09">${marks}</g>
      <text x="${w - 16}" y="${h - 12}" text-anchor="end" font-family="Helvetica,Arial,sans-serif" font-size="${Math.round(w / 150)}" fill="#2a1b18" fill-opacity="0.12">${trace}</text></svg>`;
    const out = await sharp(file).composite([{ input: Buffer.from(svg) }]).jpeg({ quality: 84 }).toBuffer();
    res.set({ 'Content-Type': 'image/jpeg', 'Cache-Control': 'no-store, private', 'X-Content-Type-Options': 'nosniff' }).send(out);
  } catch (e) { console.error(e); res.status(500).end(); }
});


// ---- admin dashboard ----
const adminAuth = (req, res, next) => {
  const raw = req.cookies.nma; const [b, sig] = (raw || '').split('.');
  if (!b || !sig || !safeEq(sig, sign('admin|' + b)) || +b < Date.now()) return res.status(401).json({ error: 'auth' });
  next();
};
const hashPw = v => crypto.createHash('sha256').update(String(v)).digest('base64url');
app.post('/api/admin/login', rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: true, legacyHeaders: false }), (req, res) => {
  if (!safeEq(hashPw(req.body.password || ''), hashPw(ADMIN_PW))) return res.status(401).json({ error: 'Wrong password' });
  const exp = String(Date.now() + 2 * 60 * 60 * 1000);
  res.cookie('nma', exp + '.' + sign('admin|' + exp), { httpOnly: true, secure: req.secure, sameSite: 'strict', maxAge: 2 * 60 * 60 * 1000, path: '/' });
  res.json({ ok: true });
});
app.post('/api/admin/logout', (req, res) => { res.clearCookie('nma'); res.json({ ok: true }); });
const view = c => ({ id: c.id, name: c.name, email: c.email, code: c.code, issuedAt: c.issuedAt, expiresAt: c.issuedAt + CODE_TTL });
app.get('/api/admin/clients', adminAuth, (req, res) => { rotate(); res.set('Cache-Control', 'no-store').json(clients.map(view)); });
app.post('/api/admin/clients', adminAuth, (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 80), email = String(req.body.email || '').trim().slice(0, 120);
  if (!name) return res.status(400).json({ error: 'Name required' });
  const c = { id: crypto.randomBytes(6).toString('hex'), name, email, code: newCode(), issuedAt: Date.now() };
  clients.push(c); save(); res.json(view(c));
});
app.post('/api/admin/clients/:id/regen', adminAuth, (req, res) => {
  const c = clients.find(x => x.id === req.params.id); if (!c) return res.status(404).end();
  c.code = newCode(); c.issuedAt = Date.now(); save(); res.json(view(c));
});
app.delete('/api/admin/clients/:id', adminAuth, (req, res) => { clients = clients.filter(x => x.id !== req.params.id); save(); res.json({ ok: true }); });
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin', 'admin.html')));

app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html', dotfiles: 'deny' }));
app.get('/healthz', (req, res) => res.json({ ok: true }));
if (require.main === module) app.listen(PORT, '127.0.0.1', () => console.log(`Namuna viewer on http://127.0.0.1:${PORT}`));
module.exports = app;
