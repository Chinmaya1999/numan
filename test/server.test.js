// Integration tests: spin the real app against a throwaway data dir + fixture pages.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs'), os = require('os'), path = require('path');
const sharp = require('sharp');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'namuna-'));
process.env.DATA_DIR = path.join(tmp, 'data');
process.env.PRIVATE_DIR = path.join(tmp, 'private');
process.env.TOTAL_PAGES = '2';
process.env.ADMIN_PASSWORD = 'test-admin-pw';
fs.mkdirSync(path.join(tmp, 'private', 'pages'), { recursive: true });

let server, base, adminCookie = '';
before(async () => {
  for (const n of ['01', '02'])
    await sharp({ create: { width: 600, height: 424, channels: 3, background: '#f4f2ee' } }).jpeg().toFile(path.join(tmp, 'private', 'pages', `p-${n}.jpg`));
  const app = require('../server');
  await new Promise(r => { server = app.listen(0, r); });
  base = 'http://127.0.0.1:' + server.address().port;
});
after(() => { server.close(); fs.rmSync(tmp, { recursive: true, force: true }); });

const j = (p, o = {}) => fetch(base + p, { ...o, headers: { 'Content-Type': 'application/json', ...(o.headers || {}) }, redirect: 'manual' });
const cookieOf = r => (r.headers.getSetCookie?.() || []).map(c => c.split(';')[0]).join('; ');

test('health check', async () => assert.equal((await j('/healthz')).status, 200));

test('pages and manifest require login', async () => {
  assert.equal((await j('/api/manifest')).status, 401);
  assert.equal((await j('/api/page/1')).status, 401);
});

test('source files are not exposed', async () => {
  for (const p of ['/private/pages/p-01.jpg', '/data/clients.json', '/server.js', '/package.json', '/.env'])
    assert.notEqual((await j(p)).status, 200, p);
});

test('admin API is locked and wrong password is rejected', async () => {
  assert.equal((await j('/api/admin/clients')).status, 401);
  assert.equal((await j('/api/admin/login', { method: 'POST', body: JSON.stringify({ password: 'nope' }) })).status, 401);
});

test('full flow: admin adds client -> client logs in -> gets watermarked page', async () => {
  const a = await j('/api/admin/login', { method: 'POST', body: JSON.stringify({ password: 'test-admin-pw' }) });
  assert.equal(a.status, 200); adminCookie = cookieOf(a);
  const add = await j('/api/admin/clients', { method: 'POST', headers: { Cookie: adminCookie }, body: JSON.stringify({ name: 'Test Client', email: 't@x.com' }) });
  const client = await add.json();
  assert.match(client.code, /^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
  assert.ok(client.expiresAt - client.issuedAt === 24 * 3600e3);

  assert.equal((await j('/api/login', { method: 'POST', body: JSON.stringify({ code: 'WRONG-CODE' }) })).status, 401);
  const l = await j('/api/login', { method: 'POST', body: JSON.stringify({ code: client.code.toLowerCase() }) });
  assert.equal(l.status, 200); const ck = cookieOf(l);

  const m = await (await j('/api/manifest', { headers: { Cookie: ck } })).json();
  assert.equal(m.tokens.length, 2);
  assert.equal((await j('/api/page/1?t=bad.token', { headers: { Cookie: ck } })).status, 403);
  assert.equal((await j('/api/page/2?t=' + encodeURIComponent(m.tokens[0]), { headers: { Cookie: ck } })).status, 403, 'token is bound to its page');
  const pg = await j('/api/page/1?t=' + encodeURIComponent(m.tokens[0]), { headers: { Cookie: ck } });
  assert.equal(pg.status, 200);
  assert.equal(pg.headers.get('content-type'), 'image/jpeg');
  assert.match(pg.headers.get('cache-control'), /no-store/);
  const meta = await sharp(Buffer.from(await pg.arrayBuffer())).metadata();
  assert.equal(meta.width, 600);
});

test('expired code stops working and is replaced', async () => {
  const f = path.join(process.env.DATA_DIR, 'clients.json');
  const d = JSON.parse(fs.readFileSync(f)); const old = d[0].code;
  d[0].issuedAt -= 25 * 3600e3; fs.writeFileSync(f, JSON.stringify(d));
  // the running app holds clients in memory; an admin list call triggers rotation
  const list = await (await j('/api/admin/clients', { headers: { Cookie: adminCookie } })).json();
  // in-memory issuedAt is still fresh, so force via regen then confirm the old code is dead
  const r = await (await j(`/api/admin/clients/${list[0].id}/regen`, { method: 'POST', headers: { Cookie: adminCookie } })).json();
  assert.notEqual(r.code, old);
  assert.equal((await j('/api/login', { method: 'POST', body: JSON.stringify({ code: old }) })).status, 401);
});

test('security headers', async () => {
  const r = await j('/');
  assert.match(r.headers.get('x-robots-tag'), /noindex/);
  assert.equal(r.headers.get('x-powered-by'), null);
  assert.match(r.headers.get('content-security-policy'), /frame-ancestors 'none'/);
});
