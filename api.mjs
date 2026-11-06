// API สมาชิก + ข้อมูลหนังสือรุ่น (Netlify Functions v2 + Netlify Blobs)
import { getStore } from '@netlify/blobs';
import { createHmac, randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scryptAsync = promisify(scrypt);
export const config = { path: '/api/*' };

const USER_RE = /^[a-z0-9._-]{3,30}$/;
const ID_RE = /^[A-Za-z0-9_-]{1,60}$/;
const THEMES = ['sky', 'sunny', 'pink', 'mint'];
const SOCIAL_KEYS = ['facebook', 'instagram', 'tiktok', 'line', 'discord'];
const TOKEN_TTL = 30 * 24 * 3600 * 1000;
const MAX_BODY = 4_000_000;

const err = (status, message) => Object.assign(new Error(message), { status });
const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }
});
const str = (v, max) => String(v ?? '').slice(0, max);
const isImg = v => typeof v === 'string' && v.startsWith('data:image/');

/* ---------- token (HMAC) & password (scrypt) ---------- */
function secret() {
  const s = process.env.SESSION_SECRET;
  if (!s || s.length < 16) throw err(500, 'เซิร์ฟเวอร์ยังไม่ได้ตั้งค่า SESSION_SECRET (อย่างน้อย 16 ตัวอักษร)');
  return s;
}
const mac = p => createHmac('sha256', secret()).update(p).digest('base64url');
function sign(u, tv) {
  const p = Buffer.from(JSON.stringify({ u, tv, exp: Date.now() + TOKEN_TTL })).toString('base64url');
  return p + '.' + mac(p);
}
function verifyToken(t) {
  const [p, s] = String(t).split('.');
  if (!p || !s) return null;
  const a = Buffer.from(s), b = Buffer.from(mac(p));
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  try { const c = JSON.parse(Buffer.from(p, 'base64url').toString()); return c.exp > Date.now() ? c : null; } catch { return null; }
}
const hashPw = async (pw, salt) => (await scryptAsync(String(pw), salt, 64)).toString('hex');
async function checkPw(rec, pw) {
  const a = Buffer.from(await hashPw(pw, rec.salt), 'hex'), b = Buffer.from(rec.hash, 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}
async function newCredentials(pw) {
  if (String(pw).length < 6 || String(pw).length > 200) throw err(400, 'รหัสผ่านต้องมีอย่างน้อย 6 ตัวอักษร');
  const salt = randomBytes(16).toString('hex');
  return { salt, hash: await hashPw(pw, salt) };
}

/* ---------- validation ---------- */
function cleanCover(c = {}) {
  if (!isImg(c.coverImage)) throw err(400, 'รูปหน้าปกไม่ถูกต้อง');
  return { school: str(c.school, 200), title: str(c.title, 200), year: str(c.year, 20), subtitle: str(c.subtitle, 300),
           theme: THEMES.includes(c.theme) ? c.theme : 'sky', coverImage: c.coverImage };
}
function cleanStudent(id, b = {}) {
  const photos = (Array.isArray(b.photos) ? b.photos : []).slice(0, 5).filter(isImg);
  if (photos.length < 3) throw err(400, 'ต้องมีรูปภาพอย่างน้อย 3 รูป');
  const so = b.socials || {};
  return { id, fullName: str(b.fullName, 200), nickname: str(b.nickname, 100), birthdate: str(b.birthdate, 10),
           dreamJob: str(b.dreamJob, 200), quote: str(b.quote, 400),
           socials: Object.fromEntries(SOCIAL_KEYS.map(k => [k, str(so[k], 100)])), photos };
}
async function readBody(req) {
  const t = await req.text();
  if (t.length > MAX_BODY) throw err(413, 'ข้อมูลมีขนาดใหญ่เกินไป');
  try { return t ? JSON.parse(t) : {}; } catch { throw err(400, 'รูปแบบข้อมูลไม่ถูกต้อง'); }
}

/* ---------- router ---------- */
export default async (req) => {
  try { return await route(req); }
  catch (e) {
    if (e.status) return json({ error: e.message }, e.status);
    console.error(e);
    return json({ error: 'เกิดข้อผิดพลาดบนเซิร์ฟเวอร์' }, 500);
  }
};

async function route(req) {
  const path = new URL(req.url).pathname.replace(/^\/api/, '') || '/';
  const m = req.method;
  const users = getStore('users'), books = getStore('yearbooks');
  const getUser = u => users.get(u, { type: 'json' });
  const body = ['POST', 'PUT', 'DELETE'].includes(m) ? await readBody(req) : {};

  if (m === 'GET' && path === '/config') return json({ inviteRequired: !!process.env.REGISTER_CODE });

  if (m === 'POST' && path === '/register') {
    const u = str(body.username, 40).trim().toLowerCase();
    if (!USER_RE.test(u)) throw err(400, 'ชื่อผู้ใช้ต้องเป็น a-z, 0-9, . _ - ยาว 3-30 ตัว');
    const code = process.env.REGISTER_CODE;
    if (code && body.invite !== code) throw err(403, 'รหัสเชิญไม่ถูกต้อง');
    if (await getUser(u)) throw err(409, 'ชื่อผู้ใช้นี้ถูกใช้แล้ว กรุณาเลือกชื่ออื่น');
    const rec = { name: str(body.name, 40).trim() || u, ...(await newCredentials(body.password)), tv: 0, created: Date.now() };
    await users.setJSON(u, rec);
    return json({ token: sign(u, 0), username: u, name: rec.name });
  }

  if (m === 'POST' && path === '/login') {
    const u = str(body.username, 40).trim().toLowerCase();
    const rec = USER_RE.test(u) ? await getUser(u) : null;
    if (rec?.lockUntil > Date.now()) throw err(429, 'ใส่รหัสผิดหลายครั้ง กรุณารอ 15 นาทีแล้วลองใหม่');
    if (!rec || !(await checkPw(rec, body.password))) {
      if (rec) {
        rec.fails = (rec.fails || 0) + 1;
        if (rec.fails >= 5) { rec.lockUntil = Date.now() + 15 * 60 * 1000; rec.fails = 0; }
        await users.setJSON(u, rec);
      }
      throw err(401, 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง');
    }
    if (rec.fails || rec.lockUntil) { rec.fails = 0; delete rec.lockUntil; await users.setJSON(u, rec); }
    return json({ token: sign(u, rec.tv), username: u, name: rec.name });
  }

  /* ----- ต่อจากนี้ต้องล็อกอิน ----- */
  const claim = verifyToken((req.headers.get('authorization') || '').replace(/^Bearer /, ''));
  const rec = claim && (await getUser(claim.u));
  if (!rec || rec.tv !== claim.tv) throw err(401, 'เซสชันหมดอายุ กรุณาเข้าสู่ระบบใหม่');
  const u = claim.u;

  if (path === '/meta') {
    if (m === 'GET') return json((await books.get(`${u}/meta`, { type: 'json' })) || { cover: null, order: [] });
    if (m === 'PUT') {
      const order = Array.isArray(body.order) ? body.order.filter(id => ID_RE.test(id)).slice(0, 500) : [];
      await books.setJSON(`${u}/meta`, { cover: cleanCover(body.cover), order });
      return json({ ok: true });
    }
  }

  const sm = path.match(/^\/student\/([^/]+)$/);
  if (sm) {
    const id = sm[1];
    if (!ID_RE.test(id)) throw err(400, 'รหัสนักเรียนไม่ถูกต้อง');
    const key = `${u}/s/${id}`;
    if (m === 'GET') { const s = await books.get(key, { type: 'json' }); if (!s) throw err(404, 'ไม่พบข้อมูลนักเรียน'); return json(s); }
    if (m === 'PUT') { await books.setJSON(key, cleanStudent(id, body)); return json({ ok: true }); }
    if (m === 'DELETE') { await books.delete(key); return json({ ok: true }); }
  }

  if (m === 'POST' && path === '/password') {
    if (!(await checkPw(rec, body.oldPassword))) throw err(403, 'รหัสผ่านเดิมไม่ถูกต้อง');
    Object.assign(rec, await newCredentials(body.newPassword), { tv: rec.tv + 1 }); // เซสชันเก่าทั้งหมดใช้ไม่ได้
    await users.setJSON(u, rec);
    return json({ token: sign(u, rec.tv) });
  }

  if (m === 'DELETE' && path === '/account') {
    if (!(await checkPw(rec, body.password))) throw err(403, 'รหัสผ่านไม่ถูกต้อง');
    const { blobs } = await books.list({ prefix: `${u}/` });
    await Promise.all(blobs.map(b => books.delete(b.key)));
    await users.delete(u);
    return json({ ok: true });
  }

  throw err(404, 'ไม่พบเส้นทางนี้');
}
