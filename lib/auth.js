// Login for the web UI: user accounts (see users.js), sessions in memory.
//
// With no account yet, the temporary login admin / admin works. Its session can only create
// the first real admin (on /setup); from then on it is gone.
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const users = require('./users');

const COOKIE = 'fgt_session';
const SESSION_IDLE_MS = 12 * 3600 * 1000; // a session ends after 12 h without requests
const MAX_FAILURES = 5; // failed logins per address ...
const FAILURE_WINDOW_MS = 15 * 60 * 1000; // ... within this window, then it is locked out
const MIN_PASSWORD = 12;
// The temporary login while there is no account. Never stored: it stops working once one exists.
const DUMMY_USER = 'admin';
const DUMMY_PASSWORD = 'admin';

const scrypt = promisify(crypto.scrypt);
const hashPassword = (password, salt) => scrypt(String(password), salt, 32);
// Compares digests, so neither length nor content leaks through timing.
const sameText = (a, b) => crypto.timingSafeEqual(
  crypto.createHash('sha256').update(String(a)).digest(),
  crypto.createHash('sha256').update(String(b)).digest(),
);

function checkPassword(password) {
  const p = String(password ?? '');
  if (p.length < MIN_PASSWORD) throw new Error(`The password needs at least ${MIN_PASSWORD} characters`);
  if (p.length > 256) throw new Error('The password can have at most 256 characters');
  return p;
}

async function sealPassword(password) {
  const salt = crypto.randomBytes(16);
  return { salt: salt.toString('base64'), hash: (await hashPassword(checkPassword(password), salt)).toString('base64') };
}

// A wrong user name costs as much time as a wrong password.
const NO_USER = { salt: crypto.randomBytes(16).toString('base64'), hash: crypto.randomBytes(32).toString('base64') };

async function passwordMatches(u, password) {
  const rec = u || NO_USER;
  const hash = await hashPassword(password ?? '', Buffer.from(rec.salt, 'base64'));
  const stored = Buffer.from(rec.hash, 'base64');
  return !!u && stored.length === hash.length && crypto.timingSafeEqual(hash, stored);
}

let noAccounts = false;

async function addUser(name, role, password) {
  const now = new Date().toISOString();
  const u = { name: users.normName(name), role: users.checkRole(role), disabled: false,
    ...(await sealPassword(password)), createdAt: now, passwordChangedAt: now };
  await users.add(u);
  return users.publicView(u);
}

async function init() {
  await users.init();
  if (await users.count()) return;
  noAccounts = true;
  console.warn(`No user accounts yet. Log in with ${DUMMY_USER} / ${DUMMY_PASSWORD} and create your own admin account; `
    + 'the temporary login is removed then. Until that, anyone who can reach this port can do the same.');
}

const setupPending = () => noAccounts;

// ---------- failed-login throttle (per client address) ----------
const failures = new Map(); // address -> { count, since }

function lockedFor(addr) {
  const f = failures.get(addr);
  if (!f) return 0;
  const left = f.since + FAILURE_WINDOW_MS - Date.now();
  if (left <= 0) {
    failures.delete(addr);
    return 0;
  }
  return f.count >= MAX_FAILURES ? Math.ceil(left / 1000) : 0;
}

function recordFailure(addr) {
  if (failures.size > 10000) failures.clear();
  const f = failures.get(addr);
  if (f) f.count++;
  else failures.set(addr, { count: 1, since: Date.now() });
}

const lockout = (wait) => ({ status: 429, error: `Too many failed attempts. Try again in ${Math.ceil(wait / 60)} min.`, retryAfter: wait });

// ---------- sessions ----------
const sessions = new Map(); // id -> { name, role, expires }

function sessionId(req) {
  const m = /(?:^|;\s*)fgt_session=([A-Za-z0-9_-]+)/.exec(req.headers.cookie || '');
  return m && m[1];
}

// The logged-in user of a request ({ name, role }), or null.
function user(req) {
  const id = sessionId(req);
  const s = id && sessions.get(id);
  if (!s) return null;
  if (s.expires < Date.now()) {
    sessions.delete(id);
    return null;
  }
  s.expires = Date.now() + SESSION_IDLE_MS;
  return { name: s.name, role: s.role };
}

// Secure is added when the request arrived over HTTPS (directly or through a reverse proxy).
function cookie(req, value, extra = '') {
  const https = req.socket.encrypted || /^https\b/.test(req.headers['x-forwarded-proto'] || '');
  return `${COOKIE}=${value}; Path=/; HttpOnly; SameSite=Strict${https ? '; Secure' : ''}${extra}`;
}

function startSession(req, u) {
  const now = Date.now();
  for (const [id, s] of sessions) if (s.expires < now) sessions.delete(id);
  const id = crypto.randomBytes(32).toString('base64url');
  sessions.set(id, { name: u.name, role: u.role, expires: now + SESSION_IDLE_MS });
  return cookie(req, id);
}

// Ends the sessions of a user (all of them, or all but the one of `keepReq`).
function endSessions(name, keepReq) {
  const keep = keepReq && sessionId(keepReq);
  for (const [id, s] of sessions) if (s.name === name && id !== keep) sessions.delete(id);
}

// Returns { cookie } on success, or { status, error, retryAfter } on failure.
async function login(req, username, password) {
  const addr = req.socket.remoteAddress || '';
  const wait = lockedFor(addr);
  if (wait) return lockout(wait);
  let name;
  try {
    name = users.normName(username);
  } catch {
    name = '';
  }
  // The temporary login: a session that can only create the first admin (see setup()).
  // `&`, not `&&`: both are always compared.
  if (noAccounts && sameText(username ?? '', DUMMY_USER) & sameText(password ?? '', DUMMY_PASSWORD)) {
    failures.delete(addr);
    console.warn(`Temporary login ${DUMMY_USER} used from ${addr}`);
    return { cookie: startSession(req, { name: DUMMY_USER, role: 'setup' }) };
  }
  const u = name ? await users.getWithHash(name) : null;
  // A disabled account answers like a wrong password, so it does not reveal that it exists.
  if (!(await passwordMatches(u, password)) || u.disabled) {
    recordFailure(addr);
    console.warn(`Failed login for "${String(username ?? '').slice(0, 64)}" from ${addr}`);
    return { status: 401, error: 'Wrong user or password' };
  }
  failures.delete(addr);
  await users.update(u.name, { lastLoginAt: new Date().toISOString() });
  return { cookie: startSession(req, u) };
}

// Creates the first admin from a session of the temporary login. That login is then gone:
// every session of it ends, and this browser continues as the new admin.
async function setup(req, me, name, password) {
  if (!noAccounts || me?.role !== 'setup') return { status: 409, error: 'Setup is already done: log in instead' };
  const u = await addUser(name, 'admin', password);
  noAccounts = false;
  for (const [id, s] of sessions) if (s.role === 'setup') sessions.delete(id);
  console.log(`First admin "${u.name}" created; the temporary login ${DUMMY_USER} / ${DUMMY_PASSWORD} is removed.`);
  return { cookie: startSession(req, u) };
}

// Ends the session; returns the cookie header that removes it from the browser.
function logout(req) {
  const id = sessionId(req);
  if (id) sessions.delete(id);
  return cookie(req, '', '; Max-Age=0');
}

// ---------- account management ----------
async function changeOwnPassword(req, me, current, password) {
  const addr = req.socket.remoteAddress || '';
  const wait = lockedFor(addr);
  if (wait) return lockout(wait);
  const u = await users.getWithHash(me.name);
  if (!(await passwordMatches(u, current))) {
    recordFailure(addr);
    return { status: 403, error: 'The current password is wrong' };
  }
  await users.update(me.name, { ...(await sealPassword(password)), passwordChangedAt: new Date().toISOString() });
  endSessions(me.name, req); // other browsers logged in as this user must log in again
  return { ok: true };
}

const enabledAdmins = async () => (await users.list()).filter((u) => u.role === 'admin' && !u.disabled).length;

// Changes { role, disabled, password } of a user. The last enabled admin cannot be demoted or
// disabled, and no one can demote or disable themselves (so an admin always remains).
async function updateUser(me, name, b) {
  name = users.normName(name);
  const u = await users.getWithHash(name);
  if (!u) return { status: 404, error: 'User not found' };
  const fields = {};
  if (b.role !== undefined && b.role !== u.role) fields.role = users.checkRole(b.role);
  if (b.disabled !== undefined && !!b.disabled !== u.disabled) fields.disabled = !!b.disabled;
  if (b.password) Object.assign(fields, await sealPassword(b.password), { passwordChangedAt: new Date().toISOString() });
  const losesAdmin = u.role === 'admin' && !u.disabled && (fields.role === 'viewer' || fields.disabled === true);
  if (losesAdmin && name === me.name) return { status: 409, error: 'You cannot remove your own admin rights or disable yourself' };
  if (losesAdmin && (await enabledAdmins()) <= 1) return { status: 409, error: 'This is the last enabled admin' };
  await users.update(name, fields);
  // A new role, a disabled account or a new password takes effect at once.
  if (Object.keys(fields).length) endSessions(name);
  return { user: users.publicView({ ...u, ...fields }) };
}

async function removeUser(me, name) {
  name = users.normName(name);
  if (name === me.name) return { status: 409, error: 'You cannot delete your own account' };
  const u = await users.getWithHash(name);
  if (!u) return { status: 404, error: 'User not found' };
  if (u.role === 'admin' && !u.disabled && (await enabledAdmins()) <= 1) return { status: 409, error: 'This is the last enabled admin' };
  await users.remove(name);
  endSessions(name);
  return { ok: true };
}

// ---------- permissions ----------
// A viewer can read everything except what only serves pushing (live object lists and
// administrators of the devices), and can ask the firewalls for their threat feed status
// (read-only on the devices). Everything else that changes something needs an admin.
const PUSH_READS = /^\/api\/firewalls\/[\w-]+\/(?:existing|objects|vdoms)$/;
const VIEWER_POSTS = [/^\/api\/firewalls\/[\w-]+\/threatfeeds$/, /^\/api\/me\/password$/];

function allowed(u, method, p) {
  if (u.role === 'setup') return false; // the temporary login only reaches /setup (server.js)
  if (u.role === 'admin') return true;
  if (method === 'GET' || method === 'HEAD') return !PUSH_READS.test(p) && !p.startsWith('/api/users');
  return method === 'POST' && VIEWER_POSTS.some((re) => re.test(p));
}

// Browsers send Origin on every cross-site request that can change something. One that does
// not match the Host the request was sent to comes from another site: refuse it (CSRF).
function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try {
    return new URL(origin).host === req.headers.host;
  } catch {
    return false;
  }
}

module.exports = {
  MIN_PASSWORD, init, setupPending, user, login, setup, logout, sameOrigin, allowed,
  addUser, updateUser, removeUser, changeOwnPassword, listUsers: () => users.list(),
};
