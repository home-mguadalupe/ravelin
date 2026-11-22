// Login accounts. Stored in PostgreSQL when DATABASE_URL is set, otherwise in data/users.json.
// Passwords are kept only as scrypt hashes; records returned by list() / get() never carry them.
//
// Roles: "admin" can do everything, "viewer" can only look (see auth.allowed()).
const fs = require('node:fs');
const path = require('node:path');

const JSON_FILE = path.join(__dirname, '..', 'data', 'users.json');
const ROLES = ['admin', 'viewer'];

// Names are compared without case, so they are stored in lower case.
function normName(name) {
  const n = String(name ?? '').trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9._@-]{0,63}$/.test(n)) {
    throw new Error('User name: 1-64 letters, digits, ".", "_", "-" or "@", starting with a letter or digit');
  }
  return n;
}

function checkRole(role) {
  if (!ROLES.includes(role)) throw new Error(`Role must be ${ROLES.join(' or ')}`);
  return role;
}

const publicView = ({ salt, hash, ...u }) => u;

// ---------- JSON file ----------
const jsonStore = {
  async init() {},
  read() {
    try {
      return JSON.parse(fs.readFileSync(JSON_FILE, 'utf8'));
    } catch (err) {
      if (err.code === 'ENOENT') return [];
      throw new Error(`Cannot read ${JSON_FILE}: ${err.message}`);
    }
  },
  save(list) {
    fs.writeFileSync(JSON_FILE, JSON.stringify(list, null, 2) + '\n', { mode: 0o600 });
    fs.chmodSync(JSON_FILE, 0o600); // `mode` only applies when the file is created
  },
  async count() {
    return this.read().length;
  },
  async list() {
    return this.read();
  },
  async get(name) {
    return this.read().find((u) => u.name === name);
  },
  async add(u) {
    const list = this.read();
    if (list.some((x) => x.name === u.name)) throw new Error(`User "${u.name}" already exists`);
    this.save([...list, u]);
  },
  async update(name, fields) {
    this.save(this.read().map((u) => (u.name === name ? { ...u, ...fields } : u)));
  },
  async remove(name) {
    this.save(this.read().filter((u) => u.name !== name));
  },
};

// ---------- PostgreSQL ----------
const COLS = `name, role, disabled, salt, hash, created_at AS "createdAt",
  password_changed_at AS "passwordChangedAt", last_login_at AS "lastLoginAt"`;
const COLUMN = { role: 'role', disabled: 'disabled', salt: 'salt', hash: 'hash',
  passwordChangedAt: 'password_changed_at', lastLoginAt: 'last_login_at' };

const pgStore = {
  async init() {
    // The schema is already applied by firewalls.init(), which runs first.
    this.pool = require('./db').getPool();
    // Accounts made while running without a database move into it; the file is then removed.
    const legacy = jsonStore.read();
    if (!legacy.length) return;
    for (const u of legacy) await this.add(u, true);
    fs.unlinkSync(JSON_FILE);
    console.log(`Imported ${legacy.length} user(s) from ${JSON_FILE} into the database and removed the file.`);
  },
  async count() {
    return Number((await this.pool.query('SELECT count(*) FROM users')).rows[0].count);
  },
  async list() {
    return (await this.pool.query(`SELECT ${COLS} FROM users ORDER BY name`)).rows;
  },
  async get(name) {
    return (await this.pool.query(`SELECT ${COLS} FROM users WHERE name = $1`, [name])).rows[0];
  },
  async add(u, skipExisting = false) {
    const r = await this.pool.query(
      `INSERT INTO users (name, role, disabled, salt, hash, created_at, password_changed_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (name) DO NOTHING`,
      [u.name, u.role, !!u.disabled, u.salt, u.hash, u.createdAt, u.passwordChangedAt]
    );
    if (!r.rowCount && !skipExisting) throw new Error(`User "${u.name}" already exists`);
  },
  async update(name, fields) {
    const keys = Object.keys(fields).filter((k) => COLUMN[k]);
    if (!keys.length) return;
    await this.pool.query(
      `UPDATE users SET ${keys.map((k, i) => `${COLUMN[k]} = $${i + 2}`).join(', ')} WHERE name = $1`,
      [name, ...keys.map((k) => fields[k])]
    );
  },
  async remove(name) {
    await this.pool.query('DELETE FROM users WHERE name = $1', [name]);
  },
};

const store = process.env.DATABASE_URL ? pgStore : jsonStore;

module.exports = {
  ROLES,
  normName,
  checkRole,
  publicView,
  init: () => store.init(),
  count: () => store.count(),
  list: async () => (await store.list()).map(publicView),
  // With the password hash: only for auth.js.
  getWithHash: (name) => store.get(name),
  add: (u) => store.add(u),
  update: (name, fields) => store.update(name, fields),
  remove: (name) => store.remove(name),
};
