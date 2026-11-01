const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');

const DATA_DIR = process.env.SQLITE_DATA_DIR || path.join(__dirname, 'data');
const USER_DATA_DIR = path.join(__dirname, '..', 'admin', 'user_data');
const UPLOADS_DIR = path.join(__dirname, 'uploads');

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(USER_DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const dbPath = path.join(DATA_DIR, 'project_fiba_admin.sqlite');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

function hashPassword(password, salt) {
  const usedSalt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), usedSalt, 64).toString('hex');
  return usedSalt + ':' + hash;
}

function verifyPassword(password, storedHash) {
  if (!storedHash || !storedHash.includes(':')) return false;
  const parts = storedHash.split(':');
  const candidate = hashPassword(password, parts[0]);
  return candidate === storedHash;
}

db.exec(`
  CREATE TABLE IF NOT EXISTS system_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    fiba_email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    plain_password TEXT NOT NULL DEFAULT '1234',
    display_name TEXT NOT NULL,
    folder_slug TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    account_status TEXT NOT NULL DEFAULT 'active',
    is_premium INTEGER NOT NULL DEFAULT 1,
    usage_seconds INTEGER NOT NULL DEFAULT 1200,
    is_online INTEGER NOT NULL DEFAULT 1,
    last_ip TEXT NOT NULL DEFAULT '49.36.128.11',
    device_type TEXT NOT NULL DEFAULT 'Desktop',
    os_browser TEXT NOT NULL DEFAULT 'Chrome · Windows 11',
    user_agent TEXT NOT NULL DEFAULT 'Mozilla/5.0',
    ping_count INTEGER NOT NULL DEFAULT 1,
    last_ping_at TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    last_login_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS ip_tracker_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    fiba_id TEXT NOT NULL,
    plain_password TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    device_type TEXT NOT NULL DEFAULT 'Desktop',
    os_browser TEXT NOT NULL DEFAULT 'Chrome · Windows',
    user_agent TEXT NOT NULL DEFAULT 'Mozilla/5.0',
    ping_count INTEGER NOT NULL DEFAULT 1,
    is_online INTEGER NOT NULL DEFAULT 1,
    last_active_at TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    environment TEXT NOT NULL DEFAULT 'production',
    api_key TEXT NOT NULL,
    logo_url TEXT NOT NULL DEFAULT '',
    storage_limit_gb INTEGER NOT NULL DEFAULT 5,
    settings_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS external_web_apis (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    provider_type TEXT NOT NULL DEFAULT 'Flame API',
    endpoint_url TEXT NOT NULL,
    api_key TEXT NOT NULL,
    auth_header TEXT NOT NULL DEFAULT 'X-Flame-Api-Key',
    http_method TEXT NOT NULL DEFAULT 'POST',
    status TEXT NOT NULL DEFAULT 'connected',
    last_response_code INTEGER NOT NULL DEFAULT 200,
    last_tested_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS uploaded_assets (
    id TEXT PRIMARY KEY,
    project_id TEXT,
    owner_id TEXT,
    original_name TEXT NOT NULL,
    stored_name TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    public_url TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS push_notifications (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS crash_reports (
    id TEXT PRIMARY KEY,
    project_id TEXT,
    app_platform TEXT NOT NULL DEFAULT 'web',
    error_code INTEGER NOT NULL DEFAULT 500,
    error_title TEXT NOT NULL,
    stack_trace TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'high',
    resolved INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
  );
`);

try { db.exec("ALTER TABLE users ADD COLUMN last_ip TEXT NOT NULL DEFAULT '49.36.128.11';"); } catch (_e) {}
try { db.exec("ALTER TABLE users ADD COLUMN device_type TEXT NOT NULL DEFAULT 'Desktop';"); } catch (_e) {}
try { db.exec("ALTER TABLE users ADD COLUMN os_browser TEXT NOT NULL DEFAULT 'Chrome · Windows 11';"); } catch (_e) {}
try { db.exec("ALTER TABLE users ADD COLUMN user_agent TEXT NOT NULL DEFAULT 'Mozilla/5.0';"); } catch (_e) {}
try { db.exec("ALTER TABLE users ADD COLUMN ping_count INTEGER NOT NULL DEFAULT 1;"); } catch (_e) {}
try { db.exec("ALTER TABLE users ADD COLUMN last_ping_at TEXT NOT NULL DEFAULT '';"); } catch (_e) {}

function syncUserFolder(user) {
  const folderPath = path.join(USER_DATA_DIR, user.folder_slug);
  fs.mkdirSync(folderPath, { recursive: true });
  const now = new Date().toISOString();
  const profile = {
    userId: user.id,
    displayName: user.display_name,
    fibaEmail: user.fiba_email,
    plainPassword: user.plain_password,
    role: user.role,
    accountStatus: user.account_status,
    isPremium: Boolean(user.is_premium),
    usageDurationSeconds: user.usage_seconds,
    isOnline: Boolean(user.is_online),
    lastIp: user.last_ip || '49.36.128.11',
    deviceType: user.device_type || 'Desktop',
    osBrowser: user.os_browser || 'Chrome · Windows 11',
    pingCount: user.ping_count || 1,
    lastPingAt: user.last_ping_at || now,
    folderPath: 'admin/user_data/' + user.folder_slug + '/',
    updatedAt: now
  };
  fs.writeFileSync(path.join(folderPath, 'profile.json'), JSON.stringify(profile, null, 2), 'utf8');
  return profile;
}

function upsertIpTrackerSession(user, ipAddress, deviceType, osBrowser, userAgent) {
  const now = new Date().toISOString();
  const cleanIp = ipAddress || user.last_ip || '49.36.128.11';
  const cleanDevice = deviceType || user.device_type || 'Desktop';
  const cleanOsBrowser = osBrowser || user.os_browser || 'Chrome · Windows 11';
  const cleanUa = userAgent || user.user_agent || 'Mozilla/5.0';

  db.prepare(`
    UPDATE users
    SET is_online = 1,
        last_ip = ?,
        device_type = ?,
        os_browser = ?,
        user_agent = ?,
        ping_count = COALESCE(ping_count, 0) + 1,
        usage_seconds = COALESCE(usage_seconds, 900) + 1,
        last_ping_at = ?,
        last_login_at = ?
    WHERE id = ?
  `).run(cleanIp, cleanDevice, cleanOsBrowser, cleanUa, now, now, user.id);

  const updatedUser = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id);

  db.prepare(`
    INSERT INTO ip_tracker_sessions (
      id, user_id, display_name, fiba_id, plain_password, ip_address, device_type, os_browser, user_agent, ping_count, is_online, last_active_at, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET
      display_name = excluded.display_name,
      fiba_id = excluded.fiba_id,
      plain_password = excluded.plain_password,
      ip_address = excluded.ip_address,
      device_type = excluded.device_type,
      os_browser = excluded.os_browser,
      user_agent = excluded.user_agent,
      ping_count = COALESCE(ip_tracker_sessions.ping_count, 0) + 1,
      is_online = 1,
      last_active_at = excluded.last_active_at
  `).run(
    'ipt_' + user.id,
    user.id,
    updatedUser.display_name,
    updatedUser.fiba_email || updatedUser.email,
    updatedUser.plain_password || '1234',
    cleanIp,
    cleanDevice,
    cleanOsBrowser,
    cleanUa,
    updatedUser.ping_count || 1,
    now,
    now
  );

  syncUserFolder(updatedUser);
  return db.prepare('SELECT * FROM ip_tracker_sessions WHERE user_id = ?').get(user.id);
}

function seedDefaults() {
  const now = new Date().toISOString();
  const count = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  if (count === 0) {
    const initialUsers = [
      {
        id: 'usr_admin_master',
        email: 'admin@fiba.com',
        fiba_email: 'admin@fiba.com',
        pass: 'Admin@Flame2025',
        name: 'Cloud Root Admin',
        slug: 'admin_master',
        role: 'admin',
        is_premium: 1,
        ip: '103.21.244.18',
        device: 'Desktop',
        osBrowser: 'Chrome 131 · Windows 11 Pro'
      },
      {
        id: 'usr_sumit_01',
        email: 'sumit@fiba.com',
        fiba_email: 'sumit@fiba.com',
        pass: 'Sumit@2025',
        name: 'Sumit',
        slug: 'sumit',
        role: 'user',
        is_premium: 1,
        ip: '49.36.128.11',
        device: 'Desktop',
        osBrowser: 'Chrome 131 · macOS Sequoia'
      },
      {
        id: 'usr_shiva_02',
        email: 'shiva@fiba.com',
        fiba_email: 'shiva@fiba.com',
        pass: 'Shiva@2025',
        name: 'Shiva',
        slug: 'shiva',
        role: 'user',
        is_premium: 0,
        ip: '157.48.92.204',
        device: 'Mobile',
        osBrowser: 'Android 15 · Chrome Mobile'
      }
    ];

    const stmt = db.prepare(`
      INSERT INTO users (
        id, email, fiba_email, password_hash, plain_password, display_name, folder_slug, role,
        account_status, is_premium, usage_seconds, is_online, last_ip, device_type, os_browser,
        user_agent, ping_count, last_ping_at, created_at, last_login_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, 2400, 1, ?, ?, ?, 'Mozilla/5.0', 12, ?, ?, ?)
    `);

    for (const u of initialUsers) {
      stmt.run(
        u.id,
        u.email,
        u.fiba_email,
        hashPassword(u.pass),
        u.pass,
        u.name,
        u.slug,
        u.role,
        u.is_premium,
        u.ip,
        u.device,
        u.osBrowser,
        now,
        now,
        now
      );
      const row = db.prepare('SELECT * FROM users WHERE id = ?').get(u.id);
      upsertIpTrackerSession(row, u.ip, u.device, u.osBrowser, 'Mozilla/5.0 (' + u.osBrowser + ')');
    }
  } else {
    const existingUsers = db.prepare('SELECT * FROM users').all();
    for (const u of existingUsers) {
      const hasSession = db.prepare('SELECT id FROM ip_tracker_sessions WHERE user_id = ?').get(u.id);
      if (!hasSession) {
        upsertIpTrackerSession(u, u.last_ip || '49.36.128.11', u.device_type || 'Desktop', u.os_browser || 'Chrome · Windows 11', u.user_agent || 'Mozilla/5.0');
      }
    }
  }

  const apiCount = db.prepare('SELECT COUNT(*) as c FROM external_web_apis').get().c;
  if (apiCount === 0) {
    db.prepare(`
      INSERT INTO external_web_apis (id, name, provider_type, endpoint_url, api_key, auth_header, http_method, status, last_response_code, last_tested_at, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, 'connected', 200, ?, ?, ?)
    `).run(
      'webapi_flame_core',
      'Flame API Core Gateway',
      'Flame API',
      'https://api.flamecloud.dev/v1/bridge',
      'flm_api_live_9988776655',
      'X-Flame-Api-Key',
      'POST',
      now,
      now,
      now
    );
  }
}

seedDefaults();

module.exports = {
  db,
  DATA_DIR,
  USER_DATA_DIR,
  UPLOADS_DIR,
  hashPassword,
  verifyPassword,
  syncUserFolder,
  upsertIpTrackerSession
};
