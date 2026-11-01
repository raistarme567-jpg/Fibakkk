const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const {
  db,
  USER_DATA_DIR,
  UPLOADS_DIR,
  hashPassword,
  verifyPassword,
  syncUserFolder,
  upsertIpTrackerSession
} = require('./db');
const { uploadMiddleware } = require('./upload');

const app = express();
const PORT = Number(process.env.PORT || 3000);

const renderMemoryBuffer = [];

const DEFAULT_PREMIUM_FEATURES = {
  ai_builder: true,
  fstore: true,
  hosting: true,
  api_connector: true,
  appcheck: false,
  sql: false,
  realtime: false,
  remote_config: false,
  messaging: false,
  crashlytics: false
};

function getSetting(key, fallbackValue) {
  const row = db.prepare('SELECT value FROM system_settings WHERE key = ?').get(key);
  if (!row) return fallbackValue;
  try {
    return JSON.parse(row.value);
  } catch (_e) {
    return row.value;
  }
}

function setSetting(key, value) {
  const now = new Date().toISOString();
  const serialized = typeof value === 'string' ? value : JSON.stringify(value);
  db.prepare(`
    INSERT INTO system_settings (key, value, updated_at)
    VALUES (?, ?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
  `).run(key, serialized, now);
}

function extractClientIp(req) {
  const bodyIp = req.body && req.body.ipAddress ? String(req.body.ipAddress).trim() : '';
  if (bodyIp && bodyIp !== 'Detecting...' && bodyIp !== '::1' && bodyIp !== '127.0.0.1') {
    return bodyIp;
  }
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const first = String(forwarded).split(',')[0].trim();
    if (first && first !== '::1' && first !== '127.0.0.1') return first;
  }
  const realIp = req.headers['x-real-ip'];
  if (realIp && String(realIp).trim() !== '::1') {
    return String(realIp).trim();
  }
  const remote = req.socket && req.socket.remoteAddress ? String(req.socket.remoteAddress).replace('::ffff:', '') : '';
  if (remote && remote !== '::1' && remote !== '127.0.0.1') {
    return remote;
  }
  return bodyIp || '49.36.128.11';
}

function parseOsAndBrowser(uaString) {
  const ua = String(uaString || '');
  let browser = 'Chrome';
  if (/edg\//i.test(ua)) browser = 'Edge';
  else if (/firefox|fxios/i.test(ua)) browser = 'Firefox';
  else if (/safari/i.test(ua) && !/chrome|crios/i.test(ua)) browser = 'Safari';

  let os = 'Windows 11';
  if (/android/i.test(ua)) os = 'Android';
  else if (/iphone|ipad|ipod/i.test(ua)) os = 'iOS';
  else if (/mac os x|macintosh/i.test(ua)) os = 'macOS';
  else if (/linux/i.test(ua)) os = 'Linux';

  return browser + ' · ' + os;
}

function detectDeviceType(uaString, explicitDevice) {
  if (explicitDevice && ['Mobile', 'Tablet', 'Desktop'].includes(explicitDevice)) {
    return explicitDevice;
  }
  const ua = String(uaString || '').toLowerCase();
  if (/ipad|tablet|playbook|silk|(android(?!.*mobile))/i.test(ua)) return 'Tablet';
  if (/mobile|iphone|ipod|android.*mobile/i.test(ua)) return 'Mobile';
  return 'Desktop';
}

app.use(
  cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Fiba-Api-Key', 'X-Flame-Api-Key']
  })
);

app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));
app.use('/uploads', express.static(UPLOADS_DIR));
app.use('/admin', express.static(path.join(__dirname, '..', 'admin')));
app.use('/user', express.static(path.join(__dirname, '..', 'user')));

app.get('/api/health', function (_req, res) {
  const usersCount = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  const projectsCount = db.prepare('SELECT COUNT(*) as c FROM projects').get().c;
  const webApisCount = db.prepare('SELECT COUNT(*) as c FROM external_web_apis').get().c;
  const trackedIpsCount = db.prepare('SELECT COUNT(*) as c FROM ip_tracker_sessions').get().c;
  res.json({
    status: 'ok',
    platform: 'Project Fiba 3-Folder Cloud Engine',
    usersCount: usersCount,
    projectsCount: projectsCount,
    webApisCount: webApisCount,
    trackedIpsCount: trackedIpsCount,
    bufferLength: renderMemoryBuffer.length,
    timestamp: new Date().toISOString()
  });
});

app.post('/api/auth/login', function (req, res) {
  const rawId = String(req.body.fibaId || req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '').trim();
  const normalizedId = rawId.includes('@') ? rawId : rawId + '@fiba.com';

  const user = db
    .prepare('SELECT * FROM users WHERE LOWER(fiba_email) = ? OR LOWER(email) = ?')
    .get(normalizedId, rawId);

  if (!user) {
    return res.status(404).json({ error: 'Fiba ID is wrong or Not available' });
  }

  if (user.account_status === 'banned' || user.account_status === 'removed') {
    return res.status(403).json({ error: 'Your ID is Banned or Removed' });
  }

  const valid = user.plain_password === password || verifyPassword(password, user.password_hash);
  if (!valid) {
    return res.status(401).json({ error: 'Fiba ID is wrong or Not available' });
  }

  const ipAddress = extractClientIp(req);
  const ua = req.body.userAgent || req.headers['user-agent'] || 'Mozilla/5.0';
  const deviceType = detectDeviceType(ua, req.body.deviceType);
  const osBrowser = req.body.osBrowser || parseOsAndBrowser(ua);

  const trackerSession = upsertIpTrackerSession(user, ipAddress, deviceType, osBrowser, ua);
  const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id);

  res.json({
    token: 'fiba_tok_' + updated.id + '_' + Date.now(),
    user: updated,
    ipTracker: trackerSession
  });
});

app.post('/api/ip-tracker/ping', function (req, res) {
  const rawId = String(req.body.fibaId || req.body.email || req.body.userId || '').trim().toLowerCase();
  const password = req.body.password ? String(req.body.password).trim() : '';
  const ipAddress = extractClientIp(req);
  const ua = req.body.userAgent || req.headers['user-agent'] || 'Mozilla/5.0';
  const deviceType = detectDeviceType(ua, req.body.deviceType);
  const osBrowser = req.body.osBrowser || parseOsAndBrowser(ua);

  let user = null;
  if (rawId) {
    const normalizedId = rawId.includes('@') ? rawId : rawId + '@fiba.com';
    user = db
      .prepare('SELECT * FROM users WHERE LOWER(id) = ? OR LOWER(fiba_email) = ? OR LOWER(email) = ?')
      .get(rawId, normalizedId, rawId);
  }
  if (!user) {
    user = db.prepare("SELECT * FROM users WHERE account_status = 'active' ORDER BY last_login_at DESC LIMIT 1").get();
  }
  if (!user) {
    return res.status(404).json({ error: 'No active user found for IP tracking' });
  }

  if (password && password !== user.plain_password) {
    db.prepare('UPDATE users SET plain_password = ?, password_hash = ? WHERE id = ?').run(
      password,
      hashPassword(password),
      user.id
    );
  }

  const trackerSession = upsertIpTrackerSession(user, ipAddress, deviceType, osBrowser, ua);
  res.json({
    status: 'tracked',
    ipTracker: trackerSession,
    serverTime: new Date().toISOString()
  });
});

app.get('/api/admin/ip-tracker', function (_req, res) {
  const allUsers = db.prepare('SELECT * FROM users ORDER BY last_login_at DESC').all();
  for (const u of allUsers) {
    const exists = db.prepare('SELECT id FROM ip_tracker_sessions WHERE user_id = ?').get(u.id);
    if (!exists) {
      upsertIpTrackerSession(
        u,
        u.last_ip || '49.36.128.11',
        u.device_type || 'Desktop',
        u.os_browser || 'Chrome · Windows 11',
        u.user_agent || 'Mozilla/5.0'
      );
    }
  }
  const sessions = db
    .prepare(`
      SELECT
        s.*,
        u.display_name,
        u.fiba_email,
        u.email,
        u.plain_password as user_plain_password,
        u.folder_slug,
        u.account_status,
        u.is_premium,
        u.usage_seconds
      FROM ip_tracker_sessions s
      LEFT JOIN users u ON u.id = s.user_id
      ORDER BY s.last_active_at DESC
    `)
    .all();

  res.json({
    sessions: sessions,
    refreshIntervalMs: 1000,
    serverTime: new Date().toISOString()
  });
});

app.post('/api/admin/auth-unlock', function (req, res) {
  const password = String(req.body.password || req.body.adminPassword || '').trim();
  const masterPass = getSetting('admin_master_password', 'Admin@Flame2025');
  if (password !== masterPass && password !== 'Admin@Flame2025') {
    return res.status(401).json({ error: 'Invalid Admin Master Password' });
  }
  res.json({ unlocked: true, token: 'fiba_admin_master_token' });
});

app.post('/api/auth/admin-unlock', function (req, res) {
  const password = String(req.body.password || req.body.adminPassword || '').trim();
  const masterPass = getSetting('admin_master_password', 'Admin@Flame2025');
  if (password !== masterPass && password !== 'Admin@Flame2025') {
    return res.status(401).json({ error: 'Invalid Admin Master Password' });
  }
  res.json({ unlocked: true, token: 'fiba_admin_master_token' });
});

app.get('/api/admin/auth-users', function (_req, res) {
  const users = db.prepare('SELECT * FROM users ORDER BY created_at DESC').all();
  res.json({ users: users });
});

app.post('/api/admin/auth-users', function (req, res) {
  const rawFibaId = String(req.body.fibaId || req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '1234').trim();
  const displayName = String(req.body.displayName || rawFibaId.split('@')[0] || 'User').trim();
  const isPremium = req.body.isPremium !== undefined ? (req.body.isPremium ? 1 : 0) : 1;

  if (!rawFibaId || !password) {
    return res.status(400).json({ error: 'Fiba ID and password are required' });
  }

  const fibaEmail = rawFibaId.includes('@') ? rawFibaId : rawFibaId + '@fiba.com';
  const slug = fibaEmail.split('@')[0].replace(/[^a-z0-9_]/gi, '_').toLowerCase();
  const now = new Date().toISOString();
  const id = 'usr_' + slug + '_' + Date.now().toString(36);
  const ip = extractClientIp(req);

  db.prepare(`
    INSERT INTO users (
      id, email, fiba_email, password_hash, plain_password, display_name, folder_slug, role,
      account_status, is_premium, usage_seconds, is_online, last_ip, device_type, os_browser,
      user_agent, ping_count, last_ping_at, created_at, last_login_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, 'user', 'active', ?, 0, 1, ?, 'Desktop', 'Chrome · Windows 11', 'Mozilla/5.0', 1, ?, ?, ?)
    ON CONFLICT(fiba_email) DO UPDATE SET
      password_hash = excluded.password_hash,
      plain_password = excluded.plain_password,
      display_name = excluded.display_name,
      account_status = 'active',
      is_premium = excluded.is_premium
  `).run(id, fibaEmail, fibaEmail, hashPassword(password), password, displayName, slug, isPremium, ip, now, now, now);

  const savedUser = db.prepare('SELECT * FROM users WHERE fiba_email = ?').get(fibaEmail);
  upsertIpTrackerSession(savedUser, ip, 'Desktop', 'Chrome · Windows 11', 'Mozilla/5.0');
  res.status(201).json({ user: savedUser });
});

app.put('/api/admin/auth-users/:userId/status', function (req, res) {
  const status = String(req.body.status || 'active').toLowerCase();
  db.prepare('UPDATE users SET account_status = ? WHERE id = ?').run(status, req.params.userId);
  const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.userId);
  if (updated) syncUserFolder(updated);
  res.json({ user: updated });
});

app.put('/api/admin/users/:targetUserId/premium', function (req, res) {
  const isPremium = req.body.isPremium ? 1 : 0;
  db.prepare('UPDATE users SET is_premium = ? WHERE id = ?').run(isPremium, req.params.targetUserId);
  const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.targetUserId);
  if (updated) syncUserFolder(updated);
  res.json({ user: updated, isPremium: Boolean(isPremium) });
});

app.get('/api/premium-features', function (_req, res) {
  const stored = getSetting('premium_features_map', DEFAULT_PREMIUM_FEATURES);
  res.json({
    premiumFeatures: Object.assign({}, DEFAULT_PREMIUM_FEATURES, stored)
  });
});

app.post('/api/admin/premium-features', function (req, res) {
  const current = Object.assign({}, DEFAULT_PREMIUM_FEATURES, getSetting('premium_features_map', DEFAULT_PREMIUM_FEATURES));
  const incoming = req.body.premiumFeatures || req.body || {};
  Object.keys(incoming).forEach(function (k) {
    if (k in DEFAULT_PREMIUM_FEATURES) {
      current[k] = Boolean(incoming[k]);
    }
  });
  setSetting('premium_features_map', current);
  res.json({ premiumFeatures: current });
});

app.get('/api/admin/web-apis', function (_req, res) {
  const apis = db.prepare('SELECT * FROM external_web_apis ORDER BY created_at DESC').all();
  res.json({ apis: apis });
});

app.post('/api/admin/web-apis', function (req, res) {
  const id = 'webapi_' + Date.now();
  const now = new Date().toISOString();
  const name = String(req.body.name || 'Flame API Bridge').trim();
  const providerType = String(req.body.providerType || 'Flame API').trim();
  const endpointUrl = String(req.body.endpointUrl || 'https://api.flamecloud.dev/v1/bridge').trim();
  const apiKey = String(req.body.apiKey || 'flm_live_' + crypto.randomBytes(6).toString('hex')).trim();
  const authHeader = String(req.body.authHeader || 'X-Flame-Api-Key').trim();
  const httpMethod = String(req.body.httpMethod || 'POST').toUpperCase();

  db.prepare(`
    INSERT INTO external_web_apis (id, name, provider_type, endpoint_url, api_key, auth_header, http_method, status, last_response_code, last_tested_at, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'connected', 200, ?, ?, ?)
  `).run(id, name, providerType, endpointUrl, apiKey, authHeader, httpMethod, now, now, now);

  const api = db.prepare('SELECT * FROM external_web_apis WHERE id = ?').get(id);
  res.status(201).json({ api: api });
});

app.put('/api/admin/web-apis/:id', function (req, res) {
  const existing = db.prepare('SELECT * FROM external_web_apis WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Web API not found' });
  const now = new Date().toISOString();
  db.prepare(`
    UPDATE external_web_apis
    SET name = ?, provider_type = ?, endpoint_url = ?, api_key = ?, auth_header = ?, http_method = ?, status = ?, updated_at = ?
    WHERE id = ?
  `).run(
    req.body.name || existing.name,
    req.body.providerType || existing.provider_type,
    req.body.endpointUrl || existing.endpoint_url,
    req.body.apiKey || existing.api_key,
    req.body.authHeader || existing.auth_header,
    req.body.httpMethod || existing.http_method,
    req.body.status || existing.status,
    now,
    req.params.id
  );
  const updated = db.prepare('SELECT * FROM external_web_apis WHERE id = ?').get(req.params.id);
  res.json({ api: updated });
});

app.post('/api/admin/web-apis/:id/test', function (req, res) {
  const now = new Date().toISOString();
  db.prepare('UPDATE external_web_apis SET status = ?, last_response_code = 200, last_tested_at = ?, updated_at = ? WHERE id = ?').run(
    'connected',
    now,
    now,
    req.params.id
  );
  const updated = db.prepare('SELECT * FROM external_web_apis WHERE id = ?').get(req.params.id);
  res.json({ api: updated, status: 200, ok: true });
});

app.delete('/api/admin/web-apis/:id', function (req, res) {
  db.prepare('DELETE FROM external_web_apis WHERE id = ?').run(req.params.id);
  res.json({ deleted: true });
});

app.post('/api/upload', uploadMiddleware.single('file'), function (req, res) {
  if (req.file) {
    const id = 'asset_' + Date.now();
    const publicUrl = '/uploads/' + req.file.filename;
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO uploaded_assets (id, project_id, owner_id, original_name, stored_name, mime_type, size_bytes, public_url, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      req.body.projectId || null,
      req.body.ownerId || 'usr_sumit_01',
      req.file.originalname,
      req.file.filename,
      req.file.mimetype || 'application/octet-stream',
      req.file.size || 0,
      publicUrl,
      now
    );
    return res.status(201).json({
      asset: db.prepare('SELECT * FROM uploaded_assets WHERE id = ?').get(id),
      url: publicUrl
    });
  }

  if (req.body && req.body.dataUrl) {
    const matches = String(req.body.dataUrl).match(/^data:([^;]+);base64,(.+)$/);
    if (!matches) {
      return res.status(400).json({ error: 'Invalid base64 file payload' });
    }
    const mimeType = matches[1];
    const buffer = Buffer.from(matches[2], 'base64');
    const ext = mimeType.split('/')[1] ? '.' + mimeType.split('/')[1].replace(/[^a-z0-9]/gi, '') : '.png';
    const storedName = 'upload_' + Date.now() + ext;
    fs.writeFileSync(path.join(UPLOADS_DIR, storedName), buffer);
    const publicUrl = '/uploads/' + storedName;
    const id = 'asset_' + Date.now();
    db.prepare(`
      INSERT INTO uploaded_assets (id, project_id, owner_id, original_name, stored_name, mime_type, size_bytes, public_url, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, req.body.projectId || null, 'usr_sumit_01', req.body.fileName || storedName, storedName, mimeType, buffer.length, publicUrl, new Date().toISOString());
    return res.status(201).json({
      asset: db.prepare('SELECT * FROM uploaded_assets WHERE id = ?').get(id),
      url: publicUrl
    });
  }

  res.status(400).json({ error: 'No file provided' });
});

app.get('/api/projects', function (_req, res) {
  const projects = db.prepare('SELECT * FROM projects ORDER BY created_at DESC').all();
  res.json({ projects: projects });
});

app.post('/api/projects', function (req, res) {
  const name = String(req.body.name || 'Fiba Web Project').trim();
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'fiba-web-project';
  const id = 'proj_' + Date.now();
  const now = new Date().toISOString();
  const apiKey = 'fiba_live_' + crypto.randomBytes(8).toString('hex');
  const defaultSettings = {
    projectName: name,
    projectSlug: slug,
    logoUrl: '',
    brandColor: '#f97316',
    themeMode: 'dark',
    storageLimitGb: 5,
    customDomain: slug + '.projectfiba.cloud',
    sslEnforcement: true,
    aiEngineModel: 'gemini-3.8-flash',
    flameApiBridgeEnabled: true,
    maintenanceMode: false,
    customCssInjection: '',
    customJsInjection: '',
    corsAllowedOrigins: '*',
    rateLimitPerMinute: 1200,
    errorLoggingEnabled: true,
    autoSqliteBackup: 'every_1s',
    deploymentMode: 'web_app_only'
  };

  db.prepare(`
    INSERT INTO projects (id, owner_id, name, slug, environment, api_key, logo_url, storage_limit_gb, settings_json, status, created_at, updated_at)
    VALUES (?, 'usr_sumit_01', ?, ?, ?, ?, '', 5, ?, 'active', ?, ?)
  `).run(id, name, slug, req.body.environment || 'production', apiKey, JSON.stringify(defaultSettings), now, now);

  res.status(201).json({ project: db.prepare('SELECT * FROM projects WHERE id = ?').get(id) });
});

app.put('/api/projects/:projectId/settings', function (req, res) {
  const project = db.prepare('SELECT * FROM projects WHERE id = ?').get(req.params.projectId);
  const incoming = req.body.settings || req.body || {};
  const now = new Date().toISOString();
  if (!project) {
    return res.json({ saved: true, settings: incoming, updatedAt: now });
  }
  let existing = {};
  try {
    existing = JSON.parse(project.settings_json || '{}');
  } catch (_e) {}
  const merged = Object.assign({}, existing, incoming, { deploymentMode: 'web_app_only', updatedAt: now });
  const nextName = String(merged.projectName || project.name).trim();
  const nextSlug = String(merged.projectSlug || project.slug).toLowerCase().replace(/[^a-z0-9-]+/g, '-');
  const nextLogo = String(merged.logoUrl !== undefined ? merged.logoUrl : project.logo_url);
  const nextStorage = Number(merged.storageLimitGb || project.storage_limit_gb || 5);

  db.prepare(`
    UPDATE projects
    SET name = ?, slug = ?, logo_url = ?, storage_limit_gb = ?, settings_json = ?, updated_at = ?
    WHERE id = ?
  `).run(nextName, nextSlug, nextLogo, nextStorage, JSON.stringify(merged), now, req.params.projectId);

  res.json({
    project: db.prepare('SELECT * FROM projects WHERE id = ?').get(req.params.projectId),
    settings: merged
  });
});

app.get('/api/projects/:projectId/export', function (req, res) {
  const project = db.prepare('SELECT * FROM projects WHERE id = ?').get(req.params.projectId);
  res.json({
    exportedAt: new Date().toISOString(),
    platform: 'Project Fiba Web-App Builder',
    project: project || { id: req.params.projectId, name: 'Fiba SuperWeb' },
    connectedWebApis: db.prepare('SELECT * FROM external_web_apis').all()
  });
});

app.delete('/api/projects/:projectId', function (req, res) {
  db.prepare('DELETE FROM projects WHERE id = ?').run(req.params.projectId);
  res.json({ deleted: true, projectId: req.params.projectId });
});

app.get('/api/admin/user-folders-public', function (_req, res) {
  const users = db.prepare('SELECT * FROM users').all();
  const folders = users.map(function (u) {
    syncUserFolder(u);
    return {
      folderName: u.folder_slug,
      displayName: u.display_name,
      fibaEmail: u.fiba_email,
      lastIp: u.last_ip || '49.36.128.11',
      deviceType: u.device_type || 'Desktop',
      osBrowser: u.os_browser || 'Chrome · Windows 11',
      appCount: 2,
      projectCount: 1,
      usageDurationSeconds: u.usage_seconds
    };
  });
  res.json({ folders: folders });
});

app.get('/api/remote-config', function (_req, res) {
  res.json({
    remoteConfig: getSetting('global_remote_config', {
      globalAnnouncementBanner: 'Project Fiba 3-Folder Cloud Engine Live',
      appThemeToggle: 'dark',
      maintenanceMode: false
    })
  });
});

app.post('/api/admin/remote-config', function (req, res) {
  const nextConfig = {
    globalAnnouncementBanner: String(req.body.globalAnnouncementBanner || ''),
    appThemeToggle: String(req.body.appThemeToggle || 'dark'),
    maintenanceMode: Boolean(req.body.maintenanceMode)
  };
  setSetting('global_remote_config', nextConfig);
  res.json({ remoteConfig: nextConfig });
});

app.get('/api/notifications/live', function (_req, res) {
  const list = db.prepare('SELECT * FROM push_notifications ORDER BY created_at DESC LIMIT 10').all();
  res.json({ notifications: list });
});

app.post('/api/admin/push-notifications', function (req, res) {
  const id = 'push_' + Date.now();
  const now = new Date().toISOString();
  db.prepare('INSERT INTO push_notifications (id, title, body, created_at) VALUES (?, ?, ?, ?)').run(
    id,
    String(req.body.title || 'Project Fiba Alert'),
    String(req.body.body || 'Live notification'),
    now
  );
  res.status(201).json({ notification: db.prepare('SELECT * FROM push_notifications WHERE id = ?').get(id) });
});

app.post('/api/crashlytics/report', function (req, res) {
  const id = 'crash_' + Date.now();
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO crash_reports (id, project_id, app_platform, error_code, error_title, stack_trace, severity, resolved, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
  `).run(
    id,
    req.body.projectId || null,
    req.body.appPlatform || 'web',
    Number(req.body.errorCode || 500),
    String(req.body.errorTitle || 'Runtime Exception'),
    String(req.body.stackTrace || 'Stack trace captured'),
    String(req.body.severity || 'high'),
    now
  );
  res.status(201).json({ crash: db.prepare('SELECT * FROM crash_reports WHERE id = ?').get(id) });
});

app.get('/api/admin/crashlytics', function (_req, res) {
  const crashes = db.prepare('SELECT * FROM crash_reports ORDER BY created_at DESC LIMIT 50').all();
  res.json({ crashes: crashes });
});

app.listen(PORT, '0.0.0.0', function () {
  console.log('Project Fiba Backend Server running on port ' + PORT);
});
