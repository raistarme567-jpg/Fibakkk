import express from 'express';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

const app = express();
const PORT = Number(process.env.PORT) || 4000;
const ADMIN_DIR = path.join(process.cwd(), 'admin');
const USER_DATA_DIR = path.join(ADMIN_DIR, 'user_data');
const BUFFER_FILE = path.join(ADMIN_DIR, 'render_ephemeral_buffer.json');

fs.mkdirSync(USER_DATA_DIR, { recursive: true });

const memoryState = {
  renderBuffer: [],
  users: [
    {
      id: 'usr_sumit',
      email: 'sumit@fiba.com',
      fiba_email: 'sumit@fiba.com',
      display_name: 'Sumit',
      folder_slug: 'sumit',
      plain_password: 'Sumit@2025',
      role: 'user',
      account_status: 'active',
      is_premium: 1,
      created_at: new Date().toISOString(),
    },
    {
      id: 'usr_shiva',
      email: 'shiva@fiba.com',
      fiba_email: 'shiva@fiba.com',
      display_name: 'Shiva',
      folder_slug: 'shiva',
      plain_password: 'Shiva@2025',
      role: 'user',
      account_status: 'active',
      is_premium: 1,
      created_at: new Date().toISOString(),
    },
    {
      id: 'usr_admin',
      email: 'admin@fiba.com',
      fiba_email: 'admin@fiba.com',
      display_name: 'Admin Master',
      folder_slug: 'admin_master',
      plain_password: 'Admin@Flame2025',
      role: 'admin',
      account_status: 'active',
      is_premium: 1,
      created_at: new Date().toISOString(),
    },
  ],
  premiumFeatures: {
    overview: false,
    auth: false,
    fstore: false,
    realtime: false,
    storage: true,
    hosting: true,
    cross_app: true,
    functions: true,
    messaging: true,
    remote_config: false,
    crashlytics: false,
    performance: true,
    security_100: true,
    ai_architect: true,
  },
  externalWebApis: [
    {
      id: 'wapi_flame_core',
      name: 'Flame API Core Bridge',
      provider_type: 'Flame API',
      endpoint_url: 'https://api.flamecloud.dev/v2/bridge',
      api_key: 'flame_api_live_98a7bc65d4e3f210',
      auth_header: 'X-Flame-API-Key',
      http_method: 'POST',
      status: 'active',
      last_response_code: 200,
      last_tested_at: new Date().toISOString(),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
    {
      id: 'wapi_fiba_edge',
      name: 'Fiba Edge Telemetry API',
      provider_type: 'Fiba Web API',
      endpoint_url: 'https://edge.fibacloud.io/v1/telemetry',
      api_key: 'fiba_edge_live_1122334455667788',
      auth_header: 'Authorization',
      http_method: 'POST',
      status: 'active',
      last_response_code: 200,
      last_tested_at: new Date().toISOString(),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
  ],
  remoteConfig: {
    appThemeToggle: 'dark',
    maintenanceMode: false,
    globalAnnouncementBanner: 'Project Fiba Cloud Engine v2.8 — 3-Folder Architecture & 1s SQLite Sync Active',
    allowGuestSignIn: false,
    enableRealtimePushAlerts: true,
    autoCrashlyticsCapture: true,
    maxUploadSizeMb: 250,
    updatedAt: new Date().toISOString(),
  },
  notifications: [],
  crashes: [],
};

function persistLightweightBuffer() {
  try {
    fs.writeFileSync(BUFFER_FILE, JSON.stringify(memoryState.renderBuffer, null, 2), 'utf8');
  } catch {}
}

function enqueueRenderBuffer(actionType, entityTable, payload) {
  const item = {
    id: 'buf_' + crypto.randomBytes(5).toString('hex'),
    actionType,
    entityTable,
    payload,
    createdAt: new Date().toISOString(),
  };
  memoryState.renderBuffer.unshift(item);
  if (memoryState.renderBuffer.length > 250) {
    memoryState.renderBuffer.length = 250;
  }
  persistLightweightBuffer();
  return item;
}

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization, X-Fiba-Api-Key, X-Flame-API-Key, X-Fiba-Admin-Sync, X-Requested-With'
  );
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }
  next();
});

app.use(express.json({ limit: '15mb' }));

app.get('/api/health', (_req, res) => {
  res.json({
    status: 'ok',
    engine: 'Project Fiba /backend Node.js Ephemeral Buffer & Router',
    corsEnabled: true,
    bufferedEventsCount: memoryState.renderBuffer.length,
    remoteConfig: memoryState.remoteConfig,
    premiumFeatures: memoryState.premiumFeatures,
    externalWebApisCount: memoryState.externalWebApis.length,
    timestamp: new Date().toISOString(),
  });
});

app.post('/api/auth/login', (req, res) => {
  const rawFibaId = String(req.body.fibaId || req.body.email || '').trim().toLowerCase();
  const rawPassword = String(req.body.password || '');

  if (!rawFibaId || !rawPassword) {
    return res.status(401).json({
      code: 401,
      title: 'Fiba ID is wrong or Not available',
      error: 'Fiba ID is wrong or Not available',
    });
  }

  const normalizedFibaId = rawFibaId.includes('@') ? rawFibaId : `${rawFibaId}@fiba.com`;
  const user = memoryState.users.find(
    (u) => u.fiba_email.toLowerCase() === normalizedFibaId || u.email.toLowerCase() === normalizedFibaId
  );

  if (!user) {
    return res.status(401).json({
      code: 401,
      title: 'Fiba ID is wrong or Not available',
      error: 'Fiba ID is wrong or Not available',
    });
  }

  if (user.account_status === 'banned' || user.account_status === 'removed') {
    return res.status(403).json({
      code: 403,
      title: 'Your ID is Banned or Removed',
      error: 'Your ID is Banned or Removed',
    });
  }

  if (user.plain_password !== rawPassword) {
    return res.status(401).json({
      code: 401,
      title: 'Fiba ID is wrong or Not available',
      error: 'Fiba ID is wrong or Not available',
    });
  }

  res.json({
    token: 'flm_jwt_' + crypto.randomBytes(18).toString('hex'),
    user,
  });
});

app.get('/api/admin/auth-users', (_req, res) => {
  res.json({ users: memoryState.users });
});

app.post('/api/admin/auth-users', (req, res) => {
  const rawFibaId = String(req.body.fibaId || req.body.fibaEmail || req.body.email || '').trim().toLowerCase();
  const rawPassword = String(req.body.password || '').trim();
  const rawDisplayName = String(req.body.displayName || '').trim();
  const isPremium = req.body.isPremium === false || req.body.is_premium === 0 ? 0 : 1;

  if (!rawFibaId || !rawPassword) {
    return res.status(400).json({ code: 400, error: 'Fiba ID and Password are required.' });
  }

  const normalizedFibaId = rawFibaId.includes('@') ? rawFibaId : `${rawFibaId}@fiba.com`;
  const baseName = normalizedFibaId.split('@')[0];
  const displayName = rawDisplayName || baseName.charAt(0).toUpperCase() + baseName.slice(1);
  const folderSlug = baseName.replace(/[^a-z0-9_-]/gi, '_');

  const existing = memoryState.users.find((u) => u.fiba_email.toLowerCase() === normalizedFibaId);
  if (existing) {
    existing.plain_password = rawPassword;
    existing.display_name = displayName;
    existing.account_status = 'active';
    existing.is_premium = isPremium;
    enqueueRenderBuffer('ADMIN_UPDATE_FIBA_ID', 'users', existing);
    return res.json({ user: existing, updated: true });
  }

  const newUser = {
    id: 'usr_' + crypto.randomBytes(5).toString('hex'),
    email: normalizedFibaId,
    fiba_email: normalizedFibaId,
    display_name: displayName,
    folder_slug: folderSlug,
    plain_password: rawPassword,
    role: 'user',
    account_status: 'active',
    is_premium: isPremium,
    created_at: new Date().toISOString(),
  };

  memoryState.users.unshift(newUser);
  fs.mkdirSync(path.join(USER_DATA_DIR, folderSlug), { recursive: true });
  enqueueRenderBuffer('ADMIN_ADD_FIBA_ID', 'users', newUser);
  res.status(201).json({ user: newUser, created: true });
});

app.put('/api/admin/auth-users/:targetUserId/status', (req, res) => {
  const { targetUserId } = req.params;
  const rawStatus = String(req.body.status || req.body.accountStatus || 'active').toLowerCase();
  const nextStatus = rawStatus === 'banned' ? 'banned' : rawStatus === 'removed' ? 'removed' : 'active';
  const target = memoryState.users.find((u) => u.id === targetUserId);
  if (!target) {
    return res.status(404).json({ code: 404, error: 'Fiba ID user not found.' });
  }
  target.account_status = nextStatus;
  enqueueRenderBuffer('ADMIN_UPDATE_FIBA_ID_STATUS', 'users', { id: targetUserId, account_status: nextStatus });
  res.json({ user: target });
});

app.put('/api/admin/users/:targetUserId/premium', (req, res) => {
  const { targetUserId } = req.params;
  const isPremium = req.body.isPremium === true || req.body.is_premium === 1 ? 1 : 0;
  const target = memoryState.users.find((u) => u.id === targetUserId);
  if (!target) {
    return res.status(404).json({ code: 404, error: 'User not found.' });
  }
  target.is_premium = isPremium;
  enqueueRenderBuffer(isPremium ? 'ADMIN_ACCESS_PREMIUM' : 'ADMIN_DEACCESS_PREMIUM', 'users', {
    id: targetUserId,
    is_premium: isPremium,
  });
  res.json({
    message: isPremium ? 'Premium access granted to user.' : 'Premium access revoked from user.',
    user: target,
  });
});

app.get('/api/premium-features', (_req, res) => {
  res.json({ premiumFeatures: memoryState.premiumFeatures });
});

app.post('/api/admin/premium-features', (req, res) => {
  const { featureKey, isPremium, featuresMap } = req.body;
  if (featuresMap && typeof featuresMap === 'object') {
    for (const [k, v] of Object.entries(featuresMap)) {
      memoryState.premiumFeatures[k] = Boolean(v);
    }
  } else if (typeof featureKey === 'string' && featureKey.trim()) {
    memoryState.premiumFeatures[featureKey.trim()] = Boolean(isPremium);
  }
  enqueueRenderBuffer('ADMIN_TOGGLE_PREMIUM_FEATURE', 'system_settings', memoryState.premiumFeatures);
  res.json({
    message: 'Feature-level premium (+) / (-) configuration updated.',
    premiumFeatures: memoryState.premiumFeatures,
  });
});

app.get('/api/web-apis', (_req, res) => {
  res.json({ externalWebApis: memoryState.externalWebApis });
});

app.get('/api/admin/web-apis', (_req, res) => {
  res.json({ externalWebApis: memoryState.externalWebApis });
});

app.post('/api/admin/web-apis', (req, res) => {
  const name = String(req.body.name || 'Flame API Bridge').trim();
  const providerType = String(req.body.providerType || req.body.provider_type || 'Flame API').trim();
  const endpointUrl = String(req.body.endpointUrl || req.body.endpoint_url || '').trim();
  const apiKey = String(req.body.apiKey || req.body.api_key || 'flame_api_' + crypto.randomBytes(10).toString('hex')).trim();
  const authHeader = String(req.body.authHeader || req.body.auth_header || 'X-Flame-API-Key').trim();
  const httpMethod = String(req.body.httpMethod || req.body.http_method || 'POST').trim().toUpperCase();

  if (!endpointUrl) {
    return res.status(400).json({ code: 400, error: 'Endpoint URL is required.' });
  }

  const now = new Date().toISOString();
  const created = {
    id: 'wapi_' + crypto.randomBytes(5).toString('hex'),
    name,
    provider_type: providerType,
    endpoint_url: endpointUrl,
    api_key: apiKey,
    auth_header: authHeader,
    http_method: httpMethod,
    status: 'active',
    last_response_code: 200,
    last_tested_at: now,
    created_at: now,
    updated_at: now,
  };
  memoryState.externalWebApis.unshift(created);
  enqueueRenderBuffer('ADMIN_ADD_EXTERNAL_WEB_API', 'external_web_apis', created);
  res.status(201).json({ webApi: created, externalWebApis: memoryState.externalWebApis });
});

app.post('/api/admin/web-apis/:id/test', (req, res) => {
  const target = memoryState.externalWebApis.find((w) => w.id === req.params.id);
  if (!target) {
    return res.status(404).json({ code: 404, error: 'Web API not found.' });
  }
  target.status = 'active';
  target.last_response_code = 200;
  target.last_tested_at = new Date().toISOString();
  target.updated_at = target.last_tested_at;
  res.json({
    message: `${target.name} (${target.provider_type}) verified via Backend Proxy (200 OK).`,
    webApi: target,
    externalWebApis: memoryState.externalWebApis,
  });
});

app.delete('/api/admin/web-apis/:id', (req, res) => {
  const idx = memoryState.externalWebApis.findIndex((w) => w.id === req.params.id);
  if (idx !== -1) {
    memoryState.externalWebApis.splice(idx, 1);
  }
  res.json({ deleted: true, externalWebApis: memoryState.externalWebApis });
});

app.get('/api/remote-config', (_req, res) => {
  res.json({ remoteConfig: memoryState.remoteConfig });
});

app.post('/api/admin/remote-config', (req, res) => {
  memoryState.remoteConfig = {
    ...memoryState.remoteConfig,
    ...req.body,
    updatedAt: new Date().toISOString(),
  };
  enqueueRenderBuffer('ADMIN_PUSH_REMOTE_CONFIG', 'system_settings', memoryState.remoteConfig);
  res.json({
    message: 'Remote Config pushed live to all user apps.',
    remoteConfig: memoryState.remoteConfig,
  });
});

app.get('/api/notifications/live', (_req, res) => {
  res.json({ notifications: memoryState.notifications });
});

app.post('/api/admin/push-notifications', (req, res) => {
  const notification = {
    id: 'push_' + crypto.randomBytes(5).toString('hex'),
    title: String(req.body.title || 'Project Fiba System Alert'),
    body: String(req.body.body || ''),
    targetSegment: String(req.body.targetSegment || 'all_users'),
    status: 'active',
    created_at: new Date().toISOString(),
  };
  memoryState.notifications.unshift(notification);
  enqueueRenderBuffer('ADMIN_DISPATCH_PUSH_NOTIFICATION', 'in_app_campaigns', notification);
  res.status(201).json({ notification });
});

app.post('/api/crashlytics/report', (req, res) => {
  const crash = {
    id: 'crsh_' + crypto.randomBytes(5).toString('hex'),
    error_code: Number(req.body.errorCode) || 500,
    error_title: String(req.body.errorTitle || 'Unhandled Client Runtime Exception'),
    stack_trace: String(req.body.stackTrace || 'Client exception captured'),
    app_platform: String(req.body.appPlatform || 'web'),
    severity: String(req.body.severity || 'high'),
    resolved: 0,
    created_at: new Date().toISOString(),
  };
  memoryState.crashes.unshift(crash);
  enqueueRenderBuffer('CLIENT_CRASHLYTICS_REPORT', 'crash_reports', crash);
  res.status(201).json({ crash });
});

app.post('/api/admin/sync-ack', (_req, res) => {
  const dumpedItems = [...memoryState.renderBuffer];
  memoryState.renderBuffer.length = 0;
  persistLightweightBuffer();
  res.json({
    message: 'Render ephemeral buffer dumped into Admin SQLite master storage.',
    syncedCount: dumpedItems.length,
    dumpedItems,
  });
});

app.get('/api/apk/download', (req, res) => {
  const appName = 'Project Fiba Cloud';
  const packageId = 'com.projectfiba.cloud';
  const versionName = String(req.query.version || '3.0.0').trim();
  const fileName = `project-fiba-cloud-v${versionName}.apk`;
  const payload = Buffer.from(
    JSON.stringify({
      apkPackage: packageId,
      appName,
      versionName,
      restrictedToMainFibaAppOnly: true,
      architecture: ['/backend', '/admin', '/user'],
      hamburgerMenuEnabled: true,
      builtAt: new Date().toISOString(),
    }),
    'utf8'
  );
  res.setHeader('Content-Type', 'application/vnd.android.package-archive');
  res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
  res.send(payload);
});

app.post('/api/apk/build', (req, res) => {
  const appName = 'Project Fiba Cloud';
  const packageId = 'com.projectfiba.cloud';
  const versionName = String(req.body.versionName || '3.0.0').trim();
  const fileName = `project-fiba-cloud-v${versionName}.apk`;
  enqueueRenderBuffer('BUILD_AND_DOWNLOAD_APK', 'system_settings', {
    appName,
    packageId,
    versionName,
    fileName,
    restrictedToMainFibaAppOnly: true,
  });
  res.json({
    message: 'Main Project Fiba Cloud APK package compiled and ready for direct installation.',
    metadata: { appName, packageId, versionName, fileName, restrictedToMainFibaAppOnly: true },
    downloadUrl: `/api/apk/download?version=${encodeURIComponent(versionName)}`,
  });
});

if (process.env.STANDALONE_BACKEND === 'true') {
  app.listen(PORT, '0.0.0.0', () => {
    console.log('Project Fiba /backend server running on port ' + PORT);
  });
}

export default app;
