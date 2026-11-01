const path = require('path');
const crypto = require('crypto');
const multer = require('multer');
const { UPLOADS_DIR } = require('./db');

const storage = multer.diskStorage({
  destination: function (_req, _file, cb) {
    cb(null, UPLOADS_DIR);
  },
  filename: function (_req, file, cb) {
    const ext = path.extname(file.originalname || '').toLowerCase() || '.png';
    const safeBase = path
      .basename(file.originalname || 'asset', ext)
      .replace(/[^a-z0-9_-]/gi, '_')
      .slice(0, 40);
    const uniqueName = safeBase + '_' + Date.now() + '_' + crypto.randomBytes(3).toString('hex') + ext;
    cb(null, uniqueName);
  }
});

const uploadMiddleware = multer({
  storage: storage,
  limits: {
    fileSize: 25 * 1024 * 1024
  }
});

module.exports = {
  uploadMiddleware
};
