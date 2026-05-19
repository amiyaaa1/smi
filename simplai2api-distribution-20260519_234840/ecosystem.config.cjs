const path = require('path');

module.exports = {
  apps: [
    {
      name: 'simplai2api',
      cwd: __dirname,
      script: 'server.js',
      env: {
        NODE_ENV: 'production',
        SIMPLAI2API_HOST: '0.0.0.0',
        SIMPLAI2API_PORT: '8031',
        SIMPLAI2API_ADMIN_PASSWORD: 'Nishibaka114514.',
        SIMPLAI_PROFILE_BASE_DIR: path.join(__dirname, 'profiles'),
        SIMPLAI_CLOAKBROWSER_PATH: path.join(__dirname, 'third_party', 'CloakBrowser'),
        SIMPLAI_PROTOCOL_KEYGEN_PATH: path.join(__dirname, 'third_party', 'protocol_keygen.py'),
        CLOAKBROWSER_CACHE_DIR: path.join(__dirname, 'cloakbrowser-cache'),
      },
    },
  ],
};
