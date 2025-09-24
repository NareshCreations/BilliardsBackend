module.exports = {
  apps: [{
    name: 'billiards-backend',
    script: 'dist/server.js',
    instances: 1,
    autorestart: true,
    watch: false,
    max_memory_restart: '1G',
    env: {
      NODE_ENV: 'production',
      PORT: 3001,
      DB_HOST: 'localhost',
      DB_PORT: '5432',
      DB_NAME: 'billiards_platform',
      DB_USER: 'billiards_user',
      DB_PASSWORD: 'your_secure_password',
      DATABASE_URL: 'postgresql://billiards_user:your_secure_password@localhost:5432/billiards_platform',
      JWT_SECRET: 'your-super-secret-jwt-key-change-this-in-production',
      REDIS_URL: 'redis://localhost:6379'
    }
  }]
};
