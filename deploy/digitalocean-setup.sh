#!/bin/bash

# DigitalOcean Droplet Setup Script for Billiards Backend
# Run this on a fresh Ubuntu 22.04 droplet

echo "🚀 Setting up Billiards Backend on DigitalOcean..."

# Update system
sudo apt update && sudo apt upgrade -y

# Install Node.js 18
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Install PostgreSQL
sudo apt install postgresql postgresql-contrib -y

# Install Redis
sudo apt install redis-server -y

# Install PM2 for process management
sudo npm install -g pm2

# Install Git
sudo apt install git -y

# Create application directory
sudo mkdir -p /var/www/billiards-backend
sudo chown $USER:$USER /var/www/billiards-backend

# Clone repository
cd /var/www/billiards-backend
git clone https://github.com/NareshCreations/BilliardsBackend.git .

# Install dependencies
npm install

# Build the application
npm run build

# Setup PostgreSQL
sudo -u postgres psql -c "CREATE DATABASE billiards_platform;"
sudo -u postgres psql -c "CREATE USER billiards_user WITH PASSWORD 'your_secure_password';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE billiards_platform TO billiards_user;"

# Create environment file
cat > .env << EOF
NODE_ENV=production
PORT=3001
DB_HOST=localhost
DB_PORT=5432
DB_NAME=billiards_platform
DB_USER=billiards_user
DB_PASSWORD=your_secure_password
DATABASE_URL=postgresql://billiards_user:your_secure_password@localhost:5432/billiards_platform
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
REDIS_URL=redis://localhost:6379
EOF

# Run database migration
npm run migrate

# Setup PM2 ecosystem
cat > ecosystem.config.js << EOF
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
      PORT: 3001
    }
  }]
};
EOF

# Start the application
pm2 start ecosystem.config.js
pm2 save
pm2 startup

# Setup Nginx
sudo apt install nginx -y

# Create Nginx configuration
sudo tee /etc/nginx/sites-available/billiards-backend << EOF
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF

# Enable the site
sudo ln -s /etc/nginx/sites-available/billiards-backend /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx

# Setup firewall
sudo ufw allow 22
sudo ufw allow 80
sudo ufw allow 443
sudo ufw --force enable

echo "✅ Setup complete!"
echo "🌐 Your app should be running at: http://your-droplet-ip"
echo "🔧 To check status: pm2 status"
echo "📋 To view logs: pm2 logs billiards-backend"
