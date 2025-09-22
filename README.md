# 🎱 Billiards Backend - Comprehensive Authentication System

A production-ready Node.js backend with comprehensive authentication, session management, and database integration.

## 🔐 Features

- **Complete Authentication System** - Login, Register, Password Reset
- **Session Management** - Multi-device support with refresh tokens
- **Security Features** - Brute force protection, account lockout
- **Database Integration** - PostgreSQL with Redis caching
- **Docker Ready** - Full containerization with Docker Compose
- **Production Grade** - Environment configurations, security headers

## 🚀 Quick Start

### Local Development
```bash
# Clone repository
git clone https://github.com/NareshCreations/BilliardsBackend.git
cd BilliardsBackend

# Start with Docker Compose
docker-compose up -d

# API will be available at http://localhost:3001
```

### Railway Deployment
This app is configured for Railway deployment with Docker.

## 📚 API Endpoints

### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/register` - User registration
- `POST /api/auth/refresh` - Refresh access token
- `POST /api/auth/logout` - Logout user
- `POST /api/auth/logout-all` - Logout from all devices

### Password Management
- `POST /api/auth/forgot-password` - Initiate password reset
- `POST /api/auth/reset-password` - Reset password with token
- `POST /api/auth/change-password` - Change password (authenticated)

### Verification
- `POST /api/auth/verify-email` - Verify email address
- `POST /api/auth/verify-phone` - Verify phone number

### Session Management
- `GET /api/auth/sessions` - Get active sessions

## 🗄️ Database Schema

- **users** - Enhanced user accounts with security features
- **user_sessions** - Session tracking and management
- **login_attempts** - Security monitoring and brute force protection
- **user_preferences** - Extended user settings

## 🐳 Docker Configuration

- **Node.js App** - Main application container
- **PostgreSQL** - Database with initialization scripts
- **Redis** - Caching and session storage
- **NGINX** - Reverse proxy with security headers
- **pgAdmin** - Database management interface

## 🔒 Security Features

- bcrypt password hashing (12 rounds)
- JWT with refresh token rotation
- Session-based authentication
- Rate limiting & IP tracking
- Account lockout mechanisms
- Password change invalidates all sessions

## 🌐 Environment Variables

Required for production deployment:
```
NODE_ENV=production
PORT=3001
DB_HOST=localhost
DB_PORT=5432
DB_NAME=billiards_platform
DB_USER=postgres
DB_PASSWORD=your_password
JWT_SECRET=your_jwt_secret
DATABASE_URL=postgresql://user:pass@host:5432/db
REDIS_URL=redis://localhost:6379
```