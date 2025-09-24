import 'reflect-metadata';
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import authRoutes from './routes/v1/auth.routes';
import { secrets, logSecretStatus } from './config/secrets';
import { initializeDatabase } from './config/orm';

// Load environment variables
dotenv.config();

// Log secret status on startup
try {
  logSecretStatus();
  console.log('✅ Secrets loaded successfully');
} catch (error) {
  console.error('❌ Secret loading failed:', error);
  process.exit(1);
}

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.get('/', (req, res) => {
  res.json({
    message: 'Hello World from nBilliardsNodeJS!',
    timestamp: new Date().toISOString(),
    status: 'success'
  });
});

app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

// Test endpoint that doesn't require database
app.get('/api/test', (req, res) => {
  res.json({
    success: true,
    message: 'API is working!',
    timestamp: new Date().toISOString(),
    endpoints: {
      auth: '/api/v1/auth/*',
      health: '/health',
      main: '/'
    }
  });
});

// API Routes
app.use('/api/v1/auth', authRoutes);

// Initialize database connection (non-blocking)
const startServer = async () => {
  try {
    await initializeDatabase();
    console.log('✅ Database initialized successfully');
  } catch (error) {
    console.error('❌ Database initialization failed:', error);
    console.log('⚠️  Server will continue without database connection');
    console.log('💡 To fix: Start Docker Desktop and run: docker-compose up -d postgres');
  }
};

// Start database connection (don't block server startup)
startServer().catch(() => {
  // Ignore database errors, server should continue
});

export default app;
