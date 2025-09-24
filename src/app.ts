import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import authRoutes from './routes/auth';
import { secrets, logSecretStatus } from './config/secrets';

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

// API Routes
app.use('/api/auth', authRoutes);

export default app;
