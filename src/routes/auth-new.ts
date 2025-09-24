import express from 'express';
import { AuthController } from '../controllers/AuthController';
import { authenticateToken } from '../middleware/auth';

const router = express.Router();
const authController = new AuthController();

// Public routes
router.post('/login', (req, res) => authController.login(req, res));
router.post('/register', (req, res) => authController.register(req, res));

// Protected routes
router.get('/profile', authenticateToken, (req, res) => authController.getProfile(req, res));

// Add other routes as needed

export default router;
