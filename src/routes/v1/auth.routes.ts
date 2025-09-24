import express from 'express';
import { AuthController } from '../../controllers/AuthController';
import { authenticateToken, authorizeRoles } from '../../middleware/auth.middleware';

const router = express.Router();
const authController = new AuthController();

// Public routes
router.post('/login', (req, res) => authController.login(req, res));
router.post('/register', (req, res) => authController.register(req, res));
router.post('/refresh', (req, res) => authController.refreshToken(req, res));
router.post('/forgot-password', (req, res) => authController.forgotPassword(req, res));
router.post('/reset-password', (req, res) => authController.resetPassword(req, res));
router.post('/verify-email', (req, res) => authController.verifyEmail(req, res));
router.post('/verify-phone', (req, res) => authController.verifyPhone(req, res));

// Protected routes
router.post('/logout', authenticateToken, (req, res) => authController.logout(req, res));
router.post('/logout-all', authenticateToken, (req, res) => authController.logoutAll(req, res));
router.post('/change-password', authenticateToken, (req, res) => authController.changePassword(req, res));
router.get('/profile', authenticateToken, (req, res) => authController.getProfile(req, res));
router.get('/sessions', authenticateToken, (req, res) => authController.getSessions(req, res));

// Admin routes
router.get('/admin/users', authenticateToken, authorizeRoles('admin'), (req, res) => {
  // Admin functionality
  res.json({ message: 'Admin users endpoint' });
});

export default router;
