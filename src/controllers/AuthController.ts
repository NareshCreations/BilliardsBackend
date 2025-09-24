// src/controllers/AuthController.ts
import { Request, Response } from 'express';
import { AuthService } from '../services/AuthService';

interface AuthenticatedRequest extends Request {
  user?: any;
}

export class AuthController {
  private authService: AuthService;

  constructor() {
    this.authService = new AuthService();
  }

  private getClientInfo(req: Request) {
    const forwarded = req.headers['x-forwarded-for'];
    const ip = forwarded ? (forwarded as string).split(',')[0] : req.connection.remoteAddress;
    return {
      ip: ip || '127.0.0.1',
      userAgent: req.headers['user-agent'] || 'Unknown',
      deviceInfo: {
        browser: req.headers['user-agent']?.split('/')[0] || 'Unknown',
        platform: req.headers['sec-ch-ua-platform'] || 'Unknown',
        mobile: req.headers['sec-ch-ua-mobile'] === '?1'
      }
    };
  }

  async login(req: Request, res: Response): Promise<void> {
    try {
      const { email, password } = req.body;
      const clientInfo = this.getClientInfo(req);

      // Validation
      if (!email || !password) {
        await this.authService.logLoginAttempt(email || 'unknown', false, clientInfo, 'missing_credentials');
        res.status(400).json({
          success: false,
          message: 'Email and password are required'
        });
        return;
      }

      // Check brute force protection
      const isRateLimited = await this.authService.checkBruteForceProtection(email);
      if (isRateLimited) {
        await this.authService.logLoginAttempt(email, false, clientInfo, 'rate_limited');
        res.status(429).json({
          success: false,
          message: 'Too many failed attempts. Please try again in 15 minutes.'
        });
        return;
      }

      // Find user
      const user = await this.authService.findUserByEmail(email);
      if (!user) {
        await this.authService.logLoginAttempt(email, false, clientInfo, 'user_not_found');
        res.status(401).json({
          success: false,
          message: 'Invalid email or password'
        });
        return;
      }

      // Verify password
      const isValidPassword = await this.authService.verifyPassword(password, user.passwordHash);
      if (!isValidPassword) {
        await this.authService.logLoginAttempt(email, false, clientInfo, 'invalid_password');
        res.status(401).json({
          success: false,
          message: 'Invalid email or password'
        });
        return;
      }

      // Create session
      const session = await this.authService.createUserSession(user.id, clientInfo);
      const accessToken = this.authService.generateAccessToken(user, session.sessionId);

      // Update user login info
      await this.authService.updateUserLastLogin(user.id, clientInfo.ip);
      await this.authService.logLoginAttempt(email, true, clientInfo);

      // Remove sensitive data
      const { passwordHash, passwordResetToken, emailVerificationToken, ...safeUser } = user;

      res.json({
        success: true,
        message: 'Login successful',
        data: {
          accessToken,
          refreshToken: session.refreshToken,
          expiresAt: session.expiresAt,
          user: safeUser
        }
      });

    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error'
      });
    }
  }

  async register(req: Request, res: Response): Promise<void> {
    try {
      const { email, password, firstName, lastName, phone, dateOfBirth } = req.body;

      // Validation
      if (!email || !password || !firstName || !lastName) {
        res.status(400).json({
          success: false,
          message: 'Email, password, first name, and last name are required'
        });
        return;
      }

      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        res.status(400).json({
          success: false,
          message: 'Please provide a valid email address'
        });
        return;
      }

      if (password.length < 8) {
        res.status(400).json({
          success: false,
          message: 'Password must be at least 8 characters long'
        });
        return;
      }

      // Check if user exists
      const existingUser = await this.authService.findUserByEmail(email);
      if (existingUser) {
        res.status(409).json({
          success: false,
          message: 'User with this email already exists'
        });
        return;
      }

      // Create user
      const user = await this.authService.createUser({
        email,
        password,
        firstName,
        lastName,
        phone,
        dateOfBirth
      });

      const accessToken = this.authService.generateAccessToken(user, '');

      const { passwordHash, ...safeUser } = user;

      res.status(201).json({
        success: true,
        message: 'User registered successfully',
        data: {
          accessToken,
          user: safeUser
        }
      });

    } catch (error) {
      console.error('Registration error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error'
      });
    }
  }

  async getProfile(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      // User should be attached by auth middleware
      const user = req.user;
      
      if (!user) {
        res.status(401).json({
          success: false,
          message: 'User not authenticated'
        });
        return;
      }

      const fullUser = await this.authService.findUserById(user.userId);
      
      if (!fullUser) {
        res.status(404).json({
          success: false,
          message: 'User not found'
        });
        return;
      }

      const { passwordHash, passwordResetToken, emailVerificationToken, ...safeUser } = fullUser;

      res.json({
        success: true,
        data: {
          user: safeUser
        }
      });

    } catch (error) {
      console.error('Profile error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error'
      });
    }
  }

  // Add other methods like logout, refresh, changePassword, etc.
}
