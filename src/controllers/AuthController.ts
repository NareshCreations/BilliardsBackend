import { Request, Response } from 'express';
import { AuthService } from '../services/AuthService';
import { LoginDto, RegisterDto, RefreshTokenDto, ForgotPasswordDto, ResetPasswordDto, ChangePasswordDto } from '../dto/auth';

interface AuthenticatedRequest extends Request {
  user?: {
    userId: string;
    email: string;
    accountType: string;
    sessionId: string;
  };
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
      const loginData: LoginDto = req.body;
      const clientInfo = this.getClientInfo(req);

      if (!loginData.email || !loginData.password) {
        res.status(400).json({
          success: false,
          message: 'Email and password are required'
        });
        return;
      }

      const result = await this.authService.login(loginData, clientInfo);

      res.json({
        success: true,
        message: 'Login successful',
        data: result
      });
    } catch (error) {
      console.error('Login error:', error);
      if (error instanceof Error && error.message.includes('No metadata')) {
        res.status(503).json({
          success: false,
          message: 'Database connection not available. Please start the database.',
          error: 'DATABASE_CONNECTION_FAILED'
        });
      } else {
        res.status(401).json({
          success: false,
          message: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    }
  }

  async register(req: Request, res: Response): Promise<void> {
    try {
      const registerData: RegisterDto = req.body;

      // Validation
      if (!registerData.email || !registerData.password || !registerData.firstName || !registerData.lastName) {
        res.status(400).json({
          success: false,
          message: 'Email, password, first name, and last name are required'
        });
        return;
      }

      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(registerData.email)) {
        res.status(400).json({
          success: false,
          message: 'Please provide a valid email address'
        });
        return;
      }

      if (registerData.password.length < 8) {
        res.status(400).json({
          success: false,
          message: 'Password must be at least 8 characters long'
        });
        return;
      }

      const result = await this.authService.register(registerData);

      res.status(201).json({
        success: true,
        message: 'User registered successfully',
        data: result
      });
    } catch (error) {
      console.error('Registration error:', error);
      if (error instanceof Error && error.message.includes('already exists')) {
        res.status(409).json({
          success: false,
          message: error.message
        });
      } else if (error instanceof Error && error.message.includes('No metadata')) {
        res.status(503).json({
          success: false,
          message: 'Database connection not available. Please start the database.',
          error: 'DATABASE_CONNECTION_FAILED'
        });
      } else {
        res.status(500).json({
          success: false,
          message: error instanceof Error ? error.message : 'Internal server error'
        });
      }
    }
  }

  async refreshToken(req: Request, res: Response): Promise<void> {
    try {
      const { refreshToken }: RefreshTokenDto = req.body;
      const clientInfo = this.getClientInfo(req);

      if (!refreshToken) {
        res.status(400).json({
          success: false,
          message: 'Refresh token is required'
        });
        return;
      }

      const result = await this.authService.refreshToken(refreshToken, clientInfo);

      res.json({
        success: true,
        message: 'Token refreshed successfully',
        data: result
      });
    } catch (error) {
      res.status(401).json({
        success: false,
        message: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  async logout(req: Request, res: Response): Promise<void> {
    try {
      const { refreshToken }: RefreshTokenDto = req.body;

      if (!refreshToken) {
        res.status(400).json({
          success: false,
          message: 'Refresh token is required'
        });
        return;
      }

      await this.authService.logout(refreshToken);

      res.json({
        success: true,
        message: 'Logged out successfully'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Internal server error'
      });
    }
  }

  async logoutAll(req: Request, res: Response): Promise<void> {
    try {
      const { refreshToken }: RefreshTokenDto = req.body;

      if (!refreshToken) {
        res.status(400).json({
          success: false,
          message: 'Refresh token is required'
        });
        return;
      }

      await this.authService.logoutAllDevices(refreshToken);

      res.json({
        success: true,
        message: 'Logged out from all devices successfully'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Internal server error'
      });
    }
  }

  async forgotPassword(req: Request, res: Response): Promise<void> {
    try {
      const { email }: ForgotPasswordDto = req.body;

      if (!email) {
        res.status(400).json({
          success: false,
          message: 'Email is required'
        });
        return;
      }

      const result = await this.authService.forgotPassword(email);

      res.json({
        success: true,
        message: 'If an account with that email exists, a password reset link has been sent',
        // Remove in production
        debug: { resetToken: result.resetToken }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Internal server error'
      });
    }
  }

  async resetPassword(req: Request, res: Response): Promise<void> {
    try {
      const { token, newPassword }: ResetPasswordDto = req.body;

      if (!token || !newPassword) {
        res.status(400).json({
          success: false,
          message: 'Token and new password are required'
        });
        return;
      }

      if (newPassword.length < 8) {
        res.status(400).json({
          success: false,
          message: 'Password must be at least 8 characters long'
        });
        return;
      }

      await this.authService.resetPassword(token, newPassword);

      res.json({
        success: true,
        message: 'Password has been reset successfully'
      });
    } catch (error) {
      res.status(400).json({
        success: false,
        message: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  async changePassword(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const { currentPassword, newPassword }: ChangePasswordDto = req.body;
      const clientInfo = this.getClientInfo(req);

      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'User not authenticated'
        });
        return;
      }

      if (!currentPassword || !newPassword) {
        res.status(400).json({
          success: false,
          message: 'Current password and new password are required'
        });
        return;
      }

      if (newPassword.length < 8) {
        res.status(400).json({
          success: false,
          message: 'New password must be at least 8 characters long'
        });
        return;
      }

      const result = await this.authService.changePassword(
        req.user.userId,
        currentPassword,
        newPassword,
        clientInfo
      );

      res.json({
        success: true,
        message: 'Password changed successfully. All other sessions have been terminated.',
        data: result
      });
    } catch (error) {
      res.status(400).json({
        success: false,
        message: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  async verifyEmail(req: Request, res: Response): Promise<void> {
    try {
      const { token } = req.body;

      if (!token) {
        res.status(400).json({
          success: false,
          message: 'Verification token is required'
        });
        return;
      }

      await this.authService.verifyEmail(token);

      res.json({
        success: true,
        message: 'Email verified successfully'
      });
    } catch (error) {
      res.status(400).json({
        success: false,
        message: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  async verifyPhone(req: Request, res: Response): Promise<void> {
    try {
      const { code, phone } = req.body;

      if (!code || !phone) {
        res.status(400).json({
          success: false,
          message: 'Verification code and phone number are required'
        });
        return;
      }

      await this.authService.verifyPhone(phone, code);

      res.json({
        success: true,
        message: 'Phone number verified successfully'
      });
    } catch (error) {
      res.status(400).json({
        success: false,
        message: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  async getProfile(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'User not authenticated'
        });
        return;
      }

      const user = await this.authService.getUserProfile(req.user.userId);

      res.json({
        success: true,
        data: { user }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Internal server error'
      });
    }
  }

  async getSessions(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'User not authenticated'
        });
        return;
      }

      const sessions = await this.authService.getUserSessions(req.user.userId);

      res.json({
        success: true,
        data: {
          sessions: sessions.map(session => ({
            id: session.id,
            deviceInfo: session.deviceInfo,
            ipAddress: session.ipAddress,
            userAgent: session.userAgent,
            createdAt: session.createdAt,
            lastUsedAt: session.lastUsedAt,
            expiresAt: session.expiresAt,
            isCurrent: session.id === req.user?.sessionId
          }))
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Internal server error'
      });
    }
  }
}