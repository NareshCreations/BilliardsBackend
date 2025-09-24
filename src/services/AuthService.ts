import { IAuthRepository } from '../repositories/interfaces/auth/IAuthRepository';
import { ISessionRepository } from '../repositories/interfaces/auth/ISessionRepository';
import { ILoginAttemptRepository } from '../repositories/interfaces/auth/ILoginAttemptRepository';
import { AuthRepository } from '../repositories/implementations/auth/AuthRepository';
import { SessionRepository } from '../repositories/implementations/auth/SessionRepository';
import { LoginAttemptRepository } from '../repositories/implementations/auth/LoginAttemptRepository';
import { User } from '../entities/auth/User.entity';
import { UserSession } from '../entities/auth/UserSession.entity';
import { LoginDto, RegisterDto, UserResponseDto } from '../dto/auth';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { secrets } from '../config/secrets';

interface ClientInfo {
  ip: string;
  userAgent: string;
  deviceInfo: {
    browser: string;
    platform: string | string[];
    mobile: boolean;
  };
}

export class AuthService {
  private authRepository: IAuthRepository;
  private sessionRepository: ISessionRepository;
  private loginAttemptRepository: ILoginAttemptRepository;

  constructor(
    authRepository?: IAuthRepository,
    sessionRepository?: ISessionRepository,
    loginAttemptRepository?: ILoginAttemptRepository
  ) {
    this.authRepository = authRepository || new AuthRepository();
    this.sessionRepository = sessionRepository || new SessionRepository();
    this.loginAttemptRepository = loginAttemptRepository || new LoginAttemptRepository();
  }

  async login(loginData: LoginDto, clientInfo: ClientInfo) {
    const { email, password } = loginData;

    try {
      // Check brute force protection
      const recentFailedAttempts = await this.loginAttemptRepository.getRecentFailedAttempts(email, 15);
      if (recentFailedAttempts >= 5) {
        await this.logFailedAttempt(email, clientInfo, 'rate_limited');
        throw new Error('Too many failed attempts. Please try again in 15 minutes.');
      }

      // Find user
      const user = await this.authRepository.findUserByEmail(email);
      if (!user) {
        await this.logFailedAttempt(email, clientInfo, 'user_not_found');
        throw new Error('Invalid email or password');
      }

      // Check if account is locked
      const isLocked = await this.authRepository.isAccountLocked(user.id);
      if (isLocked) {
        await this.logFailedAttempt(email, clientInfo, 'account_locked');
        throw new Error('Account is temporarily locked');
      }

      // Verify password
      const isValidPassword = await bcrypt.compare(password, user.passwordHash);
      if (!isValidPassword) {
        await this.authRepository.incrementLoginAttempts(user.id);
        await this.logFailedAttempt(email, clientInfo, 'invalid_password');
        throw new Error('Invalid email or password');
      }

      // Create session
      const session = await this.createUserSession(user.id, clientInfo);
      
      // Update user login info
      await this.authRepository.updateLastLogin(user.id, clientInfo.ip);
      
      // Log successful login
      await this.logSuccessfulAttempt(email, clientInfo);

      // Generate access token
      const accessToken = this.generateAccessToken(user, session.id);

      return {
        accessToken,
        refreshToken: session.refreshToken,
        expiresAt: session.expiresAt,
        user: this.sanitizeUser(user)
      };
    } catch (error) {
      throw error;
    }
  }

  async register(registerData: RegisterDto): Promise<{
    accessToken: string;
    user: UserResponseDto;
  }> {
    const { email, password, firstName, lastName, phone, dateOfBirth } = registerData;

    try {
      // Check if user already exists
      const existingUser = await this.authRepository.checkEmailExists(email);
      if (existingUser) {
        throw new Error('User with this email already exists');
      }

      // Hash password
      const passwordHash = await bcrypt.hash(password, 12);

      // Create user
      const newUser = await this.authRepository.createUser({
        email,
        phone,
        passwordHash,
        firstName,
        lastName,
        dateOfBirth,
        accountType: 'player',
        isActive: true,
        emailVerified: false,
        phoneVerified: false,
        isPremium: false
      });

      // Generate access token
      const accessToken = this.generateAccessToken(newUser, '');

      return {
        accessToken,
        user: this.sanitizeUser(newUser)
      };
    } catch (error) {
      throw error;
    }
  }

  async refreshToken(refreshToken: string, clientInfo: ClientInfo) {
    try {
      // Hash the refresh token
      const refreshTokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');

      // Find active session
      const session = await this.sessionRepository.findSessionByRefreshToken(refreshTokenHash);
      if (!session || !session.user.isActive) {
        throw new Error('Invalid or expired refresh token');
      }

      // Update session last used
      await this.sessionRepository.updateSessionLastUsed(session.id, clientInfo.ip, clientInfo.userAgent);

      // Generate new access token
      const accessToken = this.generateAccessToken(session.user, session.id);

      return {
        accessToken,
        expiresIn: '15m'
      };
    } catch (error) {
      throw error;
    }
  }

  async logout(refreshToken: string): Promise<void> {
    try {
      const refreshTokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
      const session = await this.sessionRepository.findSessionByRefreshToken(refreshTokenHash);
      
      if (session) {
        await this.sessionRepository.deactivateSession(session.id);
      }
    } catch (error) {
      throw error;
    }
  }

  async logoutAllDevices(refreshToken: string): Promise<void> {
    try {
      const refreshTokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
      const session = await this.sessionRepository.findSessionByRefreshToken(refreshTokenHash);
      
      if (session) {
        await this.sessionRepository.deactivateAllUserSessions(session.userId);
      }
    } catch (error) {
      throw error;
    }
  }

  async forgotPassword(email: string): Promise<{ resetToken: string }> {
    try {
      const user = await this.authRepository.findUserByEmail(email);
      if (!user) {
        // Always return success to prevent email enumeration
        throw new Error('If an account with that email exists, a password reset link has been sent');
      }

      // Generate reset token
      const resetToken = crypto.randomBytes(32).toString('hex');
      const resetExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

      await this.authRepository.updatePasswordResetToken(user.id, resetToken, resetExpires);

      return { resetToken };
    } catch (error) {
      throw error;
    }
  }

  async resetPassword(token: string, newPassword: string): Promise<void> {
    try {
      const user = await this.authRepository.findUserByResetToken(token);
      if (!user || !user.passwordResetExpires || user.passwordResetExpires < new Date()) {
        throw new Error('Invalid or expired reset token');
      }

      const passwordHash = await bcrypt.hash(newPassword, 12);
      await this.authRepository.updateUserPassword(user.id, passwordHash);
      await this.authRepository.clearPasswordResetToken(user.id);

      // Invalidate all sessions for security
      await this.sessionRepository.deactivateAllUserSessions(user.id);
    } catch (error) {
      throw error;
    }
  }

  async changePassword(userId: string, currentPassword: string, newPassword: string, clientInfo: ClientInfo) {
    try {
      const user = await this.authRepository.findUserById(userId);
      if (!user) {
        throw new Error('User not found');
      }

      // Verify current password
      const isValidPassword = await bcrypt.compare(currentPassword, user.passwordHash);
      if (!isValidPassword) {
        throw new Error('Current password is incorrect');
      }

      // Hash new password
      const newPasswordHash = await bcrypt.hash(newPassword, 12);
      await this.authRepository.updateUserPassword(user.id, newPasswordHash);

      // Invalidate all sessions except current one
      await this.sessionRepository.deactivateAllUserSessions(user.id);
      
      // Create new session for current user
      const newSession = await this.createUserSession(user.id, clientInfo);
      const newAccessToken = this.generateAccessToken(user, newSession.id);

      return {
        accessToken: newAccessToken,
        refreshToken: newSession.refreshToken,
        expiresAt: newSession.expiresAt
      };
    } catch (error) {
      throw error;
    }
  }

  async verifyEmail(token: string): Promise<void> {
    try {
      const user = await this.authRepository.verifyEmail(token);
      if (!user) {
        throw new Error('Invalid or expired verification token');
      }
    } catch (error) {
      throw error;
    }
  }

  async verifyPhone(phone: string, code: string): Promise<void> {
    try {
      const user = await this.authRepository.verifyPhone(phone, code);
      if (!user) {
        throw new Error('Invalid verification code or phone number');
      }
    } catch (error) {
      throw error;
    }
  }

  async getUserProfile(userId: string): Promise<UserResponseDto> {
    try {
      const user = await this.authRepository.findUserById(userId);
      if (!user) {
        throw new Error('User not found');
      }
      return this.sanitizeUser(user);
    } catch (error) {
      throw error;
    }
  }

  async getUserSessions(userId: string): Promise<UserSession[]> {
    try {
      return await this.sessionRepository.findActiveUserSessions(userId);
    } catch (error) {
      throw error;
    }
  }

  // Private helper methods
  private async createUserSession(userId: string, clientInfo: ClientInfo): Promise<{
    id: string;
    refreshToken: string;
    expiresAt: Date;
  }> {
    const refreshToken = crypto.randomBytes(32).toString('hex');
    const refreshTokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

    const session = await this.sessionRepository.createSession({
      userId,
      refreshTokenHash,
      deviceInfo: clientInfo.deviceInfo,
      ipAddress: clientInfo.ip,
      userAgent: clientInfo.userAgent,
      expiresAt
    });

    return {
      id: session.id,
      refreshToken,
      expiresAt: session.expiresAt
    };
  }

  private generateAccessToken(user: User, sessionId: string): string {
    return jwt.sign(
      { 
        userId: user.id, 
        email: user.email,
        accountType: user.accountType,
        sessionId
      },
      secrets.JWT_SECRET,
      { expiresIn: '15m' }
    );
  }

  private sanitizeUser(user: User): UserResponseDto {
    return {
      id: user.id,
      email: user.email,
      phone: user.phone,
      firstName: user.firstName,
      lastName: user.lastName,
      dateOfBirth: user.dateOfBirth,
      emailVerified: user.emailVerified,
      phoneVerified: user.phoneVerified,
      isActive: user.isActive,
      isPremium: user.isPremium,
      accountType: user.accountType,
      lastLogin: user.lastLogin,
      createdAt: user.createdAt
    };
  }

  private async logFailedAttempt(email: string, clientInfo: ClientInfo, reason: string): Promise<void> {
    await this.loginAttemptRepository.logLoginAttempt({
      email,
      ipAddress: clientInfo.ip,
      userAgent: clientInfo.userAgent,
      success: false,
      failureReason: reason
    });
  }

  private async logSuccessfulAttempt(email: string, clientInfo: ClientInfo): Promise<void> {
    await this.loginAttemptRepository.logLoginAttempt({
      email,
      ipAddress: clientInfo.ip,
      userAgent: clientInfo.userAgent,
      success: true
    });
  }
}