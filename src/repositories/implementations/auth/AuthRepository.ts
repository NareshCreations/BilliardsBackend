import { Repository } from 'typeorm';
import { AppDataSource } from '../../../config/orm';
import { User } from '../../../entities/auth/User.entity';
import { IAuthRepository } from '../../interfaces/auth/IAuthRepository';
import crypto from 'crypto';

export class AuthRepository implements IAuthRepository {
  private userRepository: Repository<User> | null = null;

  constructor() {
    // Lazy initialization - will be initialized when first used
  }

  private ensureRepository(): Repository<User> {
    if (!this.userRepository) {
      if (!AppDataSource.isInitialized) {
        throw new Error('Database not initialized. Call initializeDatabase() first.');
      }
      this.userRepository = AppDataSource.getRepository(User);
    }
    return this.userRepository;
  }

  async findUserByEmail(email: string): Promise<User | null> {
    try {
      return await this.ensureRepository().findOne({
        where: { email, isActive: true }
      });
    } catch (error) {
      throw new Error(`Failed to find user by email: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async findUserById(id: string): Promise<User | null> {
    try {
      return await this.ensureRepository().findOne({
        where: { id, isActive: true }
      });
    } catch (error) {
      throw new Error(`Failed to find user by ID: ${error instanceof Error ? error instanceof Error ? error.message : 'Unknown error' : 'Unknown error'}`);
    }
  }

  async createUser(userData: Partial<User>): Promise<User> {
    try {
      const user = this.ensureRepository().create(userData);
      return await this.ensureRepository().save(user);
    } catch (error) {
      throw new Error(`Failed to create user: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async updateUserPassword(userId: string, hashedPassword: string): Promise<void> {
    try {
      await this.ensureRepository().update(userId, {
        passwordHash: hashedPassword,
        passwordChangedAt: new Date(),
        updatedAt: new Date()
      });
    } catch (error) {
      throw new Error(`Failed to update user password: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async updateLastLogin(userId: string, ip: string): Promise<void> {
    try {
      await this.ensureRepository().update(userId, {
        lastLogin: new Date(),
        lastIp: ip,
        loginAttempts: 0,
        lockedUntil: undefined
      });
    } catch (error) {
      throw new Error(`Failed to update last login: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async incrementLoginAttempts(userId: string): Promise<void> {
    try {
      await this.ensureRepository().increment({ id: userId }, 'loginAttempts', 1);
      
      const user = await this.findUserById(userId);
      if (user && user.loginAttempts >= 4) {
        const lockUntil = new Date(Date.now() + 30 * 60 * 1000);
        await this.lockAccount(userId, lockUntil);
      }
    } catch (error) {
      throw new Error(`Failed to increment login attempts: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async resetLoginAttempts(userId: string): Promise<void> {
    try {
      await this.ensureRepository().update(userId, {
        loginAttempts: 0,
        lockedUntil: undefined
      });
    } catch (error) {
      throw new Error(`Failed to reset login attempts: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async lockAccount(userId: string, until: Date): Promise<void> {
    try {
      await this.ensureRepository().update(userId, { lockedUntil: until });
    } catch (error) {
      throw new Error(`Failed to lock account: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async isAccountLocked(userId: string): Promise<boolean> {
    try {
      const user = await this.ensureRepository().findOne({
        where: { id: userId },
        select: { lockedUntil: true }
      });
      return user?.lockedUntil ? new Date(user.lockedUntil) > new Date() : false;
    } catch (error) {
      throw new Error(`Failed to check account lock status: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async updateEmailVerificationToken(userId: string, token: string, expiresAt: Date): Promise<void> {
    try {
      await this.ensureRepository().update(userId, {
        emailVerificationToken: token,
        emailVerificationExpires: expiresAt
      });
    } catch (error) {
      throw new Error(`Failed to update email verification token: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async verifyEmail(token: string): Promise<User | null> {
    try {
      const user = await this.ensureRepository().findOne({
        where: {
          emailVerificationToken: token,
          emailVerified: false,
          isActive: true
        }
      });

      if (user && user.emailVerificationExpires && user.emailVerificationExpires > new Date()) {
        await this.ensureRepository().update(user.id, {
          emailVerified: true,
          emailVerificationToken: undefined,
          emailVerificationExpires: undefined
        });
        return user;
      }
      return null;
    } catch (error) {
      throw new Error(`Failed to verify email: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async updatePasswordResetToken(userId: string, token: string, expiresAt: Date): Promise<void> {
    try {
      const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
      await this.ensureRepository().update(userId, {
        passwordResetToken: tokenHash,
        passwordResetExpires: expiresAt
      });
    } catch (error) {
      throw new Error(`Failed to update password reset token: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async findUserByResetToken(token: string): Promise<User | null> {
    try {
      const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
      return await this.ensureRepository().findOne({
        where: {
          passwordResetToken: tokenHash,
          isActive: true
        }
      });
    } catch (error) {
      throw new Error(`Failed to find user by reset token: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async clearPasswordResetToken(userId: string): Promise<void> {
    try {
      await this.ensureRepository().update(userId, {
        passwordResetToken: undefined,
        passwordResetExpires: undefined
      });
    } catch (error) {
      throw new Error(`Failed to clear password reset token: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async updatePhoneVerificationCode(userId: string, code: string): Promise<void> {
    try {
      await this.ensureRepository().update(userId, { phoneVerificationCode: code });
    } catch (error) {
      throw new Error(`Failed to update phone verification code: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async verifyPhone(phone: string, code: string): Promise<User | null> {
    try {
      const user = await this.ensureRepository().findOne({
        where: {
          phone,
          phoneVerificationCode: code,
          phoneVerified: false,
          isActive: true
        }
      });

      if (user) {
        await this.ensureRepository().update(user.id, {
          phoneVerified: true,
          phoneVerificationCode: undefined
        });
        return user;
      }
      return null;
    } catch (error) {
      throw new Error(`Failed to verify phone: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async checkEmailExists(email: string): Promise<boolean> {
    try {
      const count = await this.ensureRepository().count({ where: { email } });
      return count > 0;
    } catch (error) {
      throw new Error(`Failed to check email existence: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async checkPhoneExists(phone: string): Promise<boolean> {
    try {
      const count = await this.ensureRepository().count({ where: { phone } });
      return count > 0;
    } catch (error) {
      throw new Error(`Failed to check phone existence: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
}
