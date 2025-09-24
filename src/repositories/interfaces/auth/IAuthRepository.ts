import { User } from '../../../entities/auth/User.entity';

export interface IAuthRepository {
  findUserByEmail(email: string): Promise<User | null>;
  findUserById(id: string): Promise<User | null>;
  createUser(userData: Partial<User>): Promise<User>;
  updateUserPassword(userId: string, hashedPassword: string): Promise<void>;
  updateLastLogin(userId: string, ip: string): Promise<void>;
  incrementLoginAttempts(userId: string): Promise<void>;
  resetLoginAttempts(userId: string): Promise<void>;
  lockAccount(userId: string, until: Date): Promise<void>;
  isAccountLocked(userId: string): Promise<boolean>;
  updateEmailVerificationToken(userId: string, token: string, expiresAt: Date): Promise<void>;
  verifyEmail(token: string): Promise<User | null>;
  updatePasswordResetToken(userId: string, token: string, expiresAt: Date): Promise<void>;
  findUserByResetToken(token: string): Promise<User | null>;
  clearPasswordResetToken(userId: string): Promise<void>;
  updatePhoneVerificationCode(userId: string, code: string): Promise<void>;
  verifyPhone(phone: string, code: string): Promise<User | null>;
  checkEmailExists(email: string): Promise<boolean>;
  checkPhoneExists(phone: string): Promise<boolean>;
}
