// src/services/AuthService.ts
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import pool from '../config/database';
import { secrets } from '../config/secrets';
import { User, UserSession } from '../models/User';

export class AuthService {
  private readonly JWT_SECRET = secrets.JWT_SECRET;
  private readonly REFRESH_TOKEN_EXPIRY = 7 * 24 * 60 * 60 * 1000; // 7 days
  private readonly ACCESS_TOKEN_EXPIRY = '15m';

  async findUserByEmail(email: string): Promise<User | null> {
    const userQuery = `
      SELECT u.*, up.skill_level, up.bio, up.notification_settings, up.privacy_settings
      FROM users u
      LEFT JOIN user_preferences up ON u.id = up.user_id
      WHERE u.email = $1 AND u.is_active = true
    `;
    
    const result = await pool.query(userQuery, [email]);
    return result.rows.length > 0 ? result.rows[0] : null;
  }

  async findUserById(id: string): Promise<User | null> {
    const userQuery = `
      SELECT u.*, up.skill_level, up.bio, up.notification_settings, up.privacy_settings
      FROM users u
      LEFT JOIN user_preferences up ON u.id = up.user_id
      WHERE u.id = $1 AND u.is_active = true
    `;
    
    const result = await pool.query(userQuery, [id]);
    return result.rows.length > 0 ? result.rows[0] : null;
  }

  async verifyPassword(plainPassword: string, hashedPassword: string): Promise<boolean> {
    return bcrypt.compare(plainPassword, hashedPassword);
  }

  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, 12);
  }

  async createUserSession(userId: string, clientInfo: any): Promise<{ sessionId: string; refreshToken: string; expiresAt: Date }> {
    const refreshToken = crypto.randomBytes(32).toString('hex');
    const refreshTokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
    const expiresAt = new Date(Date.now() + this.REFRESH_TOKEN_EXPIRY);

    const sessionResult = await pool.query(
      `INSERT INTO user_sessions (user_id, refresh_token_hash, device_info, ip_address, user_agent, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id`,
      [userId, refreshTokenHash, JSON.stringify(clientInfo.deviceInfo), clientInfo.ip, clientInfo.userAgent, expiresAt]
    );

    return {
      sessionId: sessionResult.rows[0].id,
      refreshToken,
      expiresAt
    };
  }

  generateAccessToken(user: User, sessionId: string): string {
    return jwt.sign(
      { 
        userId: user.id, 
        email: user.email,
        accountType: user.accountType || 'player',
        sessionId
      },
      this.JWT_SECRET,
      { expiresIn: this.ACCESS_TOKEN_EXPIRY }
    );
  }

  async checkBruteForceProtection(email: string): Promise<boolean> {
    const recentAttemptsQuery = `
      SELECT COUNT(*) as failed_count
      FROM login_attempts 
      WHERE email = $1 AND success = false 
      AND attempted_at > NOW() - INTERVAL '15 minutes'
    `;
    const result = await pool.query(recentAttemptsQuery, [email]);
    return parseInt(result.rows[0].failed_count) >= 5;
  }

  async logLoginAttempt(email: string, success: boolean, clientInfo: any, failureReason?: string): Promise<void> {
    try {
      await pool.query(
        `INSERT INTO login_attempts (email, ip_address, user_agent, success, failure_reason, attempted_at)
         VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)`,
        [email, clientInfo.ip, clientInfo.userAgent, success, failureReason || null]
      );
    } catch (error) {
      console.error('Failed to log login attempt:', error);
    }
  }

  async updateUserLastLogin(userId: string, ip: string): Promise<void> {
    await pool.query(
      `UPDATE users SET 
       last_login = CURRENT_TIMESTAMP, 
       last_ip = $1, 
       login_attempts = 0, 
       locked_until = NULL
       WHERE id = $2`,
      [ip, userId]
    );
  }

  async createUser(userData: {
    email: string;
    password: string;
    firstName: string;
    lastName: string;
    phone?: string;
    dateOfBirth?: Date;
  }): Promise<User> {
    const passwordHash = await this.hashPassword(userData.password);
    
    const client = await pool.connect();
    
    try {
      await client.query('BEGIN');

      const userResult = await client.query(
        `INSERT INTO users (
          email, phone, password_hash, first_name, last_name, date_of_birth,
          email_verified, phone_verified, is_active, account_type
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING *`,
        [
          userData.email, 
          userData.phone || null, 
          passwordHash, 
          userData.firstName, 
          userData.lastName, 
          userData.dateOfBirth || null,
          false, 
          false, 
          true, 
          'player'
        ]
      );

      const user = userResult.rows[0];

      // Insert user preferences
      await client.query(
        `INSERT INTO user_preferences (
          user_id, skill_level, notification_settings, privacy_settings
        ) VALUES ($1, $2, $3, $4)`,
        [
          user.id, 
          'beginner',
          JSON.stringify({
            email: true,
            push: true,
            sms: false,
            marketing: false
          }),
          JSON.stringify({
            profileVisibility: 'public',
            showEmail: false,
            showPhone: false
          })
        ]
      );

      await client.query('COMMIT');
      return user;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }
}
