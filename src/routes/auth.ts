import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import pool from '../config/database';
import { secrets } from '../config/secrets';

const router = express.Router();

// Helper function to get client info
const getClientInfo = (req: express.Request) => {
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
};

// Helper function to log login attempts
const logLoginAttempt = async (email: string, success: boolean, clientInfo: any, failureReason?: string) => {
  try {
    await pool.query(
      `INSERT INTO login_attempts (email, ip_address, user_agent, success, failure_reason, attempted_at)
       VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)`,
      [email, clientInfo.ip, clientInfo.userAgent, success, failureReason || null]
    );
  } catch (error) {
    console.error('Failed to log login attempt:', error);
  }
};

// Helper function to create user session
const createUserSession = async (userId: string, clientInfo: any) => {
  const refreshToken = crypto.randomBytes(32).toString('hex');
  const refreshTokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

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
};

// Login endpoint with session management
router.post('/login', async (req, res) => {
  const clientInfo = getClientInfo(req);
  
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      await logLoginAttempt(email || 'unknown', false, clientInfo, 'missing_credentials');
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }

    // Check for recent failed attempts (brute force protection)
    const recentAttemptsQuery = `
      SELECT COUNT(*) as failed_count
      FROM login_attempts 
      WHERE email = $1 AND success = false 
      AND attempted_at > NOW() - INTERVAL '15 minutes'
    `;
    const recentAttempts = await pool.query(recentAttemptsQuery, [email]);
    
    if (parseInt(recentAttempts.rows[0].failed_count) >= 5) {
      await logLoginAttempt(email, false, clientInfo, 'rate_limited');
      return res.status(429).json({
        success: false,
        message: 'Too many failed attempts. Please try again in 15 minutes.'
      });
    }

    // Find user by email with new table structure
    const userQuery = `
      SELECT u.*, up.skill_level, up.bio, up.notification_settings, up.privacy_settings
      FROM users u
      LEFT JOIN user_preferences up ON u.id = up.user_id
      WHERE u.email = $1 AND u.is_active = true
    `;
    
    const userResult = await pool.query(userQuery, [email]);
    
    if (userResult.rows.length === 0) {
      await logLoginAttempt(email, false, clientInfo, 'user_not_found');
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    const user = userResult.rows[0];

    // Check if account is locked
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      await logLoginAttempt(email, false, clientInfo, 'account_locked');
      return res.status(423).json({
        success: false,
        message: 'Account is temporarily locked. Please try again later.'
      });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!isValidPassword) {
      // Update failed login attempts
      await pool.query(
        `UPDATE users SET login_attempts = login_attempts + 1,
         locked_until = CASE WHEN login_attempts >= 4 THEN NOW() + INTERVAL '30 minutes' ELSE NULL END
         WHERE id = $1`,
        [user.id]
      );
      
      await logLoginAttempt(email, false, clientInfo, 'invalid_password');
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    // Successful login - create session and update user
    const session = await createUserSession(user.id, clientInfo);
    
    // Update user last login info and reset failed attempts
    await pool.query(
      `UPDATE users SET 
       last_login = CURRENT_TIMESTAMP, 
       last_ip = $1, 
       login_attempts = 0, 
       locked_until = NULL
       WHERE id = $2`,
      [clientInfo.ip, user.id]
    );

    // Log successful login
    await logLoginAttempt(email, true, clientInfo);

    // Generate JWT access token
    const accessToken = jwt.sign(
      { 
        userId: user.id, 
        email: user.email,
        accountType: user.account_type || 'player',
        sessionId: session.sessionId
      },
      secrets.JWT_SECRET,
      { expiresIn: '15m' } // Short-lived access token
    );

    // Remove sensitive data from response
    delete user.password_hash;
    delete user.password_reset_token;
    delete user.email_verification_token;

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        accessToken,
        refreshToken: session.refreshToken,
        expiresAt: session.expiresAt,
        user: {
          id: user.id,
          email: user.email,
          firstName: user.first_name,
          lastName: user.last_name,
          emailVerified: user.email_verified,
          phoneVerified: user.phone_verified,
          isActive: user.is_active,
          isPremium: user.is_premium,
          accountType: user.account_type,
          lastLogin: user.last_login,
          profile: {
            skillLevel: user.skill_level,
            bio: user.bio,
            notificationSettings: user.notification_settings,
            privacySettings: user.privacy_settings
          }
        }
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    await logLoginAttempt(req.body.email || 'unknown', false, clientInfo, 'server_error');
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Refresh token endpoint
router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    const clientInfo = getClientInfo(req);

    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        message: 'Refresh token is required'
      });
    }

    // Hash the refresh token to compare with database
    const refreshTokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');

    // Find active session
    const sessionQuery = `
      SELECT us.*, u.email, u.account_type, u.is_active
      FROM user_sessions us
      JOIN users u ON us.user_id = u.id
      WHERE us.refresh_token_hash = $1 
      AND us.is_active = true 
      AND us.expires_at > CURRENT_TIMESTAMP
    `;
    
    const sessionResult = await pool.query(sessionQuery, [refreshTokenHash]);
    
    if (sessionResult.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'Invalid or expired refresh token'
      });
    }

    const session = sessionResult.rows[0];
    
    if (!session.is_active) {
      return res.status(401).json({
        success: false,
        message: 'Account is not active'
      });
    }

    // Update session last used time and IP
    await pool.query(
      `UPDATE user_sessions SET 
       last_used_at = CURRENT_TIMESTAMP,
       ip_address = $1,
       user_agent = $2
       WHERE id = $3`,
      [clientInfo.ip, clientInfo.userAgent, session.id]
    );

    // Generate new access token
    const accessToken = jwt.sign(
      { 
        userId: session.user_id, 
        email: session.email,
        accountType: session.account_type || 'player',
        sessionId: session.id
      },
      secrets.JWT_SECRET,
      { expiresIn: '15m' }
    );

    res.json({
      success: true,
      message: 'Token refreshed successfully',
      data: {
        accessToken,
        expiresIn: '15m'
      }
    });

  } catch (error) {
    console.error('Refresh token error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Logout endpoint
router.post('/logout', async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        message: 'Refresh token is required'
      });
    }

    // Hash the refresh token to find the session
    const refreshTokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');

    // Deactivate the session
    await pool.query(
      `UPDATE user_sessions SET 
       is_active = false,
       last_used_at = CURRENT_TIMESTAMP
       WHERE refresh_token_hash = $1`,
      [refreshTokenHash]
    );

    res.json({
      success: true,
      message: 'Logged out successfully'
    });

  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Logout from all devices endpoint
router.post('/logout-all', async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        message: 'Refresh token is required'
      });
    }

    // Hash the refresh token to find the user
    const refreshTokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
    
    // First find the user ID from the session
    const sessionQuery = `
      SELECT user_id FROM user_sessions 
      WHERE refresh_token_hash = $1 AND is_active = true
    `;
    const sessionResult = await pool.query(sessionQuery, [refreshTokenHash]);
    
    if (sessionResult.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'Invalid session'
      });
    }

    const userId = sessionResult.rows[0].user_id;

    // Deactivate all sessions for this user
    await pool.query(
      `UPDATE user_sessions SET 
       is_active = false,
       last_used_at = CURRENT_TIMESTAMP
       WHERE user_id = $1 AND is_active = true`,
      [userId]
    );

    res.json({
      success: true,
      message: 'Logged out from all devices successfully'
    });

  } catch (error) {
    console.error('Logout all error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Get active sessions endpoint
router.get('/sessions', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'Authorization token required'
      });
    }

    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret') as any;
    
    // Get all active sessions for the user
    const sessionsQuery = `
      SELECT id, device_info, ip_address, user_agent, created_at, last_used_at, expires_at
      FROM user_sessions 
      WHERE user_id = $1 AND is_active = true AND expires_at > CURRENT_TIMESTAMP
      ORDER BY last_used_at DESC
    `;
    
    const sessionsResult = await pool.query(sessionsQuery, [decoded.userId]);
    
    res.json({
      success: true,
      data: {
        sessions: sessionsResult.rows.map(session => ({
          id: session.id,
          deviceInfo: session.device_info,
          ipAddress: session.ip_address,
          userAgent: session.user_agent,
          createdAt: session.created_at,
          lastUsedAt: session.last_used_at,
          expiresAt: session.expires_at,
          isCurrent: session.id === decoded.sessionId
        }))
      }
    });

  } catch (error) {
    console.error('Get sessions error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Test endpoint to debug request parsing
router.post('/test', (req, res) => {
  res.json({
    success: true,
    message: 'Test endpoint works',
    body: req.body,
    headers: req.headers,
    contentType: req.headers['content-type']
  });
});

// Simple Register endpoint - no sessions
router.post('/register', async (req, res) => {
  try {
    const { email, password, firstName, lastName, phone, dateOfBirth } = req.body;

    // Validate required fields
    if (!email || !password || !firstName || !lastName) {
      return res.status(400).json({
        success: false,
        message: 'Email, password, first name, and last name are required'
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: 'Please provide a valid email address'
      });
    }

    // Validate password strength
    if (password.length < 8) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 8 characters long'
      });
    }

    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        success: false,
        message: 'User with this email already exists'
      });
    }

    // Hash password
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Start transaction
    const client = await pool.connect();
    
    try {
      await client.query('BEGIN');

      // Insert user
      const userResult = await client.query(
        `INSERT INTO users (
          email, phone, password_hash, first_name, last_name, date_of_birth,
          email_verified, phone_verified, is_active, account_type
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING id, email, phone, first_name, last_name, date_of_birth, created_at`,
        [
          email, 
          phone || null, 
          passwordHash, 
          firstName, 
          lastName, 
          dateOfBirth || null,
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

      // Generate JWT token
      const accessToken = jwt.sign(
        { 
          userId: user.id, 
          email: user.email,
          accountType: 'player'
        },
        secrets.JWT_SECRET,
        { expiresIn: '24h' }
      );

      res.status(201).json({
        success: true,
        message: 'User registered successfully',
        data: {
          accessToken,
          user: {
            id: user.id,
            email: user.email,
            phone: user.phone,
            firstName: user.first_name,
            lastName: user.last_name,
            dateOfBirth: user.date_of_birth,
            emailVerified: false,
            phoneVerified: false,
            isActive: true,
            isPremium: false,
            accountType: 'player',
            createdAt: user.created_at,
            profile: {
              skillLevel: 'beginner'
            }
          }
        }
      });

    } catch (dbError) {
      await client.query('ROLLBACK');
      console.error('Database error:', dbError);
      res.status(500).json({
        success: false,
        message: 'Database error during registration'
      });
    } finally {
      client.release();
    }

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Forgot password endpoint
router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }

    // Find user
    const userResult = await pool.query(
      'SELECT id, email, first_name FROM users WHERE email = $1 AND is_active = true',
      [email]
    );

    // Always return success to prevent email enumeration
    if (userResult.rows.length === 0) {
      return res.json({
        success: true,
        message: 'If an account with that email exists, a password reset link has been sent'
      });
    }

    const user = userResult.rows[0];

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
    const resetExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    // Save reset token
    await pool.query(
      `UPDATE users SET 
       password_reset_token = $1, 
       password_reset_expires = $2 
       WHERE id = $3`,
      [resetTokenHash, resetExpires, user.id]
    );

    // In production, send email here
    console.log(`Password reset token for ${email}: ${resetToken}`);

    res.json({
      success: true,
      message: 'If an account with that email exists, a password reset link has been sent',
      // Remove this in production
      debug: {
        resetToken,
        userId: user.id
      }
    });

  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Reset password endpoint
router.post('/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({
        success: false,
        message: 'Token and new password are required'
      });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 8 characters long'
      });
    }

    // Hash the token to compare with database
    const resetTokenHash = crypto.createHash('sha256').update(token).digest('hex');

    // Find user with valid reset token
    const userResult = await pool.query(
      `SELECT id, email FROM users 
       WHERE password_reset_token = $1 
       AND password_reset_expires > CURRENT_TIMESTAMP 
       AND is_active = true`,
      [resetTokenHash]
    );

    if (userResult.rows.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired reset token'
      });
    }

    const user = userResult.rows[0];

    // Hash new password
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(newPassword, saltRounds);

    // Update password and clear reset token
    await pool.query(
      `UPDATE users SET 
       password_hash = $1,
       password_reset_token = NULL,
       password_reset_expires = NULL,
       password_changed_at = CURRENT_TIMESTAMP
       WHERE id = $2`,
      [passwordHash, user.id]
    );

    res.json({
      success: true,
      message: 'Password has been reset successfully'
    });

  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Verify email endpoint
router.post('/verify-email', async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({
        success: false,
        message: 'Verification token is required'
      });
    }

    // Find user with valid verification token
    const userResult = await pool.query(
      `SELECT id, email FROM users 
       WHERE email_verification_token = $1 
       AND email_verification_expires > CURRENT_TIMESTAMP 
       AND email_verified = false
       AND is_active = true`,
      [token]
    );

    if (userResult.rows.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired verification token'
      });
    }

    const user = userResult.rows[0];

    // Mark email as verified
    await pool.query(
      `UPDATE users SET 
       email_verified = true,
       email_verification_token = NULL,
       email_verification_expires = NULL
       WHERE id = $1`,
      [user.id]
    );

    res.json({
      success: true,
      message: 'Email verified successfully'
    });

  } catch (error) {
    console.error('Verify email error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Verify phone endpoint
router.post('/verify-phone', async (req, res) => {
  try {
    const { code, phone } = req.body;

    if (!code || !phone) {
      return res.status(400).json({
        success: false,
        message: 'Verification code and phone number are required'
      });
    }

    // Find user with matching phone and verification code
    const userResult = await pool.query(
      `SELECT id, phone FROM users 
       WHERE phone = $1 
       AND phone_verification_code = $2 
       AND phone_verified = false
       AND is_active = true`,
      [phone, code]
    );

    if (userResult.rows.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Invalid verification code or phone number'
      });
    }

    const user = userResult.rows[0];

    // Mark phone as verified
    await pool.query(
      `UPDATE users SET 
       phone_verified = true,
       phone_verification_code = NULL
       WHERE id = $1`,
      [user.id]
    );

    res.json({
      success: true,
      message: 'Phone number verified successfully'
    });

  } catch (error) {
    console.error('Verify phone error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Change password endpoint
router.post('/change-password', async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'Authorization token required'
      });
    }

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        message: 'Current password and new password are required'
      });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({
        success: false,
        message: 'New password must be at least 8 characters long'
      });
    }

    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret') as any;

    // Get user current password
    const userResult = await pool.query(
      'SELECT id, password_hash FROM users WHERE id = $1 AND is_active = true',
      [decoded.userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const user = userResult.rows[0];

    // Verify current password
    const isValidPassword = await bcrypt.compare(currentPassword, user.password_hash);
    if (!isValidPassword) {
      return res.status(400).json({
        success: false,
        message: 'Current password is incorrect'
      });
    }

    // Hash new password
    const saltRounds = 12;
    const newPasswordHash = await bcrypt.hash(newPassword, saltRounds);

    // Update password and invalidate all sessions
    await pool.query(
      `UPDATE users SET 
       password_hash = $1,
       password_changed_at = CURRENT_TIMESTAMP
       WHERE id = $2`,
      [newPasswordHash, user.id]
    );

    // Invalidate ALL active sessions for this user (security measure)
    await pool.query(
      `UPDATE user_sessions SET 
       is_active = false,
       last_used_at = CURRENT_TIMESTAMP
       WHERE user_id = $1 AND is_active = true`,
      [user.id]
    );

    // Create a new session for the current user (they just authenticated)
    const clientInfo = getClientInfo(req);
    const newSession = await createUserSession(user.id, clientInfo);

    // Generate new JWT access token with new session
    const newAccessToken = jwt.sign(
      { 
        userId: user.id, 
        email: decoded.email,
        accountType: decoded.accountType || 'player',
        sessionId: newSession.sessionId
      },
      secrets.JWT_SECRET,
      { expiresIn: '15m' }
    );

    res.json({
      success: true,
      message: 'Password changed successfully. All other sessions have been terminated.',
      data: {
        accessToken: newAccessToken,
        refreshToken: newSession.refreshToken,
        expiresAt: newSession.expiresAt,
        note: 'You have been issued a new token. Please update your stored credentials.'
      }
    });

  } catch (error) {
    if (error instanceof Error && error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        success: false,
        message: 'Invalid token'
      });
    }

    console.error('Change password error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Get user profile endpoint
router.get('/profile', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'No token provided'
      });
    }

    const decoded = jwt.verify(token, secrets.JWT_SECRET) as any;
    
    const userQuery = `
      SELECT u.*, up.first_name, up.last_name, up.skill_level, up.bio, up.avatar_url, up.date_of_birth
      FROM users u
      LEFT JOIN user_profiles up ON u.id = up.user_id
      WHERE u.id = $1 AND u.is_active = true
    `;
    
    const userResult = await pool.query(userQuery, [decoded.userId]);
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const user = userResult.rows[0];

    res.json({
      success: true,
      data: {
        user: {
          id: user.id,
          email: user.email,
          phone: user.phone,
          email_verified: user.email_verified,
          phone_verified: user.phone_verified,
          first_name: user.first_name,
          last_name: user.last_name,
          skill_level: user.skill_level,
          bio: user.bio,
          avatar_url: user.avatar_url,
          date_of_birth: user.date_of_birth,
          created_at: user.created_at
        }
      }
    });

  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

export default router;
