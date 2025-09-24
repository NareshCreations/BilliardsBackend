// Authentication constants
export const AUTH_CONSTANTS = {
  JWT_EXPIRES_IN: '15m',
  JWT_REFRESH_EXPIRES_IN: '7d',
  PASSWORD_MIN_LENGTH: 8,
  PASSWORD_MAX_LENGTH: 128,
  MAX_LOGIN_ATTEMPTS: 5,
  LOCKOUT_TIME_MINUTES: 15,
  REFRESH_TOKEN_LENGTH: 64,
  RESET_TOKEN_LENGTH: 32,
  VERIFICATION_CODE_LENGTH: 6,
  VERIFICATION_CODE_EXPIRES_MINUTES: 10,
  RESET_TOKEN_EXPIRES_HOURS: 1
} as const;

// Database constants
export const DB_CONSTANTS = {
  MAX_CONNECTIONS: 20,
  MIN_CONNECTIONS: 5,
  CONNECTION_TIMEOUT: 30000,
  IDLE_TIMEOUT: 30000,
  QUERY_TIMEOUT: 60000
} as const;

// API constants
export const API_CONSTANTS = {
  DEFAULT_PAGE_SIZE: 20,
  MAX_PAGE_SIZE: 100,
  RATE_LIMIT_WINDOW_MS: 15 * 60 * 1000, // 15 minutes
  RATE_LIMIT_MAX_REQUESTS: 100,
  REQUEST_TIMEOUT: 30000 // 30 seconds
} as const;

// File upload constants
export const FILE_CONSTANTS = {
  MAX_FILE_SIZE: 5 * 1024 * 1024, // 5MB
  ALLOWED_IMAGE_TYPES: ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
  ALLOWED_DOCUMENT_TYPES: ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']
} as const;

// Game constants
export const GAME_CONSTANTS = {
  MAX_PLAYERS_PER_ROOM: 8,
  MIN_PLAYERS_TO_START: 2,
  GAME_TIMEOUT_MINUTES: 30,
  MAX_GAME_DURATION_HOURS: 2,
  DEFAULT_BALL_COUNT: 15
} as const;

// Error messages
export const ERROR_MESSAGES = {
  // Authentication errors
  INVALID_CREDENTIALS: 'Invalid email or password',
  USER_NOT_FOUND: 'User not found',
  USER_ALREADY_EXISTS: 'User with this email already exists',
  ACCOUNT_LOCKED: 'Account is temporarily locked due to too many failed login attempts',
  INVALID_TOKEN: 'Invalid or expired token',
  TOKEN_EXPIRED: 'Token has expired',
  REFRESH_TOKEN_INVALID: 'Invalid refresh token',
  PASSWORD_TOO_WEAK: 'Password does not meet security requirements',
  
  // Validation errors
  VALIDATION_FAILED: 'Validation failed',
  REQUIRED_FIELD_MISSING: 'Required field is missing',
  INVALID_EMAIL_FORMAT: 'Invalid email format',
  INVALID_PHONE_FORMAT: 'Invalid phone number format',
  
  // Database errors
  DATABASE_CONNECTION_FAILED: 'Database connection failed',
  QUERY_EXECUTION_FAILED: 'Database query execution failed',
  RECORD_NOT_FOUND: 'Record not found',
  DUPLICATE_ENTRY: 'Duplicate entry found',
  
  // General errors
  INTERNAL_SERVER_ERROR: 'Internal server error',
  SERVICE_UNAVAILABLE: 'Service temporarily unavailable',
  FORBIDDEN_ACCESS: 'Access forbidden',
  UNAUTHORIZED_ACCESS: 'Unauthorized access'
} as const;

// Success messages
export const SUCCESS_MESSAGES = {
  USER_REGISTERED: 'User registered successfully',
  USER_LOGGED_IN: 'User logged in successfully',
  USER_LOGGED_OUT: 'User logged out successfully',
  PASSWORD_CHANGED: 'Password changed successfully',
  PASSWORD_RESET_SENT: 'Password reset email sent',
  PASSWORD_RESET_SUCCESS: 'Password reset successfully',
  EMAIL_VERIFIED: 'Email verified successfully',
  PHONE_VERIFIED: 'Phone number verified successfully',
  PROFILE_UPDATED: 'Profile updated successfully',
  ACCOUNT_DELETED: 'Account deleted successfully'
} as const;
