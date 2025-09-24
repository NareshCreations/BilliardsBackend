export interface JwtPayload {
  userId: string;
  email: string;
  accountType: string;
  iat?: number;
  exp?: number;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface DeviceInfo {
  browser: string;
  platform: string;
  mobile: boolean;
  os?: string;
  version?: string;
}

export interface LoginAttemptInfo {
  email: string;
  ipAddress: string;
  userAgent: string;
  success: boolean;
  failureReason?: string;
}

export interface SessionInfo {
  userId: string;
  deviceInfo: DeviceInfo;
  ipAddress: string;
  userAgent: string;
}

export type AccountType = 'player' | 'admin' | 'moderator';

export interface PasswordResetInfo {
  token: string;
  expiresAt: Date;
  userId: string;
}

export interface EmailVerificationInfo {
  token: string;
  expiresAt: Date;
  userId: string;
}

export interface PhoneVerificationInfo {
  code: string;
  expiresAt: Date;
  userId: string;
}
