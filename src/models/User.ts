// src/models/User.ts
export interface User {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  passwordHash: string;
  emailVerified: boolean;
  phoneVerified: boolean;
  isActive: boolean;
  isPremium: boolean;
  accountType: 'player' | 'admin';
  lastLogin?: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface UserSession {
  id: string;
  userId: string;
  refreshTokenHash: string;
  deviceInfo: any;
  ipAddress: string;
  userAgent: string;
  isActive: boolean;
  expiresAt: Date;
  createdAt: Date;
  lastUsedAt: Date;
}
