import { UserSession } from '../../../entities/auth/UserSession.entity';

export interface ISessionRepository {
  createSession(sessionData: Partial<UserSession>): Promise<UserSession>;
  findSessionByRefreshToken(refreshTokenHash: string): Promise<UserSession | null>;
  updateSessionLastUsed(sessionId: string, ip: string, userAgent: string): Promise<void>;
  deactivateSession(sessionId: string): Promise<void>;
  deactivateAllUserSessions(userId: string): Promise<void>;
  findActiveUserSessions(userId: string): Promise<UserSession[]>;
  cleanExpiredSessions(): Promise<number>;
  findSessionById(sessionId: string): Promise<UserSession | null>;
}
