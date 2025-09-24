import { Repository } from 'typeorm';
import { AppDataSource } from '../../../config/orm';
import { UserSession } from '../../../entities/auth/UserSession.entity';
import { ISessionRepository } from '../../interfaces/auth/ISessionRepository';

export class SessionRepository implements ISessionRepository {
  private sessionRepository: Repository<UserSession>;

  constructor() {
    this.sessionRepository = AppDataSource.getRepository(UserSession);
  }

  async createSession(sessionData: Partial<UserSession>): Promise<UserSession> {
    try {
      const session = this.sessionRepository.create(sessionData);
      return await this.sessionRepository.save(session);
    } catch (error) {
      throw new Error(`Failed to create session: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async findSessionByRefreshToken(refreshTokenHash: string): Promise<UserSession | null> {
    try {
      return await this.sessionRepository.findOne({
        where: { refreshTokenHash, isActive: true },
        relations: ['user']
      });
    } catch (error) {
      throw new Error(`Failed to find session by refresh token: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async updateSessionLastUsed(sessionId: string, ip: string, userAgent: string): Promise<void> {
    try {
      await this.sessionRepository.update(sessionId, {
        lastUsedAt: new Date(),
        ipAddress: ip,
        userAgent: userAgent
      });
    } catch (error) {
      throw new Error(`Failed to update session last used: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async deactivateSession(sessionId: string): Promise<void> {
    try {
      await this.sessionRepository.update(sessionId, {
        isActive: false,
        lastUsedAt: new Date()
      });
    } catch (error) {
      throw new Error(`Failed to deactivate session: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async deactivateAllUserSessions(userId: string): Promise<void> {
    try {
      await this.sessionRepository.update(
        { userId, isActive: true },
        { isActive: false, lastUsedAt: new Date() }
      );
    } catch (error) {
      throw new Error(`Failed to deactivate all user sessions: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async findActiveUserSessions(userId: string): Promise<UserSession[]> {
    try {
      return await this.sessionRepository.find({
        where: { userId, isActive: true },
        order: { lastUsedAt: 'DESC' }
      });
    } catch (error) {
      throw new Error(`Failed to find active user sessions: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async cleanExpiredSessions(): Promise<number> {
    try {
      const result = await this.sessionRepository.update(
        { isActive: true },
        { isActive: false }
      );
      return result.affected || 0;
    } catch (error) {
      throw new Error(`Failed to clean expired sessions: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async findSessionById(sessionId: string): Promise<UserSession | null> {
    try {
      return await this.sessionRepository.findOne({
        where: { id: sessionId, isActive: true },
        relations: ['user']
      });
    } catch (error) {
      throw new Error(`Failed to find session by ID: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
}
