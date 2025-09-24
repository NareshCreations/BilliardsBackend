import { Repository, MoreThan } from 'typeorm';
import { AppDataSource } from '../../../config/orm';
import { LoginAttempt } from '../../../entities/auth/LoginAttempt.entity';
import { ILoginAttemptRepository } from '../../interfaces/auth/ILoginAttemptRepository';

export class LoginAttemptRepository implements ILoginAttemptRepository {
  private repository: Repository<LoginAttempt>;

  constructor() {
    this.repository = AppDataSource.getRepository(LoginAttempt);
  }

  async logLoginAttempt(attemptData: Partial<LoginAttempt>): Promise<LoginAttempt> {
    try {
      const attempt = this.repository.create(attemptData);
      return await this.repository.save(attempt);
    } catch (error) {
      throw new Error(`Failed to log login attempt: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async getRecentFailedAttempts(email: string, minutes: number): Promise<number> {
    try {
      const cutoffTime = new Date(Date.now() - minutes * 60 * 1000);
      return await this.repository.count({
        where: {
          email,
          success: false,
          attemptedAt: MoreThan(cutoffTime)
        }
      });
    } catch (error) {
      throw new Error(`Failed to get recent failed attempts: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async getRecentAttemptsByIP(ip: string, minutes: number): Promise<number> {
    try {
      const cutoffTime = new Date(Date.now() - minutes * 60 * 1000);
      return await this.repository.count({
        where: {
          ipAddress: ip,
          success: false,
          attemptedAt: MoreThan(cutoffTime)
        }
      });
    } catch (error) {
      throw new Error(`Failed to get recent attempts by IP: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async cleanOldAttempts(daysOld: number): Promise<number> {
    try {
      const cutoffDate = new Date(Date.now() - daysOld * 24 * 60 * 60 * 1000);
      const result = await this.repository.delete({
        attemptedAt: MoreThan(cutoffDate)
      });
      return result.affected || 0;
    } catch (error) {
      throw new Error(`Failed to clean old attempts: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
}
