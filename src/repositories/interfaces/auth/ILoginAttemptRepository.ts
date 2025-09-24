import { LoginAttempt } from '../../../entities/auth/LoginAttempt.entity';

export interface ILoginAttemptRepository {
  logLoginAttempt(attemptData: Partial<LoginAttempt>): Promise<LoginAttempt>;
  getRecentFailedAttempts(email: string, minutes: number): Promise<number>;
  getRecentAttemptsByIP(ip: string, minutes: number): Promise<number>;
  cleanOldAttempts(daysOld: number): Promise<number>;
}
