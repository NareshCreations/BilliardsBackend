import { DataSource } from 'typeorm';
import { User } from '../entities/auth/User.entity';
import { UserSession } from '../entities/auth/UserSession.entity';
import { LoginAttempt } from '../entities/auth/LoginAttempt.entity';
import { secrets } from './secrets';

export const AppDataSource = new DataSource({
  type: 'postgres',
  url: secrets.DATABASE_URL,
  entities: [
    User,
    UserSession,
    LoginAttempt
  ],
  synchronize: false, // Set to false in production
  logging: process.env.NODE_ENV === 'development',
  migrations: ['src/migrations/*.ts'],
  subscribers: ['src/subscribers/*.ts'],
});

// Initialize the data source
export const initializeDatabase = async () => {
  try {
    if (!AppDataSource.isInitialized) {
      await AppDataSource.initialize();
      console.log('✅ Database connection established');
    } else {
      console.log('✅ Database already initialized');
    }
  } catch (error) {
    console.error('❌ Database connection failed:', error);
    // Don't throw error, let server continue without database
    return false;
  }
  return true;
};
