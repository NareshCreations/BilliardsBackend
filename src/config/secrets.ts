// Secret management configuration using Doppler
// This file handles loading secrets from Doppler in production
// Falls back to environment variables in development

import dotenv from 'dotenv';

// Load environment variables for development
if (process.env.NODE_ENV !== 'production') {
  dotenv.config();
}

// Secret configuration interface
export interface SecretConfig {
  // Database secrets
  DB_HOST: string;
  DB_PORT: string;
  DB_NAME: string;
  DB_USER: string;
  DB_PASSWORD: string;
  DATABASE_URL: string;
  
  // JWT secrets
  JWT_SECRET: string;
  
  // Redis secrets
  REDIS_URL: string;
  
  // Application secrets
  NODE_ENV: string;
  PORT: string;
}

// Load secrets from Doppler or environment variables
const loadSecrets = (): SecretConfig => {
  // In production, Doppler injects secrets as environment variables
  // In development, we use .env file
  
  const requiredSecrets = [
    'DB_HOST', 'DB_PORT', 'DB_NAME', 'DB_USER', 'DB_PASSWORD',
    'DATABASE_URL', 'JWT_SECRET', 'REDIS_URL', 'NODE_ENV', 'PORT'
  ];
  
  const missingSecrets: string[] = [];
  
  const secrets: Partial<SecretConfig> = {};
  
  for (const secret of requiredSecrets) {
    const value = process.env[secret];
    if (!value) {
      missingSecrets.push(secret);
    } else {
      secrets[secret as keyof SecretConfig] = value;
    }
  }
  
  if (missingSecrets.length > 0) {
    throw new Error(`Missing required secrets: ${missingSecrets.join(', ')}`);
  }
  
  return secrets as SecretConfig;
};

// Export the loaded secrets
export const secrets = loadSecrets();

// Validation function
export const validateSecrets = (): boolean => {
  try {
    loadSecrets();
    return true;
  } catch (error) {
    console.error('Secret validation failed:', error);
    return false;
  }
};

// Log secret status (without exposing values)
export const logSecretStatus = (): void => {
  console.log('🔐 Secret Management Status:');
  console.log(`   Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`   Database: ${process.env.DB_HOST}:${process.env.DB_PORT}/${process.env.DB_NAME}`);
  console.log(`   Redis: ${process.env.REDIS_URL ? 'Configured' : 'Not configured'}`);
  console.log(`   JWT Secret: ${process.env.JWT_SECRET ? 'Configured' : 'Missing'}`);
  console.log(`   Port: ${process.env.PORT || '3001'}`);
};
