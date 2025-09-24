// Database migration script for Railway deployment
import { Pool } from 'pg';
import fs from 'fs';
import path from 'path';

async function runMigration() {
  // Wait for database to be ready
  console.log('⏳ Waiting for database connection...');
  await new Promise(resolve => setTimeout(resolve, 5000));

  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    max: 1,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
  });

  try {
    console.log('🔄 Starting database migration...');
    console.log('🔗 Database URL:', process.env.DATABASE_URL ? 'Set' : 'Not set');
    
    // Test connection first
    await pool.query('SELECT 1');
    console.log('✅ Database connection successful');
    
    // Check if tables already exist
    const existingTables = await pool.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public'
    `);
    
    if (existingTables.rows.length > 0) {
      console.log('✅ Tables already exist, skipping migration');
      console.log('📋 Existing tables:', existingTables.rows.map(row => row.table_name));
      return;
    }
    
    // Read the init.sql file
    const initSqlPath = path.join(process.cwd(), 'database/init.sql');
    console.log('📁 Looking for SQL file at:', initSqlPath);
    
    if (!fs.existsSync(initSqlPath)) {
      throw new Error(`SQL file not found at: ${initSqlPath}`);
    }
    
    const initSql = fs.readFileSync(initSqlPath, 'utf8');
    console.log('📄 SQL file loaded successfully');
    
    // Execute the SQL
    await pool.query(initSql);
    
    console.log('✅ Database migration completed successfully!');
    
    // Verify tables were created
    const result = await pool.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public'
    `);
    
    console.log('📋 Created tables:', result.rows.map(row => row.table_name));
    
  } catch (error) {
    console.error('❌ Migration failed:', error);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

runMigration();
