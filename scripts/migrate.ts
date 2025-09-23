// Database migration script for Railway deployment
import { Pool } from 'pg';
import fs from 'fs';
import path from 'path';

async function runMigration() {
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
  });

  try {
    console.log('🔄 Starting database migration...');
    
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
