-- Billiards Platform Database Initialization
-- This script runs when the PostgreSQL container starts for the first time

-- Create the main database (already created by POSTGRES_DB)
-- \c billiards_platform;

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Users table with security features (updated to match TypeORM entities)
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    phone VARCHAR(20) UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    date_of_birth DATE,
    email_verified BOOLEAN DEFAULT FALSE,
    phone_verified BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    is_premium BOOLEAN DEFAULT FALSE,
    account_type VARCHAR(20) DEFAULT 'player', -- player, admin
    last_login TIMESTAMP,
    last_ip INET,
    login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP,
    password_reset_token VARCHAR(255),
    password_reset_expires TIMESTAMP,
    email_verification_token VARCHAR(255),
    email_verification_expires TIMESTAMP,
    phone_verification_code VARCHAR(6),
    password_changed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- User sessions table
CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash VARCHAR(255) NOT NULL,
    device_info JSONB,
    ip_address INET,
    user_agent TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMP NOT NULL,
    last_used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Login attempts table
CREATE TABLE IF NOT EXISTS login_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255),
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN,
    failure_reason VARCHAR(100),
    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- User preferences table
CREATE TABLE IF NOT EXISTS user_preferences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    skill_level VARCHAR(20) DEFAULT 'beginner',
    bio TEXT,
    preferred_game_types JSONB,
    notification_settings JSONB DEFAULT '{"email": true, "sms": false, "push": true}',
    privacy_settings JSONB DEFAULT '{"profile_visible": true, "stats_visible": true}',
    theme VARCHAR(20) DEFAULT 'light',
    language VARCHAR(10) DEFAULT 'en',
    timezone VARCHAR(50) DEFAULT 'UTC',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Bars/Organizations table
CREATE TABLE IF NOT EXISTS bars (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    address TEXT NOT NULL,
    city VARCHAR(100) NOT NULL,
    state VARCHAR(100),
    country VARCHAR(100) NOT NULL,
    postal_code VARCHAR(20),
    phone VARCHAR(20),
    email VARCHAR(255),
    website VARCHAR(500),
    rating DECIMAL(3,2) DEFAULT 0.0,
    facilities JSONB,
    operating_hours JSONB,
    description TEXT,
    images JSONB,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Competitions table
CREATE TABLE IF NOT EXISTS competitions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    bar_id UUID REFERENCES bars(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    game_type VARCHAR(50) NOT NULL,
    entry_fee DECIMAL(10,2) NOT NULL,
    prize_pool DECIMAL(10,2) NOT NULL,
    max_participants INTEGER,
    current_participants INTEGER DEFAULT 0,
    current_round INTEGER DEFAULT 1,
    total_rounds INTEGER NOT NULL,
    status VARCHAR(20) DEFAULT 'upcoming',
    start_date TIMESTAMP NOT NULL,
    end_date TIMESTAMP,
    rules JSONB,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Matches table
CREATE TABLE IF NOT EXISTS matches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    competition_id UUID REFERENCES competitions(id) ON DELETE CASCADE,
    round_number INTEGER NOT NULL,
    table_number INTEGER NOT NULL,
    status VARCHAR(20) DEFAULT 'scheduled',
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    winner_id UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Match participants table
CREATE TABLE IF NOT EXISTS match_participants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    match_id UUID REFERENCES matches(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    score INTEGER DEFAULT 0,
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Competition entries table
CREATE TABLE IF NOT EXISTS competition_entries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    competition_id UUID REFERENCES competitions(id) ON DELETE CASCADE,
    entry_fee DECIMAL(10,2) NOT NULL,
    payment_status VARCHAR(20) DEFAULT 'pending',
    payment_method VARCHAR(50),
    payment_reference VARCHAR(255),
    entry_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Transactions table
CREATE TABLE IF NOT EXISTS transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    amount DECIMAL(10,2) NOT NULL,
    type VARCHAR(50) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    payment_method VARCHAR(50),
    payment_reference VARCHAR(255),
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Match events table
CREATE TABLE IF NOT EXISTS match_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    match_id UUID REFERENCES matches(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id),
    event_type VARCHAR(50) NOT NULL,
    data JSONB,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone);
CREATE INDEX IF NOT EXISTS idx_users_last_login ON users(last_login);
CREATE INDEX IF NOT EXISTS idx_users_account_type ON users(account_type);
CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active);

CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_refresh_token ON user_sessions(refresh_token_hash);
CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at ON user_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_user_sessions_ip ON user_sessions(ip_address);
CREATE INDEX IF NOT EXISTS idx_user_sessions_active ON user_sessions(is_active, expires_at);

CREATE INDEX IF NOT EXISTS idx_login_attempts_email_time ON login_attempts(email, attempted_at);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time ON login_attempts(ip_address, attempted_at);
CREATE INDEX IF NOT EXISTS idx_login_attempts_success ON login_attempts(success, attempted_at);

CREATE INDEX IF NOT EXISTS idx_user_preferences_user_id ON user_preferences(user_id);

CREATE INDEX IF NOT EXISTS idx_bars_city ON bars(city);
CREATE INDEX IF NOT EXISTS idx_bars_country ON bars(country);
CREATE INDEX IF NOT EXISTS idx_bars_is_active ON bars(is_active);

CREATE INDEX IF NOT EXISTS idx_competitions_bar_id ON competitions(bar_id);
CREATE INDEX IF NOT EXISTS idx_competitions_status ON competitions(status);
CREATE INDEX IF NOT EXISTS idx_competitions_start_date ON competitions(start_date);

CREATE INDEX IF NOT EXISTS idx_matches_competition_id ON matches(competition_id);
CREATE INDEX IF NOT EXISTS idx_matches_status ON matches(status);

CREATE INDEX IF NOT EXISTS idx_match_participants_match_id ON match_participants(match_id);
CREATE INDEX IF NOT EXISTS idx_match_participants_user_id ON match_participants(user_id);

CREATE INDEX IF NOT EXISTS idx_competition_entries_user_id ON competition_entries(user_id);
CREATE INDEX IF NOT EXISTS idx_competition_entries_competition_id ON competition_entries(competition_id);

CREATE INDEX IF NOT EXISTS idx_transactions_user_id ON transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_transactions_type ON transactions(type);
CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status);

CREATE INDEX IF NOT EXISTS idx_match_events_match_id ON match_events(match_id);
CREATE INDEX IF NOT EXISTS idx_match_events_user_id ON match_events(user_id);
CREATE INDEX IF NOT EXISTS idx_match_events_event_type ON match_events(event_type);

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_sessions_updated_at BEFORE UPDATE ON user_sessions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_preferences_updated_at BEFORE UPDATE ON user_preferences
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_bars_updated_at BEFORE UPDATE ON bars
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_competitions_updated_at BEFORE UPDATE ON competitions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert sample data
INSERT INTO users (email, password_hash, first_name, last_name, phone, account_type, is_active, email_verified) VALUES
('admin@billiards.com', '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/8Qz8K2O', 'Admin', 'User', '+1234567890', 'admin', true, true),
('john.doe@example.com', '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/8Qz8K2O', 'John', 'Doe', '+1234567891', 'player', true, true),
('jane.smith@example.com', '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/8Qz8K2O', 'Jane', 'Smith', '+1234567892', 'player', true, false);

-- Insert user preferences for sample users
INSERT INTO user_preferences (user_id, skill_level, bio, notification_settings, privacy_settings) 
SELECT id, 'intermediate', 'Passionate billiards player', 
       '{"email": true, "sms": false, "push": true}',
       '{"profile_visible": true, "stats_visible": true}'
FROM users WHERE email IN ('admin@billiards.com', 'john.doe@example.com', 'jane.smith@example.com');

-- Insert sample bars
INSERT INTO bars (name, address, city, state, country, postal_code, phone, email, rating, facilities, operating_hours, description) VALUES
('The Cue Ball', '123 Main Street', 'New York', 'NY', 'USA', '10001', '+1-555-0123', 'info@cueball.com', 4.5, 
 '{"tables": 12, "food": true, "bar": true, "parking": true}', 
 '{"monday": "9:00-23:00", "tuesday": "9:00-23:00", "wednesday": "9:00-23:00", "thursday": "9:00-23:00", "friday": "9:00-01:00", "saturday": "9:00-01:00", "sunday": "10:00-22:00"}',
 'Premier billiards hall in downtown Manhattan'),
('Pool Palace', '456 Oak Avenue', 'Los Angeles', 'CA', 'USA', '90210', '+1-555-0456', 'contact@poolpalace.com', 4.2,
 '{"tables": 8, "food": true, "bar": false, "parking": true}',
 '{"monday": "10:00-22:00", "tuesday": "10:00-22:00", "wednesday": "10:00-22:00", "thursday": "10:00-22:00", "friday": "10:00-24:00", "saturday": "10:00-24:00", "sunday": "12:00-22:00"}',
 'Family-friendly pool hall with great atmosphere');

-- Insert sample competitions
INSERT INTO competitions (bar_id, title, description, game_type, entry_fee, prize_pool, max_participants, total_rounds, start_date, end_date, created_by) 
SELECT b.id, 'Weekly 8-Ball Tournament', 'Weekly 8-ball tournament with cash prizes', '8-ball', 25.00, 500.00, 32, 5, 
       CURRENT_TIMESTAMP + INTERVAL '7 days', CURRENT_TIMESTAMP + INTERVAL '7 days' + INTERVAL '4 hours',
       u.id
FROM bars b, users u 
WHERE b.name = 'The Cue Ball' AND u.email = 'admin@billiards.com';

COMMIT;
