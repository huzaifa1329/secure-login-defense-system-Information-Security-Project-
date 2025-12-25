-- Create the database
CREATE DATABASE IF NOT EXISTS login_security;

-- Use the database
USE login_security;

-- Create the users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    failed_attempts INT DEFAULT 0,
    locked_until BIGINT DEFAULT NULL,
    consecutive_locks INT DEFAULT 0,
    otp VARCHAR(10) DEFAULT NULL,
    otp_expiry BIGINT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Optional: Insert a test user (remove in production)
-- INSERT INTO users (username, email, password_hash) VALUES ('testuser', 'test@example.com', SHA2('password', 256));
