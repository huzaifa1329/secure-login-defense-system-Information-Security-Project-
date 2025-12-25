CREATE DATABASE login_security;
USE login_security;


DROP TABLE users;

CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    failed_attempts INT DEFAULT 0,
    locked_until BIGINT DEFAULT NULL,
    consecutive_locks INT DEFAULT 0,  -- NEW COLUMN
	otp VARCHAR(6),
    otp_expiry BIGINT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
