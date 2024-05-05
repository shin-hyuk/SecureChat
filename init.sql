-- Use the specified database (Replace 'chatdb' with your actual database name if different)
USE chatdb;

-- Drop tables if they already exist (to avoid conflicts during development/testing)
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS users;

-- Create 'users' table
CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL, -- Passwords will be stored as bcrypt hashes
    security_question VARCHAR(255) NOT NULL,
    security_answer VARCHAR(255) NOT NULL,
    public_key VARCHAR(2048), -- ECDH public key for secure key exchange
    iv VARBINARY(32), -- For AES CBC mode encryption of user info (optional, based on your security design)
    totp_secret VARCHAR(16) NOT NULL,
    memorized_secret VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create 'messages' table
CREATE TABLE messages (
    message_id INT AUTO_INCREMENT PRIMARY KEY,
    sender_id INT NOT NULL,
    receiver_id INT NOT NULL,
    ciphertext TEXT NOT NULL, -- Storing encrypted message content
    iv TEXT NOT NULL, -- Initialization Vector for AES GCM mode encryption
    hmac TEXT NOT NULL, -- HMAC signature to ensure message integrity
    aad TEXT NOT NULL, -- Additional Authenticated Data
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users(user_id),
    FOREIGN KEY (receiver_id) REFERENCES users(user_id)
);

