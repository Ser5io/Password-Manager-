-- Database Schema for Secure Password Manager

-- Users Table: Stores authentication data and KDF parameters
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    master_password_hash TEXT NOT NULL, -- bcrypt hash for server-side auth
    vault_salt TEXT NOT NULL,           -- Base64 salt for PBKDF2 key derivation
    kdf_iterations INTEGER NOT NULL,    -- Number of PBKDF2 iterations
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Vault Items Table: Stores encrypted item data
CREATE TABLE IF NOT EXISTS vault_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    -- The following fields are stored as JSON-serialized, then AES-256-GCM encrypted strings
    -- encapsulated in a "package" containing nonce and ciphertext.
    encrypted_data TEXT NOT NULL, 
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Security Logs for auditing
CREATE TABLE IF NOT EXISTS security_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL, -- e.g., "LOGIN_SUCCESS", "FAILED_LOGIN", "EXPORT_VAULT"
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
