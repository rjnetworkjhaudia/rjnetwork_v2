-- RJ NETWORK V2.4 migration for an EXISTING V2.3 D1 database.
-- Run this ONCE against the existing database. Do not run repeatedly.

ALTER TABLE customers ADD COLUMN password_hash TEXT;
ALTER TABLE customers ADD COLUMN password_salt TEXT;
ALTER TABLE customers ADD COLUMN password_updated_at TEXT;

CREATE TABLE IF NOT EXISTS customer_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_id INTEGER NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_customer_sessions_token ON customer_sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_customer_sessions_customer ON customer_sessions(customer_id);
CREATE INDEX IF NOT EXISTS idx_customer_sessions_expiry ON customer_sessions(expires_at);
