-- Scam Check PK Pro: database tables. Run once in the D1 console.
CREATE TABLE IF NOT EXISTS codes (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  code_hash     TEXT NOT NULL UNIQUE,
  plan          TEXT NOT NULL CHECK (plan IN ('pro','business')),
  label         TEXT NOT NULL,
  issued_at     INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,
  max_devices   INTEGER NOT NULL,
  monthly_limit INTEGER NOT NULL,
  status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
  replaced_by   INTEGER
);
CREATE TABLE IF NOT EXISTS devices (
  code_id     INTEGER NOT NULL,
  device_hash TEXT NOT NULL,
  first_seen  INTEGER NOT NULL,
  PRIMARY KEY (code_id, device_hash)
);
CREATE TABLE IF NOT EXISTS usage (
  code_id INTEGER PRIMARY KEY,
  count   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS trials (
  device_hash TEXT PRIMARY KEY,
  used        INTEGER NOT NULL DEFAULT 0,
  first_seen  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS daily_ai (
  day   TEXT PRIMARY KEY,
  count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS rate_limits (
  key          TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  count        INTEGER NOT NULL
);
