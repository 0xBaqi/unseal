-- ==============================================================================
-- Unseal D1 Edge Relational Schema (0001_initial_schema.sql)
-- Multi-region ACID consistency for Spaces, Documents & Atomic Nonces
-- ==============================================================================

-- 1. SPACES: Replaces in-memory DEFAULT_SPACES & data/spaces.json
CREATE TABLE IF NOT EXISTS spaces (
  space_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  contract_id TEXT NOT NULL,
  required_token_id TEXT NOT NULL,
  issuer TEXT NOT NULL,
  is_public_demo INTEGER NOT NULL DEFAULT 0,
  secret_payload TEXT NOT NULL, -- JSON string
  enforce_expiry INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- 2. DOCUMENTS: Replaces SpaceObjectRegistry & data/documents.json
-- Explicit lifecycle states: 'PENDING_UPLOAD', 'COMMITTED', 'DELETING'
CREATE TABLE IF NOT EXISTS documents (
  space_id TEXT PRIMARY KEY,
  bucket TEXT NOT NULL,
  object_key TEXT NOT NULL,
  filename TEXT NOT NULL,
  size INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  mime_type TEXT NOT NULL DEFAULT 'application/pdf',
  uploaded_by TEXT NOT NULL,
  uploaded_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'COMMITTED',
  FOREIGN KEY (space_id) REFERENCES spaces(space_id) ON DELETE CASCADE
);

-- 3. CHALLENGES: Atomic single-use nonces replacing challenge.js in-memory Map
CREATE TABLE IF NOT EXISTS challenges (
  nonce_b64 TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  recipient TEXT NOT NULL,
  message TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER DEFAULT NULL
);

-- 4. ORPHAN RECONCILIATION: Compensating deletion tracking for failed metadata writes
CREATE TABLE IF NOT EXISTS orphan_reconciliation (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  bucket TEXT NOT NULL,
  object_key TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL,
  resolved_at TEXT DEFAULT NULL
);

-- Performance & Isolation Indexes
CREATE INDEX IF NOT EXISTS idx_spaces_issuer ON spaces(issuer);
CREATE INDEX IF NOT EXISTS idx_challenges_lookup ON challenges(nonce_b64, consumed_at, expires_at);
CREATE INDEX IF NOT EXISTS idx_challenges_account ON challenges(account_id);
