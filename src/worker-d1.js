/**
 * worker-d1.js — Cloudflare D1 Data Access Layer for Unseal.
 *
 * Implements strict ACID single-writer guarantees, atomic challenge consumption
 * to prevent replay attacks, and explicit document lifecycle management.
 */

import { randomBytes } from 'node:crypto';

export const DEFAULT_TTL_MS = 5 * 60 * 1000; // 5 minutes
export const NONCE_BYTES = 32;

export class D1DatabaseError extends Error {
  constructor(code, message, status = 500) {
    super(`${code}: ${message}`);
    this.name = 'D1DatabaseError';
    this.code = code;
    this.status = status;
  }
}

/**
 * Initializes D1 schema and seeds default spaces if empty.
 * @param {D1Database} db
 */
export async function initializeD1(db) {
  // 1. Ensure tables exist
  await db.exec(`
    CREATE TABLE IF NOT EXISTS spaces (
      space_id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      contract_id TEXT NOT NULL,
      required_token_id TEXT NOT NULL,
      issuer TEXT NOT NULL,
      is_public_demo INTEGER NOT NULL DEFAULT 0,
      secret_payload TEXT NOT NULL,
      enforce_expiry INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

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

    CREATE TABLE IF NOT EXISTS challenges (
      nonce_b64 TEXT PRIMARY KEY,
      account_id TEXT NOT NULL,
      recipient TEXT NOT NULL,
      message TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      consumed_at INTEGER DEFAULT NULL
    );

    CREATE TABLE IF NOT EXISTS orphan_reconciliation (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      bucket TEXT NOT NULL,
      object_key TEXT NOT NULL,
      reason TEXT NOT NULL,
      created_at TEXT NOT NULL,
      resolved_at TEXT DEFAULT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_spaces_issuer ON spaces(issuer);
    CREATE INDEX IF NOT EXISTS idx_challenges_lookup ON challenges(nonce_b64, consumed_at, expires_at);
    CREATE INDEX IF NOT EXISTS idx_challenges_account ON challenges(account_id);
  `);

  // 2. Seed initial demo spaces if empty
  const countRes = await db.prepare('SELECT COUNT(*) as count FROM spaces').first();
  if (countRes && countRes.count === 0) {
    const now = new Date().toISOString();
    const demoSpaces = [
      {
        spaceId: 'space-alpha',
        name: 'Unseal Alpha Demo Vault (Synthetic Testnet Space)',
        contractId: 'unseal-nft-55335700.testnet',
        requiredTokenId: 'pass-alpha-1',
        issuer: 'baronal.testnet',
        isPublicDemo: 1,
        secretPayload: JSON.stringify({
          message: 'Welcome to Unseal Alpha Demo Space. Access granted via verified NEP-171 NFT ownership.',
          timestamp: now,
          clearanceLevel: 'GATE_A3_VERIFIED',
        }),
        enforceExpiry: 1,
      },
      {
        spaceId: 'space-transfer',
        name: 'Unseal Transferable Demo Space',
        contractId: 'unseal-nft-55335700.testnet',
        requiredTokenId: 'pass-transfer-493545',
        issuer: 'baronal.testnet',
        isPublicDemo: 1,
        secretPayload: JSON.stringify({
          message: 'Welcome to Unseal Transfer Test Space. Access granted via transferred NEP-171 NFT pass.',
          timestamp: now,
          clearanceLevel: 'GATE_A3_TRANSFEREE_VERIFIED',
        }),
        enforceExpiry: 1,
      },
    ];

    const statements = demoSpaces.map((s) =>
      db.prepare(`
        INSERT INTO spaces (space_id, name, contract_id, required_token_id, issuer, is_public_demo, secret_payload, enforce_expiry, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        s.spaceId,
        s.name,
        s.contractId,
        s.requiredTokenId,
        s.issuer,
        s.isPublicDemo,
        s.secretPayload,
        s.enforceExpiry,
        now,
        now
      )
    );
    await db.batch(statements);
  }
}

// ── Atomic Challenge Nonce Operations ───────────────────────────────────────

/**
 * Issues a cryptographically random challenge and persists it in D1.
 */
export async function issueChallengeD1(db, { accountId, recipient, message, ttlMs = DEFAULT_TTL_MS }) {
  if (!accountId || typeof accountId !== 'string') throw new TypeError('accountId must be a non-empty string');
  if (!recipient || typeof recipient !== 'string') throw new TypeError('recipient must be a non-empty string');
  if (!message || typeof message !== 'string') throw new TypeError('message must be a non-empty string');

  const rawNonce = randomBytes(NONCE_BYTES);
  const nonceB64 = rawNonce.toString('base64');
  const expiresAt = Date.now() + ttlMs;

  await db.prepare(`
    INSERT INTO challenges (nonce_b64, account_id, recipient, message, expires_at, consumed_at)
    VALUES (?, ?, ?, ?, ?, NULL)
  `).bind(nonceB64, accountId, recipient, message, expiresAt).run();

  return { nonceB64, message, recipient, accountId, expiresAt };
}

/**
 * Consumes a challenge nonce atomically using conditional SQL UPDATE.
 * Prevents replay attacks and double-spending across concurrent edge requests.
 */
export async function consumeChallengeD1(db, { nonceB64, accountId, recipient }) {
  if (!nonceB64 || typeof nonceB64 !== 'string') throw new TypeError('nonceB64 must be a non-empty string');
  if (!accountId || typeof accountId !== 'string') throw new TypeError('accountId must be a non-empty string');
  if (!recipient || typeof recipient !== 'string') throw new TypeError('recipient must be a non-empty string');

  const now = Date.now();

  // ATOMIC CONDITIONAL UPDATE:
  // Only updates and returns row if:
  // 1. nonce exists
  // 2. account_id matches
  // 3. recipient matches
  // 4. consumed_at IS NULL (never consumed before)
  // 5. expires_at > now (has not expired)
  const result = await db.prepare(`
    UPDATE challenges
    SET consumed_at = ?
    WHERE nonce_b64 = ?
      AND account_id = ?
      AND recipient = ?
      AND consumed_at IS NULL
      AND expires_at > ?
    RETURNING nonce_b64, account_id, recipient, message, expires_at
  `).bind(now, nonceB64, accountId, recipient, now).first();

  if (!result) {
    // Determine specific reason for descriptive fail-closed error
    const check = await db.prepare(`
      SELECT account_id, recipient, expires_at, consumed_at
      FROM challenges
      WHERE nonce_b64 = ?
    `).bind(nonceB64).first();

    if (!check) {
      throw new D1DatabaseError('CHALLENGE_NOT_FOUND', 'Nonce is unknown or does not exist', 400);
    }
    if (check.consumed_at !== null) {
      throw new D1DatabaseError('CHALLENGE_REPLAY', 'Nonce has already been consumed (replay attack detected)', 400);
    }
    if (now > check.expires_at) {
      throw new D1DatabaseError('CHALLENGE_EXPIRED', 'Nonce TTL has elapsed', 400);
    }
    if (check.account_id !== accountId) {
      throw new D1DatabaseError('CHALLENGE_ACCOUNT_MISMATCH', `Nonce was issued for account "${check.account_id}", not "${accountId}"`, 400);
    }
    if (check.recipient !== recipient) {
      throw new D1DatabaseError('CHALLENGE_RECIPIENT_MISMATCH', `Nonce was issued for recipient "${check.recipient}", not "${recipient}"`, 400);
    }
    throw new D1DatabaseError('CHALLENGE_INVALID', 'Challenge validation failed', 400);
  }

  const nonceBytes = Buffer.from(result.nonce_b64, 'base64');
  return {
    nonce: new Uint8Array(nonceBytes),
    message: result.message,
  };
}

// ── Spaces & Documents Repository ──────────────────────────────────────────

export async function getSpaceD1(db, spaceId) {
  const row = await db.prepare('SELECT * FROM spaces WHERE space_id = ?').bind(spaceId).first();
  if (!row) return null;
  return {
    spaceId: row.space_id,
    name: row.name,
    contractId: row.contract_id,
    requiredTokenId: row.required_token_id,
    issuer: row.issuer,
    isPublicDemo: Boolean(row.is_public_demo),
    secretPayload: JSON.parse(row.secret_payload),
    expiryPolicy: { enforceExpiry: Boolean(row.enforce_expiry) },
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export async function listSpacesD1(db, { accountId = null, requestedSpaceId = null } = {}) {
  let query = 'SELECT s.*, d.filename, d.size, d.sha256, d.uploaded_at, d.status as doc_status FROM spaces s LEFT JOIN documents d ON s.space_id = d.space_id';
  const params = [];

  const rows = (await db.prepare(query).all()).results || [];

  return rows
    .filter((s) => {
      if (requestedSpaceId && s.space_id === requestedSpaceId) return true;
      if (s.is_public_demo) return true;
      if (accountId && s.issuer === accountId) return true;
      return false;
    })
    .map((s) => {
      const hasDoc = Boolean(s.filename && s.doc_status === 'COMMITTED');
      const isPublic = Boolean(s.is_public_demo);
      const isCreator = Boolean(accountId && s.issuer === accountId);
      const isAuthorizedViewer = isPublic || isCreator;

      return {
        spaceId: s.space_id,
        name: s.name,
        contractId: s.contract_id,
        requiredTokenId: s.required_token_id,
        issuer: isPublic ? s.issuer : (isCreator ? s.issuer : 'Confidential Creator'),
        isPublicDemo: isPublic,
        hasDocument: hasDoc,
        documentInfo: (hasDoc && isAuthorizedViewer)
          ? {
              filename: s.filename,
              size: s.size,
              sha256: s.sha256,
              uploadedAt: s.uploaded_at,
            }
          : (hasDoc ? { size: s.size, status: 'Confidential Document Ready' } : null),
      };
    });
}

export async function upsertSpaceD1(db, spaceData) {
  const now = new Date().toISOString();
  await db.prepare(`
    INSERT INTO spaces (space_id, name, contract_id, required_token_id, issuer, is_public_demo, secret_payload, enforce_expiry, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(space_id) DO UPDATE SET
      name = excluded.name,
      contract_id = excluded.contract_id,
      required_token_id = excluded.required_token_id,
      secret_payload = excluded.secret_payload,
      enforce_expiry = excluded.enforce_expiry,
      updated_at = excluded.updated_at
  `).bind(
    spaceData.spaceId,
    spaceData.name,
    spaceData.contractId,
    spaceData.requiredTokenId,
    spaceData.issuer,
    spaceData.isPublicDemo ? 1 : 0,
    typeof spaceData.secretPayload === 'string' ? spaceData.secretPayload : JSON.stringify(spaceData.secretPayload),
    spaceData.expiryPolicy?.enforceExpiry ? 1 : 0,
    spaceData.createdAt || now,
    now
  ).run();
}

export async function getDocumentD1(db, spaceId) {
  const row = await db.prepare('SELECT * FROM documents WHERE space_id = ?').bind(spaceId).first();
  if (!row) return null;
  return {
    spaceId: row.space_id,
    bucket: row.bucket,
    objectKey: row.object_key,
    filename: row.filename,
    size: row.size,
    sha256: row.sha256,
    mimeType: row.mime_type,
    uploadedBy: row.uploaded_by,
    uploadedAt: row.uploaded_at,
    status: row.status,
  };
}

export async function setDocumentD1(db, docRecord) {
  await db.prepare(`
    INSERT INTO documents (space_id, bucket, object_key, filename, size, sha256, mime_type, uploaded_by, uploaded_at, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(space_id) DO UPDATE SET
      bucket = excluded.bucket,
      object_key = excluded.object_key,
      filename = excluded.filename,
      size = excluded.size,
      sha256 = excluded.sha256,
      mime_type = excluded.mime_type,
      uploaded_by = excluded.uploaded_by,
      uploaded_at = excluded.uploaded_at,
      status = excluded.status
  `).bind(
    docRecord.spaceId,
    docRecord.bucket,
    docRecord.objectKey,
    docRecord.filename,
    docRecord.size,
    docRecord.sha256,
    docRecord.mimeType || 'application/pdf',
    docRecord.uploadedBy,
    docRecord.uploadedAt,
    docRecord.status || 'COMMITTED'
  ).run();
}

export async function deleteDocumentD1(db, spaceId) {
  return await db.prepare('DELETE FROM documents WHERE space_id = ?').bind(spaceId).run();
}

export async function recordOrphanD1(db, { bucket, objectKey, reason }) {
  const now = new Date().toISOString();
  await db.prepare(`
    INSERT INTO orphan_reconciliation (bucket, object_key, reason, created_at)
    VALUES (?, ?, ?, ?)
  `).bind(bucket, objectKey, reason, now).run();
}
