/**
 * challenge.js — Server-side nonce (challenge) generator and store.
 *
 * Generates cryptographically secure 32-byte nonces and tracks them
 * with TTL and single-use enforcement. No external dependencies.
 *
 * Security properties:
 *   - Nonces are generated server-side using crypto.randomBytes(32)
 *   - Each nonce has a TTL (default 5 minutes); expired nonces are rejected
 *   - Nonces are invalidated immediately on first successful consumption
 *   - The in-memory store is intentionally simple for the proof; a production
 *     deployment would replace it with Redis or a database.
 */

import { randomBytes } from 'node:crypto';

// ── Constants ──────────────────────────────────────────────────────────────

/** Default nonce lifetime in milliseconds (5 minutes). */
export const DEFAULT_TTL_MS = 5 * 60 * 1000;

/** Required nonce length in bytes per NEP-413 spec. */
export const NONCE_BYTES = 32;

// ── In-memory store ────────────────────────────────────────────────────────

/**
 * @typedef {{ nonce: Uint8Array, expiresAt: number, consumed: boolean }} ChallengeEntry
 */

/** @type {Map<string, ChallengeEntry>} */
const store = new Map();

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * Issue a new challenge for a given account and recipient.
 *
 * @param {object} opts
 * @param {string} opts.accountId   - NEAR account ID requesting login
 * @param {string} opts.recipient   - Recipient domain/app identifier (must match verifier)
 * @param {string} opts.message     - Human-readable message to display in wallet
 * @param {number} [opts.ttlMs]     - TTL in ms (default: DEFAULT_TTL_MS)
 * @returns {{ nonceB64: string, message: string, recipient: string, accountId: string, expiresAt: number }}
 */
export function issueChallenge({ accountId, recipient, message, ttlMs = DEFAULT_TTL_MS }) {
  if (!accountId || typeof accountId !== 'string') throw new TypeError('accountId must be a non-empty string');
  if (!recipient || typeof recipient !== 'string') throw new TypeError('recipient must be a non-empty string');
  if (!message || typeof message !== 'string') throw new TypeError('message must be a non-empty string');
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) throw new TypeError('ttlMs must be a positive number');

  const rawNonce = randomBytes(NONCE_BYTES); // 32 cryptographically random bytes
  const nonceB64 = rawNonce.toString('base64');
  const expiresAt = Date.now() + ttlMs;

  store.set(nonceB64, {
    nonce: new Uint8Array(rawNonce),
    accountId,
    recipient,
    message,
    expiresAt,
    consumed: false,
  });

  return { nonceB64, message, recipient, accountId, expiresAt };
}

/**
 * Consume and validate a challenge nonce, enforcing:
 *   - Existence (was issued by this server)
 *   - Expiry (not past TTL)
 *   - Single-use (not already consumed)
 *   - Account binding (nonce was issued for this accountId)
 *   - Recipient binding (nonce was issued for this recipient)
 *
 * On success, the nonce is immediately removed from the store.
 * On failure, an Error is thrown with a descriptive reason.
 *
 * @param {object} opts
 * @param {string} opts.nonceB64    - Base64 nonce from client
 * @param {string} opts.accountId   - Claimed account ID
 * @param {string} opts.recipient   - Expected recipient (must match what was issued)
 * @returns {{ nonce: Uint8Array, message: string }} The raw nonce bytes and original message
 * @throws {Error} On any validation failure
 */
export function consumeChallenge({ nonceB64, accountId, recipient }) {
  if (!nonceB64 || typeof nonceB64 !== 'string') throw new TypeError('nonceB64 must be a non-empty string');
  if (!accountId || typeof accountId !== 'string') throw new TypeError('accountId must be a non-empty string');
  if (!recipient || typeof recipient !== 'string') throw new TypeError('recipient must be a non-empty string');

  const entry = store.get(nonceB64);

  // Fail closed: unknown nonce is treated as invalid (never issued or already deleted)
  if (!entry) {
    throw new Error('CHALLENGE_NOT_FOUND: Nonce is unknown, expired, or already consumed');
  }

  // Check expiry before anything else
  if (Date.now() > entry.expiresAt) {
    store.delete(nonceB64); // clean up
    throw new Error('CHALLENGE_EXPIRED: Nonce TTL has elapsed');
  }

  // Guard against consumed nonces (double-use defense-in-depth)
  if (entry.consumed) {
    store.delete(nonceB64);
    throw new Error('CHALLENGE_REPLAY: Nonce has already been consumed');
  }

  // Account binding
  if (entry.accountId !== accountId) {
    throw new Error(`CHALLENGE_ACCOUNT_MISMATCH: Nonce was issued for account "${entry.accountId}", not "${accountId}"`);
  }

  // Recipient binding (defense-in-depth; verifier also checks this independently)
  if (entry.recipient !== recipient) {
    throw new Error(`CHALLENGE_RECIPIENT_MISMATCH: Nonce was issued for recipient "${entry.recipient}", not "${recipient}"`);
  }

  // Single-use: delete immediately on first consumption
  store.delete(nonceB64);

  return { nonce: entry.nonce, message: entry.message };
}

/**
 * Peek at a challenge without consuming it. For testing only.
 * @param {string} nonceB64
 * @returns {ChallengeEntry | undefined}
 */
export function _peekChallenge(nonceB64) {
  return store.get(nonceB64);
}

/**
 * Clear all challenges. For testing only.
 */
export function _clearStore() {
  store.clear();
}

/**
 * Return current store size. For testing only.
 * @returns {number}
 */
export function _storeSize() {
  return store.size;
}
