/**
 * verifier.js — NEP-413 signature verifier.
 *
 * Validates a NEP-413 signed message against:
 *   1. The signed payload (message, nonce, recipient) via near-api-js verifyMessage
 *   2. On-chain key ownership via RPC view_access_key (FullAccess required)
 *   3. Recipient exact-match (application-layer binding)
 *
 * Security contract:
 *   - FAILS CLOSED on any error (RPC failure, missing key, bad sig)
 *   - Never returns true without both cryptographic AND on-chain verification
 *   - The provider is required; callers cannot skip the RPC check
 *
 * Source truth for verifyMessage behaviour (from installed near-api-js@7.4.0):
 *   - verifyMessage() calls provider.viewAccessKey() and asserts FullAccess
 *   - verifyMessage() THROWS (does not return false) on failure
 *   - MessagePayload.nonce must be Uint8Array (32 bytes)
 *   - TAG = 2147484061 (2^31+413), LE bytes: [157,1,0,128]
 */

import './http-client.js';
import { verifyMessage as nearVerifyMessage } from 'near-api-js/nep413';
import { JsonRpcProvider, FailoverRpcProvider } from 'near-api-js';

// ── Constants ──────────────────────────────────────────────────────────────

/** Primary Testnet RPC endpoints with failover redundancy. */
export const TESTNET_RPC_URLS = [
  'https://archival-rpc.testnet.near.org',
  'https://test.rpc.fastnear.com',
  'https://rpc.testnet.near.org',
];

export const TESTNET_RPC_URL = process.env.NEAR_RPC_URL || TESTNET_RPC_URLS[0];

/** Expected recipient for Unseal Gate A.2 proof. */
export const UNSEAL_RECIPIENT = 'unseal-gate-a.proof';

// ── Provider factory ───────────────────────────────────────────────────────

/**
 * Create an RPC provider.
 * Uses FailoverRpcProvider across multiple testnet endpoints when no single rpcUrl is forced.
 * Exported so tests can inject a mock provider.
 * @param {string} [rpcUrl]
 * @returns {JsonRpcProvider | FailoverRpcProvider}
 */
export function createProvider(rpcUrl) {
  if (rpcUrl) {
    return new JsonRpcProvider({ url: rpcUrl });
  }
  if (process.env.NEAR_RPC_URL) {
    return new JsonRpcProvider({ url: process.env.NEAR_RPC_URL });
  }
  return new FailoverRpcProvider(TESTNET_RPC_URLS.map(url => new JsonRpcProvider({ url })));
}

// ── Core verification ──────────────────────────────────────────────────────

/**
 * Verify a NEP-413 signed authentication challenge.
 *
 * All three conditions must hold:
 *   A) Challenge nonce, message, and recipient are consistent (checked by caller
 *      via consumeChallenge before this is called)
 *   B) Cryptographic signature is valid for the stated publicKey and payload
 *   C) The stated publicKey is a FullAccess key on the stated NEAR account (RPC)
 *   D) recipient in payload exactly matches the expected value
 *
 * @param {object} opts
 * @param {string}     opts.accountId    - NEAR account ID (e.g. "user.testnet")
 * @param {string}     opts.publicKey    - Public key string (e.g. "ed25519:ABC...")
 * @param {Uint8Array} opts.signature    - 64-byte raw signature (decoded from base64)
 * @param {string}     opts.message      - The message string that was signed
 * @param {string}     opts.recipient    - The recipient string that was signed
 * @param {Uint8Array} opts.nonce        - The 32-byte nonce that was signed
 * @param {string}     [opts.callbackUrl]- Optional callbackUrl (must match if used)
 * @param {object}     [opts.provider]   - JsonRpcProvider instance (injected for testing)
 * @returns {Promise<{ ok: true, accountId: string, publicKey: string }>}
 * @throws {Error} With code property on any verification failure
 */
export async function verifyAuth({
  accountId,
  publicKey,
  signature,
  message,
  recipient,
  nonce,
  callbackUrl,
  provider,
}) {
  // ── Input validation ────────────────────────────────────────────────────
  assertString(accountId, 'accountId');
  assertString(publicKey, 'publicKey');
  assertString(message, 'message');
  assertString(recipient, 'recipient');
  assertUint8Array(signature, 'signature', 64);
  assertUint8Array(nonce, 'nonce', 32);
  if (callbackUrl !== undefined && typeof callbackUrl !== 'string') {
    throw Object.assign(new TypeError('callbackUrl must be a string if provided'), { code: 'INVALID_INPUT' });
  }

  // ── D: Recipient binding ────────────────────────────────────────────────
  // The recipient in the signed payload must exactly match our configured value.
  // This prevents accepting signatures intended for other applications.
  if (recipient !== UNSEAL_RECIPIENT) {
    throw Object.assign(
      new Error(`RECIPIENT_MISMATCH: Expected "${UNSEAL_RECIPIENT}", got "${recipient}"`),
      { code: 'RECIPIENT_MISMATCH' }
    );
  }

  // ── B+C: Cryptographic + on-chain verification via near-api-js ──────────
  // near-api-js verifyMessage:
  //   1. Calls provider.viewAccessKey(accountId, publicKey) → asserts FullAccess
  //   2. Rebuilds the Borsh-serialized + SHA-256 hashed payload with the tag
  //   3. Verifies the Ed25519 signature against the public key
  //   Throws on any failure.

  const rpcProvider = provider ?? createProvider();

  const payload = {
    message,
    recipient,
    nonce, // Uint8Array[32]
    ...(callbackUrl !== undefined && { callbackUrl }),
  };

  try {
    await nearVerifyMessage({
      signerAccountId: accountId,
      signerPublicKey: publicKey,
      signature,
      payload,
      provider: rpcProvider,
    });
  } catch (err) {
    // Classify the error for callers and tests
    const msg = err?.message ?? String(err);
    let code = 'VERIFICATION_FAILED';
    if (msg.includes('FullAccess')) code = 'NOT_FULL_ACCESS_KEY';
    else if (msg.includes('Signature verification failed')) code = 'BAD_SIGNATURE';
    else if (msg.includes('does not exist') || msg.includes('KeyNotFound') || msg.includes('key not found')) code = 'KEY_NOT_ON_CHAIN';
    else if (msg.includes('fetch') || msg.includes('network') || msg.includes('ECONNREFUSED') || msg.includes('timeout')) code = 'RPC_FAILURE';

    throw Object.assign(new Error(`${code}: ${msg}`), { code, cause: err });
  }

  return { ok: true, accountId, publicKey };
}

// ── Helpers ────────────────────────────────────────────────────────────────

function assertString(value, name) {
  if (!value || typeof value !== 'string') {
    throw Object.assign(new TypeError(`${name} must be a non-empty string`), { code: 'INVALID_INPUT' });
  }
}

function assertUint8Array(value, name, expectedLength) {
  if (!(value instanceof Uint8Array)) {
    throw Object.assign(new TypeError(`${name} must be a Uint8Array`), { code: 'INVALID_INPUT' });
  }
  if (expectedLength !== undefined && value.length !== expectedLength) {
    throw Object.assign(
      new TypeError(`${name} must be exactly ${expectedLength} bytes, got ${value.length}`),
      { code: 'INVALID_INPUT' }
    );
  }
}
