/**
 * sign_challenge.js — Sign a NEP-413 challenge using a local key pair.
 *
 * SECURITY: This script uses near-api-js KeyPairSigner.fromSecretKey().
 * Your secret key is passed as an environment variable — it is NEVER
 * written to disk, logged, or transmitted (only the public key and
 * signature are sent to the server).
 *
 * Usage:
 *   NEAR_SECRET_KEY="ed25519:YOURPRIVATEKEY" \
 *   NEAR_ACCOUNT_ID="yourname.testnet" \
 *   node signing/sign_challenge.js
 *
 * Where to find your secret key (choose one):
 *   A) NEAR CLI credentials: cat ~/.near-credentials/testnet/YOURNAME.testnet.json
 *      → use the "private_key" field value
 *   B) Meteor Wallet → Settings → Export Key → Ed25519 format
 *
 * The script:
 *   1. POSTs to /challenge to get a server-issued nonce
 *   2. Signs the challenge using near-api-js (no custom crypto)
 *   3. POSTs to /verify with the signed result
 *   4. Prints the full result and exports env vars for REAL_SIG=1
 *
 * Server must be running: npm run serve
 */

import { KeyPairSigner, KeyPairEd25519, baseEncode } from 'near-api-js';
import { signMessage } from 'near-api-js/nep413';
import { UNSEAL_RECIPIENT } from '../src/verifier.js';

const SERVER = process.env.SERVER_URL ?? 'http://localhost:3000';
const ACCOUNT_ID = process.env.NEAR_ACCOUNT_ID;
const SECRET_KEY = process.env.NEAR_SECRET_KEY;

// ── Validate inputs ─────────────────────────────────────────────────────────

if (!ACCOUNT_ID) {
  console.error('[sign_challenge] ERROR: NEAR_ACCOUNT_ID env var is required');
  console.error('  export NEAR_ACCOUNT_ID="yourname.testnet"');
  process.exit(1);
}

if (!SECRET_KEY) {
  console.error('[sign_challenge] ERROR: NEAR_SECRET_KEY env var is required');
  console.error('  export NEAR_SECRET_KEY="ed25519:YOURPRIVATEKEY"');
  console.error('');
  console.error('  Find it in: ~/.near-credentials/testnet/YOURNAME.testnet.json');
  console.error('  (use the "private_key" field value)');
  process.exit(1);
}

// ── Step 1: Get a challenge ──────────────────────────────────────────────────

console.log(`[sign_challenge] Server: ${SERVER}`);
console.log(`[sign_challenge] Account: ${ACCOUNT_ID}`);
console.log(`[sign_challenge] Recipient: ${UNSEAL_RECIPIENT}`);
console.log('');
console.log('[sign_challenge] Step 1: Requesting challenge from server...');

let challenge;
try {
  const res = await fetch(`${SERVER}/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ accountId: ACCOUNT_ID }),
  });
  challenge = await res.json();
  if (!challenge.nonceB64) throw new Error(JSON.stringify(challenge));
} catch (err) {
  console.error('[sign_challenge] ERROR: Could not get challenge from server.');
  console.error('  Is the server running? Run: npm run serve');
  console.error('  Details:', err.message);
  process.exit(1);
}

console.log('[sign_challenge] Challenge received:');
console.log('  nonceB64 :', challenge.nonceB64);
console.log('  message  :', challenge.message);
console.log('  recipient:', challenge.recipient);
console.log('  expiresAt:', new Date(challenge.expiresAt).toISOString());
console.log('');

// ── Step 2: Sign the challenge ───────────────────────────────────────────────

console.log('[sign_challenge] Step 2: Signing with KeyPairSigner...');

let accountId, publicKey, signature, signatureB64;
try {
  // Build signer from the provided secret key
  const signer = KeyPairSigner.fromSecretKey(SECRET_KEY);
  const pk = await signer.getPublicKey();

  // Build an Account-like object that signMessage() expects
  // signMessage() calls signerAccount.getSigner() → signer.signNep413Message()
  const signerAccount = {
    accountId: ACCOUNT_ID,
    getSigner: () => signer,
  };

  const nonce = new Uint8Array(Buffer.from(challenge.nonceB64, 'base64'));

  const signed = await signMessage({
    signerAccount,
    payload: {
      message: challenge.message,
      recipient: challenge.recipient,
      nonce,
    },
  });

  accountId = signed.accountId;
  publicKey = signed.publicKey.toString();
  // SignedMessage.signature is Uint8Array
  signatureB64 = Buffer.from(signed.signature).toString('base64');

  console.log('[sign_challenge] Signature produced:');
  console.log('  accountId   :', accountId);
  console.log('  publicKey   :', publicKey);
  console.log('  signatureB64:', signatureB64);
  console.log('');
} catch (err) {
  console.error('[sign_challenge] ERROR: Signing failed:', err.message);
  process.exit(1);
}

// ── Step 3: Submit to /verify ────────────────────────────────────────────────

console.log('[sign_challenge] Step 3: Submitting to /verify...');

let verifyResult;
try {
  const res = await fetch(`${SERVER}/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      accountId,
      publicKey,
      signatureB64,
      nonceB64: challenge.nonceB64,
    }),
  });
  verifyResult = await res.json();
  console.log('[sign_challenge] /verify response (HTTP', res.status + '):');
  console.log(JSON.stringify(verifyResult, null, 2));
  console.log('');

  if (!verifyResult.ok) {
    console.error('[sign_challenge] VERIFICATION FAILED. See error above.');
    process.exit(1);
  }
} catch (err) {
  console.error('[sign_challenge] ERROR: Could not reach /verify:', err.message);
  process.exit(1);
}

// ── Step 4: Print env vars for REAL_SIG=1 test run ──────────────────────────

console.log('[sign_challenge] ✅ Authentication verified successfully.');
console.log('');
console.log('To run the [REQUIRES-REAL-WALLET] integration tests, copy-paste:');
console.log('');
console.log(`export NEAR_ACCOUNT_ID="${accountId}"`);
console.log(`export NEAR_PUBLIC_KEY="${publicKey}"`);
console.log(`export NEAR_SIGNATURE_B64="${signatureB64}"`);
console.log(`export NEAR_NONCE_B64="${challenge.nonceB64}"`);
console.log(`export NEAR_MESSAGE="${challenge.message}"`);
console.log('REAL_SIG=1 npm run test:rpc');
console.log('');
console.log('NOTE: The nonce above was consumed by /verify. Issue a fresh challenge');
console.log('      before running REAL_SIG=1 tests (they call verifyAuth directly,');
console.log('      bypassing consumeChallenge, so the same sig+nonce can be reused');
console.log('      in the test suite as a known-good vector).');
