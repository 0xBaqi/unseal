/**
 * verifier.rpc.test.js — Integration tests hitting the real NEAR testnet RPC.
 *
 * Label: [REAL-RPC] — These tests make live network requests to
 * https://rpc.testnet.near.org and require internet access.
 *
 * Label: [REQUIRES-REAL-WALLET] — The positive authentication test
 * requires a real wallet-signed payload. See SIGNING_INSTRUCTIONS.md.
 *
 * Tests that can run without a wallet (RPC connectivity + key lookup) are
 * clearly separated from tests requiring a real signature.
 *
 * HOW TO RUN:
 *   1. Run all RPC tests:          npm run test:rpc
 *   2. With a real wallet sig:     REAL_SIG=1 npm run test:rpc
 *      (set env vars per SIGNING_INSTRUCTIONS.md)
 *
 * IMPORTANT: These tests make READ-ONLY RPC calls. No transactions are sent.
 */

import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';

import { verifyAuth, createProvider, TESTNET_RPC_URL, UNSEAL_RECIPIENT } from '../src/verifier.js';

// ── Well-known testnet account for RPC connectivity test ─────────────────────
// near is a well-known testnet root account; we only read its key list.
const PROBE_ACCOUNT = 'near';

// ── Real-wallet environment variables ────────────────────────────────────────
// Set these when running with REAL_SIG=1 (see SIGNING_INSTRUCTIONS.md):
//   NEAR_ACCOUNT_ID     e.g. yourwallet.testnet
//   NEAR_PUBLIC_KEY     e.g. ed25519:ABC...
//   NEAR_SIGNATURE_B64  base64-encoded 64-byte signature from wallet
//   NEAR_NONCE_B64      base64-encoded 32-byte nonce (issued by /challenge)
//   NEAR_MESSAGE        the exact message string signed
const REAL_SIG = process.env.REAL_SIG === '1';
const ENV = {
  accountId: process.env.NEAR_ACCOUNT_ID,
  publicKey: process.env.NEAR_PUBLIC_KEY,
  signatureB64: process.env.NEAR_SIGNATURE_B64,
  nonceB64: process.env.NEAR_NONCE_B64,
  message: process.env.NEAR_MESSAGE,
};

// ════════════════════════════════════════════════════════════
// SUITE 1: RPC connectivity — no wallet required
// ════════════════════════════════════════════════════════════
describe('[REAL-RPC] testnet RPC connectivity', () => {

  it('createProvider returns a usable JsonRpcProvider', async () => {
    const provider = createProvider(TESTNET_RPC_URL);
    assert.ok(provider, 'provider must be truthy');
    assert.ok(typeof provider.viewAccessKey === 'function' || typeof provider.query === 'function',
      'provider must have viewAccessKey or query method');
  });

  it('[REAL-RPC] view_access_key_list returns keys for well-known testnet account', async () => {
    const provider = createProvider(TESTNET_RPC_URL);
    // Use the lower-level query method to list keys for the probe account
    const result = await provider.query({
      request_type: 'view_access_key_list',
      finality: 'final',
      account_id: PROBE_ACCOUNT,
    });
    assert.ok(result, 'RPC result must be truthy');
    assert.ok(Array.isArray(result.keys), 'result.keys must be an array');
    assert.ok(result.keys.length > 0, `${PROBE_ACCOUNT} must have at least one key`);
    // Log the actual RPC response for evidence (not an assertion)
    console.log(`[REAL-RPC] ${PROBE_ACCOUNT} has ${result.keys.length} key(s) at block ${result.block_height}`);
    console.log('[REAL-RPC] First key:', result.keys[0].public_key, '|', JSON.stringify(result.keys[0].access_key.permission));
  });

  it('[REAL-RPC] view_access_key for a non-existent key throws (key not found)', async () => {
    const provider = createProvider(TESTNET_RPC_URL);
    // Use a syntactically valid but non-existent public key
    const fakeKey = 'ed25519:11111111111111111111111111111111';
    // near-api-js may throw a typed error or return an error object
    let threw = false;
    try {
      await provider.viewAccessKey({ accountId: PROBE_ACCOUNT, publicKey: fakeKey });
    } catch {
      threw = true;
    }
    // We just verify the RPC correctly indicates the key doesn't exist
    assert.ok(threw, 'RPC must reject a non-existent key lookup');
    console.log('[REAL-RPC] Confirmed: non-existent key lookup throws as expected');
  });

  it('[REAL-RPC][NEGATIVE] verifyAuth with fake key on real account → fails closed', async () => {
    // A syntactically valid key that is not on any real account
    const fakePublicKey = 'ed25519:AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9';
    const fakeNonce = new Uint8Array(32).fill(0x01);
    const fakeSig = new Uint8Array(64).fill(0x00);

    await assert.rejects(
      () => verifyAuth({
        accountId: PROBE_ACCOUNT,
        publicKey: fakePublicKey,
        signature: fakeSig,
        message: 'test',
        recipient: UNSEAL_RECIPIENT,
        nonce: fakeNonce,
        provider: createProvider(TESTNET_RPC_URL),
      }),
      (err) => {
        // Must reject — either key not on chain, bad sig, or not FullAccess
        assert.ok(err.code !== undefined, `Error must have a code property: ${err.message}`);
        assert.notEqual(err.code, 'RECIPIENT_MISMATCH'); // wrong code for this failure mode
        console.log(`[REAL-RPC] Correctly rejected with code=${err.code}`);
        return true;
      }
    );
  });

  it('[REAL-RPC][NEGATIVE] RPC to wrong endpoint → fails closed', async () => {
    const badProvider = createProvider('http://localhost:19999'); // nothing listening here
    const fakeNonce = new Uint8Array(32).fill(0x02);
    const fakeSig = new Uint8Array(64).fill(0x00);

    await assert.rejects(
      () => verifyAuth({
        accountId: 'test.testnet',
        publicKey: 'ed25519:AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9',
        signature: fakeSig,
        message: 'test',
        recipient: UNSEAL_RECIPIENT,
        nonce: fakeNonce,
        provider: badProvider,
      }),
      (err) => {
        assert.ok(err.code !== undefined, `Error must have a code: ${err.message}`);
        console.log(`[REAL-RPC] RPC failure correctly rejected with code=${err.code}`);
        return true;
      }
    );
  });
});

// ════════════════════════════════════════════════════════════
// SUITE 2: Real wallet authentication (requires REAL_SIG=1)
// ════════════════════════════════════════════════════════════
describe('[REQUIRES-REAL-WALLET] full authentication with live testnet wallet', () => {

  function assertRealSigEnv() {
    const requiredEnv = {
      NEAR_ACCOUNT_ID: ENV.accountId,
      NEAR_PUBLIC_KEY: ENV.publicKey,
      NEAR_SIGNATURE_B64: ENV.signatureB64,
      NEAR_NONCE_B64: ENV.nonceB64,
      NEAR_MESSAGE: ENV.message,
    };
    for (const [k, v] of Object.entries(requiredEnv)) {
      assert.ok(v, `Missing required REAL_SIG environment variable: ${k}`);
    }
  }

  const skipReason = !REAL_SIG ? 'Skipped: set REAL_SIG=1 and provide testnet wallet exports to run' : false;

  it('[REQUIRES-REAL-WALLET] verifyAuth succeeds with a real wallet signature', { skip: skipReason }, async () => {
    assertRealSigEnv();

    const signature = new Uint8Array(Buffer.from(ENV.signatureB64, 'base64'));
    const nonce = new Uint8Array(Buffer.from(ENV.nonceB64, 'base64'));
    assert.equal(signature.length, 64, 'Signature must be 64 bytes');
    assert.equal(nonce.length, 32, 'Nonce must be 32 bytes');

    const provider = createProvider(TESTNET_RPC_URL);
    const result = await verifyAuth({
      accountId: ENV.accountId,
      publicKey: ENV.publicKey,
      signature,
      message: ENV.message,
      recipient: UNSEAL_RECIPIENT,
      nonce,
      provider,
    });

    assert.equal(result.ok, true, 'verifyAuth must return { ok: true }');
    assert.equal(result.accountId, ENV.accountId);
    assert.equal(result.publicKey, ENV.publicKey);
  });

  it('[REQUIRES-REAL-WALLET][NEGATIVE] real wallet sig with tampered message → rejected', { skip: skipReason }, async () => {
    assertRealSigEnv();

    const signature = new Uint8Array(Buffer.from(ENV.signatureB64, 'base64'));
    const nonce = new Uint8Array(Buffer.from(ENV.nonceB64, 'base64'));
    const provider = createProvider(TESTNET_RPC_URL);

    await assert.rejects(
      () => verifyAuth({
        accountId: ENV.accountId,
        publicKey: ENV.publicKey,
        signature,
        message: ENV.message + ' TAMPERED',
        recipient: UNSEAL_RECIPIENT,
        nonce,
        provider,
      }),
      (err) => {
        assert.ok(err.code === 'BAD_SIGNATURE' || err.code === 'VERIFICATION_FAILED', err.message);
        return true;
      }
    );
  });

  it('[REQUIRES-REAL-WALLET][NEGATIVE] real wallet sig with wrong recipient → RECIPIENT_MISMATCH', { skip: skipReason }, async () => {
    assertRealSigEnv();

    const signature = new Uint8Array(Buffer.from(ENV.signatureB64, 'base64'));
    const nonce = new Uint8Array(Buffer.from(ENV.nonceB64, 'base64'));
    const provider = createProvider(TESTNET_RPC_URL);

    await assert.rejects(
      () => verifyAuth({
        accountId: ENV.accountId,
        publicKey: ENV.publicKey,
        signature,
        message: ENV.message,
        recipient: 'wrong-app.com',
        nonce,
        provider,
      }),
      (err) => {
        assert.equal(err.code, 'RECIPIENT_MISMATCH', err.message);
        return true;
      }
    );
  });
});
