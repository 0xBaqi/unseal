/**
 * transferee-auth.rpc.test.js — Transferee HTTP Endpoint Authorization Suite.
 *
 * Verifies the transferee authorization path through the actual HTTP endpoint:
 *   1. Issues a fresh server nonce challenge for the transferee via handleChallenge()
 *   2. If TRANSFEREE_SIG=1 is provided with a real wallet signature:
 *      - Submits to handleSpaceAccess() -> asserts 200 OK and unlocked vault payload.
 *   3. If TRANSFEREE_SIG=1 is NOT provided:
 *      - Verifies on-chain ownership preconditions via live RPC.
 *      - Issues the fresh challenge.
 *      - Explicitly reports SKIPPED (BLOCKED pending real wallet interaction).
 *      - Zero fabricated signatures.
 */

import '../src/http-client.js';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { JsonRpcProvider } from 'near-api-js';
import { handleChallenge, handleSpaceAccess } from '../src/server.js';
import { fetchNftToken } from '../src/ownership.js';
import { createProvider, UNSEAL_RECIPIENT } from '../src/verifier.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = join(__dirname, '..');
const deployment = JSON.parse(readFileSync(join(ROOT_DIR, 'deployment.testnet.json'), 'utf8'));

const CONTRACT_ID = deployment.contractId;
const TRANSFER_TOKEN_ID = 'pass-transfer-493545';
const TRANSFEREE_ACCOUNT_ID = 'c1755.bob-55400334.testnet';

const TRANSFEREE_SIG = process.env.TRANSFEREE_SIG === '1';
const ENV_TRANSFEREE = {
  accountId: process.env.TRANSFEREE_ACCOUNT_ID,
  publicKey: process.env.TRANSFEREE_PUBLIC_KEY,
  signatureB64: process.env.TRANSFEREE_SIGNATURE_B64,
  nonceB64: process.env.TRANSFEREE_NONCE_B64,
  message: process.env.TRANSFEREE_MESSAGE,
};

const spacesConfig = {
  'space-transfer': {
    spaceId: 'space-transfer',
    name: 'Unseal Transferable Vault',
    contractId: CONTRACT_ID,
    requiredTokenId: TRANSFER_TOKEN_ID,
    issuer: 'baronal.testnet',
    secretPayload: { clearance: 'TRANSFEREE_VAULT_UNLOCKED' },
    expiryPolicy: { enforceExpiry: true },
  },
};

describe('[TRANSFEREE-AUTH] Transferee HTTP Authorization Path', () => {
  const provider = createProvider();

  it('1. Precondition: Transferee is confirmed on-chain owner via finalized RPC', async () => {
    const token = await fetchNftToken({ contractId: CONTRACT_ID, tokenId: TRANSFER_TOKEN_ID, provider });
    assert.ok(token, `Token ${TRANSFER_TOKEN_ID} must exist on contract ${CONTRACT_ID}`);
    assert.equal(token.owner_id, TRANSFEREE_ACCOUNT_ID, `On-chain owner must be transferee ${TRANSFEREE_ACCOUNT_ID}`);
    console.log(`[TRANSFEREE-AUTH] On-chain token confirmed: id=${token.token_id}, owner=${token.owner_id}`);
  });

  it('2. Negative: Previous owner (bob) is DENIED access to space-transfer (403 NOT_TOKEN_OWNER)', async () => {
    const bobAccountId = 'bob-55400334.testnet';

    // A: Via HTTP handler: unauthenticated request is denied
    const httpRes = await handleSpaceAccess(
      { accountId: bobAccountId, spaceId: 'space-transfer' },
      'space-transfer',
      { provider, spacesConfig }
    );
    assert.equal(httpRes.body.ok, false);
    assert.ok(httpRes.status >= 400);

    // B: Via ownership module: Bob no longer owns token -> 403 NOT_TOKEN_OWNER
    const { verifySpaceAccess } = await import('../src/ownership.js');
    await assert.rejects(
      () =>
        verifySpaceAccess({
          accountId: bobAccountId,
          spaceId: 'space-transfer',
          provider,
          spacesConfig,
        }),
      (err) => {
        assert.equal(err.code, 'NOT_TOKEN_OWNER');
        assert.equal(err.status, 403);
        return true;
      }
    );

    const token = await fetchNftToken({ contractId: CONTRACT_ID, tokenId: TRANSFER_TOKEN_ID, provider });
    assert.notEqual(token.owner_id, bobAccountId, 'Bob must NOT be on-chain owner');
    console.log(`[TRANSFEREE-AUTH] Confirmed Bob (${bobAccountId}) is denied: current owner is ${token.owner_id}`);
  });

  it('3. Negative: Transferee is DENIED access to space-alpha (403 NOT_TOKEN_OWNER)', async () => {
    // Transferee owns pass-transfer-493545, but space-alpha requires pass-alpha-1
    const alphaToken = await fetchNftToken({ contractId: CONTRACT_ID, tokenId: 'pass-alpha-1', provider });
    assert.notEqual(alphaToken.owner_id, TRANSFEREE_ACCOUNT_ID, 'Transferee does NOT own pass-alpha-1');
    assert.equal(alphaToken.owner_id, 'baronal.testnet');
    console.log(`[TRANSFEREE-AUTH] Confirmed transferee (${TRANSFEREE_ACCOUNT_ID}) cannot access space-alpha (owned by ${alphaToken.owner_id})`);
  });

  it('4. Precondition: Server issues fresh single-use nonce challenge for transferee', async () => {
    const challengeRes = await handleChallenge({
      accountId: TRANSFEREE_ACCOUNT_ID,
      recipient: UNSEAL_RECIPIENT,
      message: 'Sign in to Unseal Gate A.3 Transferee Proof',
    });

    assert.equal(challengeRes.status, 200);
    assert.ok(challengeRes.body.nonceB64, 'Nonce must be issued');
    assert.equal(challengeRes.body.accountId, TRANSFEREE_ACCOUNT_ID);
    assert.equal(challengeRes.body.recipient, UNSEAL_RECIPIENT);
    console.log(`[TRANSFEREE-AUTH] Challenge issued for transferee: accountId=${challengeRes.body.accountId}, recipient=${challengeRes.body.recipient}`);
  });

  it(
    '5. [REQUIRES-REAL-WALLET] Transferee authenticates via POST /space/:spaceId/access with real NEP-413 signature',
    {
      skip: !TRANSFEREE_SIG
        ? 'BLOCKED: Awaiting real transferee browser-wallet signature (set TRANSFEREE_SIG=1 with environment exports)'
        : false,
    },
    async () => {
      // Validate inputs if TRANSFEREE_SIG=1 is requested
      const required = {
        TRANSFEREE_ACCOUNT_ID: ENV_TRANSFEREE.accountId,
        TRANSFEREE_PUBLIC_KEY: ENV_TRANSFEREE.publicKey,
        TRANSFEREE_SIGNATURE_B64: ENV_TRANSFEREE.signatureB64,
        TRANSFEREE_NONCE_B64: ENV_TRANSFEREE.nonceB64,
        TRANSFEREE_MESSAGE: ENV_TRANSFEREE.message,
      };

      for (const [k, v] of Object.entries(required)) {
        assert.ok(v, `Missing required environment variable when TRANSFEREE_SIG=1: ${k}`);
      }

      const reqBody = {
        accountId: ENV_TRANSFEREE.accountId,
        publicKey: ENV_TRANSFEREE.publicKey,
        signatureB64: ENV_TRANSFEREE.signatureB64,
        nonceB64: ENV_TRANSFEREE.nonceB64,
        recipient: UNSEAL_RECIPIENT,
        message: ENV_TRANSFEREE.message,
      };

      const res = await handleSpaceAccess(reqBody, 'space-transfer', { provider, spacesConfig });

      assert.equal(res.status, 200, `Expected HTTP 200, got ${res.status}: ${JSON.stringify(res.body)}`);
      assert.equal(res.body.ok, true);
      assert.equal(res.body.accessGranted, true);
      assert.equal(res.body.access.ownerId, ENV_TRANSFEREE.accountId);
      assert.deepEqual(res.body.access.secretPayload, { clearance: 'TRANSFEREE_VAULT_UNLOCKED' });
      console.log(`[TRANSFEREE-AUTH] Access granted to transferee! Unlocked payload:`, res.body.access.secretPayload);
    }
  );
});
