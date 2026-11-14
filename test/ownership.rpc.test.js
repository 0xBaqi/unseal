/**
 * ownership.rpc.test.js — Live NEAR Testnet RPC Integration Suite for Gate A.3.
 *
 * Verifies live on-chain NEP-171 ownership verification and transfer revocation:
 *   - L1: Live RPC view call for pass-alpha-1 on unseal-nft contract -> baronal.testnet confirmed owner (200 OK).
 *   - L2: Non-owner rejection -> 403 NOT_TOKEN_OWNER.
 *   - L3: Non-existent token -> 403 TOKEN_MISMATCH / TOKEN_NOT_FOUND.
 *   - L4: Contract mismatch -> 403 CONTRACT_MISMATCH.
 *   - L5: Live testnet NFT transfer & instant revocation proof:
 *         Bob holds pass-transfer-proof -> Bob granted access (200 OK).
 *         Bob executes real on-chain nft_transfer to Charlie.
 *         Bob is immediately revoked (403 NOT_TOKEN_OWNER) with zero stale cache.
 *         Charlie is immediately granted access (200 OK).
 *   - L6: Fail-closed on RPC failure -> 503 RPC_FAILURE.
 */

import '../src/http-client.js';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  Account,
  JsonRpcProvider,
  KeyPair,
  KeyPairSigner,
} from 'near-api-js';
import { verifySpaceAccess, fetchNftToken, OwnershipError } from '../src/ownership.js';
import { createProvider } from '../src/verifier.js';
import { parseNearAmount } from 'near-api-js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = join(__dirname, '..');
const deployment = JSON.parse(readFileSync(join(ROOT_DIR, 'deployment.testnet.json'), 'utf8'));
const bobAuth = JSON.parse(readFileSync(join(ROOT_DIR, '.testnet-bob.json'), 'utf8'));
const contractKeys = JSON.parse(readFileSync(join(ROOT_DIR, '.testnet-keys.json'), 'utf8'));

const CONTRACT_ID = deployment.contractId;
const FAUCET_URL = 'https://helper.testnet.near.org/account';

const liveSpacesConfig = {
  'space-alpha': {
    spaceId: 'space-alpha',
    name: 'Unseal Alpha Vault',
    contractId: CONTRACT_ID,
    requiredTokenId: 'pass-alpha-1',
    issuer: 'baronal.testnet',
    secretPayload: { clearance: 'ALPHA_VAULT_CLEAR' },
    expiryPolicy: { enforceExpiry: true },
  },
  'space-transfer': {
    spaceId: 'space-transfer',
    name: 'Unseal Transferable Vault',
    contractId: CONTRACT_ID,
    requiredTokenId: null, // dynamically bound in L5
    issuer: 'baronal.testnet',
    secretPayload: { clearance: 'TRANSFER_VAULT_CLEAR' },
    expiryPolicy: { enforceExpiry: true },
  },
};

describe('Gate A.3: Live Testnet RPC Ownership & Revocation Tests', () => {
  const provider = createProvider();

  it('L1 [Positive]: Live on-chain ownership check confirms baronal.testnet for pass-alpha-1', async () => {
    const token = await fetchNftToken({ contractId: CONTRACT_ID, tokenId: 'pass-alpha-1', provider });
    assert.ok(token, 'Token pass-alpha-1 must exist on-chain');
    assert.equal(token.token_id, 'pass-alpha-1');
    assert.equal(token.owner_id, 'baronal.testnet');

    const res = await verifySpaceAccess({
      accountId: 'baronal.testnet',
      spaceId: 'space-alpha',
      provider,
      spacesConfig: liveSpacesConfig,
    });

    assert.equal(res.ok, true);
    assert.equal(res.ownerId, 'baronal.testnet');
    assert.equal(res.tokenId, 'pass-alpha-1');
    assert.deepEqual(res.secretPayload, { clearance: 'ALPHA_VAULT_CLEAR' });
  });

  it('L2 [Negative]: Unrelated account is rejected with 403 NOT_TOKEN_OWNER against live contract', async () => {
    await assert.rejects(
      () =>
        verifySpaceAccess({
          accountId: 'unrelated-attacker.testnet',
          spaceId: 'space-alpha',
          provider,
          spacesConfig: liveSpacesConfig,
        }),
      (err) => {
        assert.ok(err instanceof OwnershipError);
        assert.equal(err.code, 'NOT_TOKEN_OWNER');
        assert.equal(err.status, 403);
        return true;
      }
    );
  });

  it('L3 [Negative]: Query for mismatched token rejects with 403 TOKEN_MISMATCH', async () => {
    await assert.rejects(
      () =>
        verifySpaceAccess({
          accountId: 'baronal.testnet',
          spaceId: 'space-alpha',
          tokenId: 'non-existent-token-99999',
          provider,
          spacesConfig: liveSpacesConfig,
        }),
      (err) => {
        assert.ok(err instanceof OwnershipError);
        assert.equal(err.code, 'TOKEN_MISMATCH');
        return true;
      }
    );
  });

  it('L4 [Negative]: Query with mismatched contract ID rejects with 403 CONTRACT_MISMATCH', async () => {
    await assert.rejects(
      () =>
        verifySpaceAccess({
          accountId: 'baronal.testnet',
          spaceId: 'space-alpha',
          contractId: 'wrong-contract.testnet',
          provider,
          spacesConfig: liveSpacesConfig,
        }),
      (err) => {
        assert.ok(err instanceof OwnershipError);
        assert.equal(err.code, 'CONTRACT_MISMATCH');
        assert.equal(err.status, 403);
        return true;
      }
    );
  });

  it('L5 [Live Revocation]: Bob access OK -> Real nft_transfer to Charlie -> Bob REVOKED (403) -> Charlie access OK', async () => {
    const bobAccountId = bobAuth.accountId;
    const transferTokenId = `pass-transfer-${Date.now().toString().slice(-6)}`;
    liveSpacesConfig['space-transfer'].requiredTokenId = transferTokenId;

    // 0. Mint fresh transferable pass to Bob using contract signer
    console.log(`\n  [L5 Step 0] Minting fresh access pass "${transferTokenId}" to Bob: ${bobAccountId}...`);
    const contractKeyPair = KeyPair.fromString(contractKeys.secretKey);
    const contractSigner = new KeyPairSigner(contractKeyPair);
    const contractAccount = new Account(CONTRACT_ID, provider, contractSigner);

    await contractAccount.callFunctionRaw({
      contractId: CONTRACT_ID,
      methodName: 'nft_mint',
      args: {
        token_id: transferTokenId,
        token_owner_id: bobAccountId,
        token_metadata: {
          title: 'Live Revocation Test Pass',
          description: 'Transferable access pass for Gate A.3 revocation proof',
          copies: 1,
          issued_at: Date.now().toString(),
          extra: JSON.stringify({ space_id: 'space-transfer' }),
        },
      },
      deposit: BigInt(parseNearAmount('0.02')),
      gas: 50000000000000n,
    });
    // Brief settle for mint receipt
    await new Promise((r) => setTimeout(r, 2500));

    // 1. Check Bob initial ownership
    console.log(`  [L5 Step 1] Verifying initial access for Bob: ${bobAccountId}...`);
    const tokenBefore = await fetchNftToken({ contractId: CONTRACT_ID, tokenId: transferTokenId, provider });
    assert.ok(tokenBefore, 'Transfer pass must exist');
    assert.equal(tokenBefore.owner_id, bobAccountId, 'Bob must initially own transfer pass');

    const bobInitialAccess = await verifySpaceAccess({
      accountId: bobAccountId,
      spaceId: 'space-transfer',
      provider,
      spacesConfig: liveSpacesConfig,
    });
    assert.equal(bobInitialAccess.ok, true, 'Bob must have initial access');
    console.log(`  [L5 Step 1 Result] Bob initial access GRANTED (200 OK)`);

    // 2. Create recipient subaccount directly on-chain via Bob (zero external faucet dependency)
    const charliePrefix = `c${Date.now().toString().slice(-4)}`;
    const charlieAccountId = `${charliePrefix}.${bobAccountId}`;
    const charlieKeyPair = KeyPair.fromRandom('ed25519');
    console.log(`  [L5 Step 2] Creating recipient subaccount on-chain: ${charlieAccountId}...`);

    const bobKeyPair = KeyPair.fromString(bobAuth.secretKey);
    const bobSigner = new KeyPairSigner(bobKeyPair);
    const bobAccount = new Account(bobAccountId, provider, bobSigner);

    await bobAccount.createSubAccount({
      accountOrPrefix: charliePrefix,
      publicKey: charlieKeyPair.getPublicKey(),
      nearToTransfer: parseNearAmount('0.1'),
    });
    console.log(`  [L5 Step 2 Result] Recipient account created on-chain: ${charlieAccountId}`);

    // 3. Bob executes real on-chain nft_transfer to Charlie
    console.log(`  [L5 Step 3] Bob executing real on-chain nft_transfer to ${charlieAccountId}...`);

    const transferOutcome = await bobAccount.callFunctionRaw({
      contractId: CONTRACT_ID,
      methodName: 'nft_transfer',
      args: {
        receiver_id: charlieAccountId,
        token_id: transferTokenId,
        memo: 'Gate A.3 live revocation proof transfer',
      },
      deposit: 1n, // Exactly 1 yoctoNEAR attached deposit per NEP-171 standard
      gas: 30000000000000n, // 30 TGas
    });

    const transferTxHash = transferOutcome.transaction?.hash || transferOutcome.transaction_outcome?.id;
    console.log(`  [L5 Step 3 Result] Real nft_transfer confirmed! Tx: ${transferTxHash}`);
    assert.ok(transferTxHash, 'Transfer transaction hash must exist');

    // Wait 3.5 seconds for receipt execution across shards/blocks to reach finality
    await new Promise((resolve) => setTimeout(resolve, 3500));

    // 4. Verify token state on-chain
    const tokenAfter = await fetchNftToken({ contractId: CONTRACT_ID, tokenId: transferTokenId, provider });
    assert.equal(tokenAfter.owner_id, charlieAccountId, 'On-chain owner must now be Charlie');
    console.log(`  [L5 Step 4] On-chain token owner verified as: ${tokenAfter.owner_id}`);

    // 5. Verify Bob is IMMEDIATELY REVOKED (403 NOT_TOKEN_OWNER)
    console.log(`  [L5 Step 5] Querying space access for previous owner Bob (expect 403)...`);
    await assert.rejects(
      () =>
        verifySpaceAccess({
          accountId: bobAccountId,
          spaceId: 'space-transfer',
          provider,
          spacesConfig: liveSpacesConfig,
        }),
      (err) => {
        assert.ok(err instanceof OwnershipError);
        assert.equal(err.code, 'NOT_TOKEN_OWNER');
        assert.equal(err.status, 403);
        console.log(`  [L5 Step 5 Result] Previous owner Bob IMMEDIATELY REVOKED (403 NOT_TOKEN_OWNER)`);
        return true;
      }
    );

    // 6. Verify Charlie has ACCESS GRANTED (200 OK)
    console.log(`  [L5 Step 6] Querying space access for new owner Charlie (expect 200 OK)...`);
    const charlieAccess = await verifySpaceAccess({
      accountId: charlieAccountId,
      spaceId: 'space-transfer',
      provider,
      spacesConfig: liveSpacesConfig,
    });
    assert.equal(charlieAccess.ok, true);
    assert.equal(charlieAccess.ownerId, charlieAccountId);
    assert.deepEqual(charlieAccess.secretPayload, { clearance: 'TRANSFER_VAULT_CLEAR' });
    console.log(`  [L5 Step 6 Result] New owner Charlie GRANTED ACCESS (200 OK)`);
  });

  it('L6 [Negative]: Fails closed with 503 RPC_FAILURE on RPC network failure', async () => {
    const deadProvider = new JsonRpcProvider({ url: 'http://127.0.0.1:54321' });
    await assert.rejects(
      () =>
        verifySpaceAccess({
          accountId: 'baronal.testnet',
          spaceId: 'space-alpha',
          provider: deadProvider,
          spacesConfig: liveSpacesConfig,
        }),
      (err) => {
        assert.ok(err instanceof OwnershipError);
        assert.equal(err.code, 'RPC_FAILURE');
        assert.equal(err.status, 503);
        return true;
      }
    );
  });
});
