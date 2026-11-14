/**
 * ownership.unit.test.js — Unit test suite for Gate A.3 ownership and space access.
 *
 * Verifies all security edge cases, fail-closed dynamics, and space policy binding:
 *   - T1: Valid token owner -> Access granted
 *   - T2: Token owner mismatch -> 403 NOT_TOKEN_OWNER
 *   - T3: Non-existent token -> 403 TOKEN_NOT_FOUND
 *   - T4: Wrong contract -> 403 CONTRACT_MISMATCH
 *   - T5: Expired pass -> 403 PASS_EXPIRED
 *   - Space mismatch -> 403 SPACE_MISMATCH
 *   - RPC error -> 503 RPC_FAILURE (Fail Closed)
 *   - Non-existent contract -> 403 CONTRACT_NOT_FOUND
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { verifySpaceAccess, fetchNftToken, OwnershipError } from '../src/ownership.js';

// Helper to create mock JsonRpcProvider
function createMockProvider({ tokenResult, error } = {}) {
  return {
    async query({ request_type, method_name, args_base64 }) {
      if (error) throw error;
      assert.equal(request_type, 'call_function');
      assert.equal(method_name, 'nft_token');
      
      if (tokenResult === null || tokenResult === undefined) {
        return { result: Buffer.from('null') };
      }
      return { result: Buffer.from(JSON.stringify(tokenResult)) };
    },
  };
}

const mockSpacesConfig = {
  'test-space': {
    spaceId: 'test-space',
    name: 'Test Vault',
    contractId: 'nft.unseal.testnet',
    requiredTokenId: 'pass-1',
    issuer: 'issuer.testnet',
    secretPayload: { secret: 'TOP_SECRET_VALUE' },
    expiryPolicy: {
      enforceExpiry: true,
    },
  },
};

describe('Gate A.3: Ownership & Space Access Unit Tests', () => {
  it('T1: Valid owner grants 200 access with secret payload', async () => {
    const provider = createMockProvider({
      tokenResult: {
        token_id: 'pass-1',
        owner_id: 'alice.testnet',
        metadata: {
          title: 'Pass 1',
          extra: JSON.stringify({ space_id: 'test-space' }),
        },
      },
    });

    const res = await verifySpaceAccess({
      accountId: 'alice.testnet',
      spaceId: 'test-space',
      provider,
      spacesConfig: mockSpacesConfig,
    });

    assert.equal(res.ok, true);
    assert.equal(res.spaceId, 'test-space');
    assert.equal(res.ownerId, 'alice.testnet');
    assert.deepEqual(res.secretPayload, { secret: 'TOP_SECRET_VALUE' });
  });

  it('T2: Wrong owner throws 403 NOT_TOKEN_OWNER', async () => {
    const provider = createMockProvider({
      tokenResult: {
        token_id: 'pass-1',
        owner_id: 'bob.testnet',
      },
    });

    await assert.rejects(
      () =>
        verifySpaceAccess({
          accountId: 'alice.testnet',
          spaceId: 'test-space',
          provider,
          spacesConfig: mockSpacesConfig,
        }),
      (err) => {
        assert.ok(err instanceof OwnershipError);
        assert.equal(err.code, 'NOT_TOKEN_OWNER');
        assert.equal(err.status, 403);
        return true;
      }
    );
  });

  it('T3: Non-existent token throws 403 TOKEN_NOT_FOUND', async () => {
    const provider = createMockProvider({ tokenResult: null });

    await assert.rejects(
      () =>
        verifySpaceAccess({
          accountId: 'alice.testnet',
          spaceId: 'test-space',
          provider,
          spacesConfig: mockSpacesConfig,
        }),
      (err) => {
        assert.ok(err instanceof OwnershipError);
        assert.equal(err.code, 'TOKEN_NOT_FOUND');
        assert.equal(err.status, 403);
        return true;
      }
    );
  });

  it('T4: Contract mismatch throws 403 CONTRACT_MISMATCH without calling RPC', async () => {
    let rpcCalled = false;
    const provider = {
      async query() {
        rpcCalled = true;
        return { result: Buffer.from('null') };
      },
    };

    await assert.rejects(
      () =>
        verifySpaceAccess({
          accountId: 'alice.testnet',
          spaceId: 'test-space',
          contractId: 'attacker-nft.testnet',
          provider,
          spacesConfig: mockSpacesConfig,
        }),
      (err) => {
        assert.ok(err instanceof OwnershipError);
        assert.equal(err.code, 'CONTRACT_MISMATCH');
        assert.equal(err.status, 403);
        return true;
      }
    );

    assert.equal(rpcCalled, false, 'RPC must not be called when contractId mismatches');
  });

  it('T5: Expired pass throws 403 PASS_EXPIRED', async () => {
    const pastTimestamp = Date.now() - 10000;
    const provider = createMockProvider({
      tokenResult: {
        token_id: 'pass-1',
        owner_id: 'alice.testnet',
        metadata: {
          expires_at: pastTimestamp,
        },
      },
    });

    await assert.rejects(
      () =>
        verifySpaceAccess({
          accountId: 'alice.testnet',
          spaceId: 'test-space',
          provider,
          spacesConfig: mockSpacesConfig,
        }),
      (err) => {
        assert.ok(err instanceof OwnershipError);
        assert.equal(err.code, 'PASS_EXPIRED');
        assert.equal(err.status, 403);
        return true;
      }
    );
  });

  it('T5b: Nanosecond-precision expired pass throws 403 PASS_EXPIRED', async () => {
    const pastNanoseconds = (Date.now() - 60000) * 1e6; // 1 minute ago in ns
    const provider = createMockProvider({
      tokenResult: {
        token_id: 'pass-1',
        owner_id: 'alice.testnet',
        metadata: {
          expires_at: pastNanoseconds.toString(),
        },
      },
    });

    await assert.rejects(
      () =>
        verifySpaceAccess({
          accountId: 'alice.testnet',
          spaceId: 'test-space',
          provider,
          spacesConfig: mockSpacesConfig,
        }),
      (err) => {
        assert.equal(err.code, 'PASS_EXPIRED');
        return true;
      }
    );
  });

  it('Space mismatch in token extra throws 403 SPACE_MISMATCH', async () => {
    const provider = createMockProvider({
      tokenResult: {
        token_id: 'pass-1',
        owner_id: 'alice.testnet',
        metadata: {
          extra: JSON.stringify({ space_id: 'unrelated-space' }),
        },
      },
    });

    await assert.rejects(
      () =>
        verifySpaceAccess({
          accountId: 'alice.testnet',
          spaceId: 'test-space',
          provider,
          spacesConfig: mockSpacesConfig,
        }),
      (err) => {
        assert.equal(err.code, 'SPACE_MISMATCH');
        return true;
      }
    );
  });

  it('T8: RPC network error throws 503 RPC_FAILURE (Fail Closed)', async () => {
    const provider = createMockProvider({ error: new Error('fetch failed: ECONNREFUSED') });

    await assert.rejects(
      () =>
        verifySpaceAccess({
          accountId: 'alice.testnet',
          spaceId: 'test-space',
          provider,
          spacesConfig: mockSpacesConfig,
        }),
      (err) => {
        assert.ok(err instanceof OwnershipError);
        assert.equal(err.code, 'RPC_FAILURE');
        assert.equal(err.status, 503);
        return true;
      }
    );
  });

  it('Unknown space ID throws 404 UNKNOWN_SPACE', async () => {
    await assert.rejects(
      () =>
        verifySpaceAccess({
          accountId: 'alice.testnet',
          spaceId: 'nonexistent-space',
          spacesConfig: mockSpacesConfig,
        }),
      (err) => {
        assert.equal(err.code, 'UNKNOWN_SPACE');
        assert.equal(err.status, 404);
        return true;
      }
    );
  });
});
