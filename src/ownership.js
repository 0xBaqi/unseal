/**
 * ownership.js — Live on-chain NEP-171 NFT ownership and space access verification.
 *
 * Implements Gate A.3 on-chain access gating:
 *   1. Zero caching: queries NEAR RPC view method `nft_token` with `finality: 'final'` on every call.
 *   2. Strict space-to-token binding: enforces contract ID, token ID, and space policy.
 *   3. Expiry enforcement: validates pass expiration timestamps.
 *   4. Fail closed: missing token, wrong contract, owner mismatch, expired pass, or RPC errors
 *      all resolve to DENY.
 */

import { JsonRpcProvider } from 'near-api-js';
import { TESTNET_RPC_URL, createProvider } from './verifier.js';

// ── Default Spaces Configuration ─────────────────────────────────────────────

export const DEFAULT_SPACES = {
  'space-alpha': {
    spaceId: 'space-alpha',
    name: 'Unseal Alpha Secret Space',
    contractId: process.env.NFT_CONTRACT_ID || 'unseal-nft-55335700.testnet',
    requiredTokenId: 'pass-alpha-1',
    issuer: 'baronal.testnet',
    secretPayload: {
      message: 'Welcome to Unseal Alpha Space. Access granted via verified NEP-171 NFT ownership.',
      timestamp: new Date().toISOString(),
      clearanceLevel: 'GATE_A3_VERIFIED',
    },
    expiryPolicy: {
      enforceExpiry: true,
    },
  },
  'space-transfer': {
    spaceId: 'space-transfer',
    name: 'Unseal Transferable Test Space',
    contractId: process.env.NFT_CONTRACT_ID || 'unseal-nft-55335700.testnet',
    requiredTokenId: 'pass-transfer-493545',
    issuer: 'baronal.testnet',
    secretPayload: {
      message: 'Welcome to Unseal Transfer Test Space. Access granted via transferred NEP-171 NFT pass.',
      timestamp: new Date().toISOString(),
      clearanceLevel: 'GATE_A3_TRANSFEREE_VERIFIED',
    },
    expiryPolicy: {
      enforceExpiry: true,
    },
  },
};

// ── Custom Error Class ───────────────────────────────────────────────────────

export class OwnershipError extends Error {
  /**
   * @param {string} code
   * @param {string} message
   * @param {number} [status=403]
   */
  constructor(code, message, status = 403) {
    super(`${code}: ${message}`);
    this.name = 'OwnershipError';
    this.code = code;
    this.status = status;
  }
}

// ── On-chain Token Fetching ──────────────────────────────────────────────────

/**
 * Fetch token data from the NEP-171 contract via RPC.
 * Queries with `finality: 'final'` to ensure zero stale state.
 *
 * @param {object} params
 * @param {string} params.contractId
 * @param {string} params.tokenId
 * @param {JsonRpcProvider} [params.provider]
 * @returns {Promise<object|null>} NFT Token object or null if not found
 */
export async function fetchNftToken({ contractId, tokenId, provider = createProvider() }) {
  if (!contractId) throw new OwnershipError('MISSING_CONTRACT_ID', 'Contract ID is required', 400);
  if (!tokenId) throw new OwnershipError('MISSING_TOKEN_ID', 'Token ID is required', 400);

  try {
    const res = await provider.query({
      request_type: 'call_function',
      finality: 'final',
      account_id: contractId,
      method_name: 'nft_token',
      args_base64: Buffer.from(JSON.stringify({ token_id: tokenId })).toString('base64'),
    });

    if (!res || !res.result) return null;

    const rawString = Buffer.from(res.result).toString('utf8');
    if (!rawString || rawString === 'null') return null;

    return JSON.parse(rawString);
  } catch (err) {
    // If the contract returned a panic or doesn't exist, fail closed
    if (err instanceof OwnershipError) throw err;
    const msg = err.message || String(err);
    if (msg.includes('does not exist') || msg.includes('MethodNotFound') || msg.includes('CompilationError')) {
      throw new OwnershipError('CONTRACT_NOT_FOUND', `NFT contract ${contractId} is invalid or not deployed: ${msg}`, 403);
    }
    throw new OwnershipError('RPC_FAILURE', `Failed to query NEAR RPC for nft_token: ${msg}`, 503);
  }
}

// ── Space Policy Verification ────────────────────────────────────────────────

/**
 * Verify that an authenticated account owns the required NFT for a space.
 *
 * @param {object} params
 * @param {string} params.accountId - The NEP-413 verified NEAR account
 * @param {string} params.spaceId - Target space identifier
 * @param {string} [params.tokenId] - Token ID (defaults to space requirement)
 * @param {string} [params.contractId] - Contract ID (defaults to space configuration)
 * @param {JsonRpcProvider} [params.provider] - NEAR RPC provider
 * @param {object} [params.spacesConfig] - Spaces registry (defaults to DEFAULT_SPACES)
 * @returns {Promise<object>} Access grant result
 */
export async function verifySpaceAccess({
  accountId,
  spaceId,
  tokenId,
  contractId,
  provider = createProvider(),
  spacesConfig = DEFAULT_SPACES,
}) {
  if (!accountId) throw new OwnershipError('MISSING_ACCOUNT_ID', 'accountId is required', 400);
  if (!spaceId) throw new OwnershipError('MISSING_SPACE_ID', 'spaceId is required', 400);

  const space = spacesConfig[spaceId];
  if (!space) {
    throw new OwnershipError('UNKNOWN_SPACE', `Space "${spaceId}" does not exist`, 404);
  }

  const targetContractId = contractId || space.contractId;
  const targetTokenId = tokenId || space.requiredTokenId;

  if (!targetContractId) {
    throw new OwnershipError('SPACE_NOT_CONFIGURED', `Space "${spaceId}" has no contract ID configured`, 500);
  }

  // Contract match enforcement (prevent contract spoofing)
  if (space.contractId && targetContractId !== space.contractId) {
    throw new OwnershipError(
      'CONTRACT_MISMATCH',
      `Provided contract "${targetContractId}" does not match space policy contract "${space.contractId}"`,
      403
    );
  }

  // Token ID match enforcement (prevent collection-level cross-space pollution)
  if (space.requiredTokenId && targetTokenId !== space.requiredTokenId) {
    throw new OwnershipError(
      'TOKEN_MISMATCH',
      `Provided token "${targetTokenId}" does not match space policy required token "${space.requiredTokenId}"`,
      403
    );
  }

  // Live on-chain view call with finality: 'final'
  const token = await fetchNftToken({ contractId: targetContractId, tokenId: targetTokenId, provider });

  if (!token) {
    throw new OwnershipError('TOKEN_NOT_FOUND', `Token "${targetTokenId}" does not exist on contract "${targetContractId}"`, 403);
  }

  // Ownership check
  if (token.owner_id !== accountId) {
    throw new OwnershipError(
      'NOT_TOKEN_OWNER',
      `Account "${accountId}" is not the current owner of token "${targetTokenId}" (current owner: "${token.owner_id}")`,
      403
    );
  }

  // Space extra validation (if token metadata has space_id binding)
  let extra = null;
  if (token.metadata?.extra) {
    try {
      extra = typeof token.metadata.extra === 'string' ? JSON.parse(token.metadata.extra) : token.metadata.extra;
      if (extra?.space_id && extra.space_id !== spaceId) {
        throw new OwnershipError(
          'SPACE_MISMATCH',
          `Token bound to space "${extra.space_id}", cannot access space "${spaceId}"`,
          403
        );
      }
    } catch (e) {
      if (e instanceof OwnershipError) throw e;
      // If extra is not valid JSON, ignore extra space_id check
    }
  }

  // Expiry check
  if (space.expiryPolicy?.enforceExpiry) {
    let expiresAt = null;
    if (token.metadata?.expires_at) {
      const expNum = Number(token.metadata.expires_at);
      // NEAR timestamps may be in nanoseconds (19 digits) or milliseconds (13 digits)
      expiresAt = expNum > 1e16 ? Math.floor(expNum / 1e6) : expNum;
    } else if (extra?.expires_at) {
      expiresAt = Number(extra.expires_at);
    }

    if (expiresAt && expiresAt <= Date.now()) {
      throw new OwnershipError('PASS_EXPIRED', `Access pass "${targetTokenId}" expired at ${new Date(expiresAt).toISOString()}`, 403);
    }
  }

  return {
    ok: true,
    spaceId,
    spaceName: space.name,
    contractId: targetContractId,
    tokenId: targetTokenId,
    ownerId: token.owner_id,
    secretPayload: space.secretPayload,
    verifiedAt: new Date().toISOString(),
  };
}
