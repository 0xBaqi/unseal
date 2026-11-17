/**
 * worker.js — Unseal Cloudflare Worker Entrypoint.
 *
 * Implements Web Standards Fetch API (Request/Response), D1 single-writer metadata,
 * native R2 private bucket streaming, NEP-413 Ed25519 authentication, and live
 * on-chain NEP-171 NFT access gating.
 */

import { initializeD1, issueChallengeD1, consumeChallengeD1, listSpacesD1, getSpaceD1, upsertSpaceD1 } from './worker-d1.js';
import { uploadSpacePdfWorker, downloadSpacePdfWorker } from './worker-storage.js';
import { verifyAuth, UNSEAL_RECIPIENT, createProvider } from './verifier.js';
import { verifySpaceAccess } from './ownership.js';

// ── Rate Limiter & Free-Tier Guard ──────────────────────────────────────────

class FreeTierMonitor {
  constructor() {
    this.requestsToday = 0;
    this.lastReset = Date.now();
    this.DAILY_LIMIT = 95000; // Leave 5,000 safety buffer below 100,000 free limit
  }

  checkLimit() {
    const now = Date.now();
    // Reset counter every 24 hours
    if (now - this.lastReset > 24 * 60 * 60 * 1000) {
      this.requestsToday = 0;
      this.lastReset = now;
    }
    this.requestsToday++;
    if (this.requestsToday > this.DAILY_LIMIT) {
      return false;
    }
    return true;
  }
}

export const monitor = new FreeTierMonitor();

// ── JSON Response Helpers ───────────────────────────────────────────────────

export function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'X-Content-Type-Options': 'nosniff',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      ...extraHeaders,
    },
  });
}

export function safeDecode(str) {
  if (!str) return null;
  try {
    return decodeURIComponent(str).trim();
  } catch {
    return null;
  }
}

// ── Worker Handler ──────────────────────────────────────────────────────────

export default {
  /**
   * Main fetch handler for Cloudflare Workers.
   * @param {Request} request
   * @param {object} env
   * @param {ExecutionContext} ctx
   * @returns {Promise<Response>}
   */
  async fetch(request, env, ctx) {
    const db = env.DB || env.unseal_db;
    // 1. CORS Preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
          'Access-Control-Max-Age': '86400',
        },
      });
    }

    // 2. Free Tier Daily Request Quota Circuit Breaker
    if (!monitor.checkLimit()) {
      return jsonResponse(
        { ok: false, code: 'FREE_TIER_QUOTA_EXHAUSTED', error: 'Daily free-tier request quota limit reached. Resets at 00:00 UTC.' },
        429
      );
    }

    const url = new URL(request.url);
    const pathname = url.pathname;

    // 3. Static Assets: Delegate to Cloudflare Workers Static Assets binding if present
    if ((request.method === 'GET' || request.method === 'HEAD') && env.ASSETS) {
      if (pathname === '/' || pathname === '/index.html' || pathname === '/proof.bundle.js' || pathname === '/favicon.svg' || pathname === '/favicon.ico') {
        return env.ASSETS.fetch(request);
      }
    }

    // Fallback GET routes if testing without env.ASSETS
    if (request.method === 'GET' || request.method === 'HEAD') {
      if (pathname === '/spaces' || pathname === '/api/spaces') {
        const accountId = url.searchParams.get('accountId');
        const requestedSpaceId = url.searchParams.get('spaceId');
        try {
          const spaces = await listSpacesD1(db, { accountId, requestedSpaceId });
          return jsonResponse({ ok: true, spaces });
        } catch (err) {
          return jsonResponse({ ok: false, error: err.message }, 500);
        }
      }

      if (pathname === '/' || pathname === '/index.html') {
        return new Response('<!DOCTYPE html><html><head><title>Unseal — Edge</title></head><body>Unseal Cloudflare Worker Active</body></html>', {
          headers: { 'Content-Type': 'text/html; charset=utf-8' },
        });
      }

      return jsonResponse({ ok: false, error: 'Not found' }, 404);
    }

    // 4. API POST Routes
    if (request.method !== 'POST') {
      return jsonResponse({ ok: false, error: 'Method not allowed' }, 405);
    }

    let body = {};
    try {
      body = await request.json();
    } catch {
      return jsonResponse({ ok: false, error: 'Invalid JSON body' }, 400);
    }

    // ── Route: POST /challenge ──────────────────────────────────────────────
    if (pathname === '/challenge') {
      const { accountId, recipient = UNSEAL_RECIPIENT, message = 'Sign in to Unseal Gate A.2 proof' } = body;
      if (!accountId) {
        return jsonResponse({ ok: false, code: 'MISSING_FIELD', error: 'accountId is required' }, 400);
      }
      try {
        const challenge = await issueChallengeD1(db, { accountId, recipient, message });
        return jsonResponse({
          nonceB64: challenge.nonceB64,
          message: challenge.message,
          recipient: challenge.recipient,
          accountId: challenge.accountId,
          expiresAt: challenge.expiresAt,
          ttlSeconds: 300,
        });
      } catch (err) {
        return jsonResponse({ ok: false, code: 'CHALLENGE_ERROR', error: err.message }, 500);
      }
    }

    // ── Route: POST /verify ────────────────────────────────────────────────
    if (pathname === '/verify') {
      const { accountId, publicKey, signatureB64, nonceB64, recipient = UNSEAL_RECIPIENT, callbackUrl } = body;

      for (const [name, val] of [['accountId', accountId], ['publicKey', publicKey], ['signatureB64', signatureB64], ['nonceB64', nonceB64]]) {
        if (!val) return jsonResponse({ ok: false, code: 'MISSING_FIELD', error: `${name} is required` }, 400);
      }

      let signature;
      try {
        const sigBuf = Buffer.from(signatureB64, 'base64');
        if (sigBuf.length !== 64) throw new Error(`Expected 64 bytes, got ${sigBuf.length}`);
        signature = new Uint8Array(sigBuf);
      } catch (err) {
        return jsonResponse({ ok: false, code: 'INVALID_SIGNATURE_ENCODING', error: err.message }, 400);
      }

      // ATOMIC NONCE CONSUMPTION (D1 Single-Use Replay Protection)
      let nonce, message;
      try {
        ({ nonce, message } = await consumeChallengeD1(db, { nonceB64, accountId, recipient }));
      } catch (err) {
        return jsonResponse({ ok: false, code: err.code || 'CHALLENGE_FAILED', error: err.message }, err.status || 400);
      }

      // Cryptographic + On-Chain Verification
      try {
        const provider = env.NEAR_PROVIDER || createProvider(env.NEAR_RPC_URL);
        const result = await verifyAuth({ accountId, publicKey, signature, message, recipient, nonce, callbackUrl, provider });
        return jsonResponse(result, 200);
      } catch (err) {
        const isAuthFailure = ['RECIPIENT_MISMATCH', 'BAD_SIGNATURE', 'NOT_FULL_ACCESS_KEY', 'KEY_NOT_ON_CHAIN'].includes(err.code);
        return jsonResponse({ ok: false, code: err.code ?? 'VERIFICATION_FAILED', error: err.message }, isAuthFailure ? 401 : 500);
      }
    }

    // ── Route: POST /spaces (Create / Reconfigure Space) ───────────────────
    if (pathname === '/spaces' || pathname === '/api/spaces') {
      const { spaceId, name, contractId, requiredTokenId } = body;
      for (const [fName, val] of [['spaceId', spaceId], ['name', name], ['contractId', contractId], ['requiredTokenId', requiredTokenId]]) {
        if (!val) return jsonResponse({ ok: false, code: 'MISSING_FIELD', error: `${fName} is required` }, 400);
      }

      // Authenticate creator via NEP-413
      const authRes = await this.fetch(new Request(new URL('/verify', request.url), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }), env, ctx);

      const authData = await authRes.json();
      if (authRes.status !== 200 || !authData.ok) {
        return jsonResponse(authData, authRes.status);
      }
      const { accountId } = authData;

      const existing = await getSpaceD1(db, spaceId);
      if (existing && existing.issuer && existing.issuer !== accountId) {
        return jsonResponse({
          ok: false,
          code: 'SPACE_ALREADY_EXISTS',
          error: `Space "${spaceId}" is already registered to "${existing.issuer}". Only the original creator may reconfigure it.`,
        }, 403);
      }

      await upsertSpaceD1(db, {
        spaceId,
        name,
        contractId,
        requiredTokenId,
        issuer: accountId,
        secretPayload: {
          message: `Welcome to ${name}. Access granted via verified NEP-171 NFT ownership.`,
          timestamp: new Date().toISOString(),
          clearanceLevel: 'GATE_A3_VERIFIED',
        },
        expiryPolicy: { enforceExpiry: true },
      });

      return jsonResponse({
        ok: true,
        space: { spaceId, name, contractId, requiredTokenId, issuer: accountId, hasDocument: false },
      });
    }

    // ── Route: POST /space/:spaceId/access ─────────────────────────────────
    if (pathname.startsWith('/space/') && pathname.endsWith('/access')) {
      const match = pathname.match(/^\/space\/([^/]+)\/access$/);
      const spaceId = match ? safeDecode(match[1]) : null;
      if (!spaceId) return jsonResponse({ ok: false, code: 'MALFORMED_URI', error: 'Invalid space ID' }, 400);

      // 1. Authenticate identity
      const authRes = await this.fetch(new Request(new URL('/verify', request.url), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }), env, ctx);

      const authData = await authRes.json();
      if (authRes.status !== 200 || !authData.ok) {
        return jsonResponse(authData, authRes.status);
      }
      const { accountId } = authData;
      const { tokenId, contractId } = body;

      // 2. Fetch space from D1
      const space = await getSpaceD1(db, spaceId);
      if (!space) return jsonResponse({ ok: false, code: 'UNKNOWN_SPACE', error: `Space "${spaceId}" does not exist` }, 404);

      // 3. Live on-chain NFT ownership check at finality: 'final'
      try {
        const provider = env.NEAR_PROVIDER || createProvider(env.NEAR_RPC_URL);
        const accessRes = await verifySpaceAccess({
          accountId,
          spaceId,
          tokenId,
          contractId,
          provider,
          spacesConfig: { [spaceId]: space },
        });

        return jsonResponse({ ok: true, accessGranted: true, auth: authData, access: accessRes });
      } catch (err) {
        const status = err.status || (err.code === 'RPC_FAILURE' ? 503 : 403);
        return jsonResponse({ ok: false, code: err.code || 'ACCESS_DENIED', error: err.message }, status);
      }
    }

    // ── Route: POST /space/:spaceId/upload ─────────────────────────────────
    if (pathname.startsWith('/space/') && pathname.endsWith('/upload')) {
      const match = pathname.match(/^\/space\/([^/]+)\/upload$/);
      const spaceId = match ? safeDecode(match[1]) : null;
      if (!spaceId) return jsonResponse({ ok: false, code: 'MALFORMED_URI', error: 'Invalid space ID' }, 400);

      // 1. Authenticate identity
      const authRes = await this.fetch(new Request(new URL('/verify', request.url), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }), env, ctx);

      const authData = await authRes.json();
      if (authRes.status !== 200 || !authData.ok) {
        return jsonResponse(authData, authRes.status);
      }
      const { accountId } = authData;

      // 2. Space lookup & Creator Authorization
      let space = await getSpaceD1(db, spaceId);
      if (!space) {
        const name = body.name || body.spaceName || `Space ${spaceId}`;
        const contractId = body.contractId || env.NFT_CONTRACT_ID || 'unseal-nft-55335700.testnet';
        const requiredTokenId = body.requiredTokenId || `pass-${spaceId}-1`;
        space = {
          spaceId,
          name,
          contractId,
          requiredTokenId,
          issuer: accountId,
          secretPayload: {
            message: `Welcome to ${name}. Access granted via verified NEP-171 NFT ownership.`,
            timestamp: new Date().toISOString(),
            clearanceLevel: 'GATE_A3_VERIFIED',
          },
          expiryPolicy: { enforceExpiry: true },
        };
        await upsertSpaceD1(db, space);
      } else if (!space.issuer || space.issuer !== accountId) {
        return jsonResponse({
          ok: false,
          code: 'NOT_SPACE_CREATOR',
          error: `Account "${accountId}" is not authorized to upload to space "${spaceId}" (authorized creator: "${space.issuer}")`,
        }, 403);
      }

      // 3. Extract and validate base64 PDF
      if (!body.pdfBase64) {
        return jsonResponse({ ok: false, code: 'MISSING_PDF_PAYLOAD', error: 'pdfBase64 is required' }, 400);
      }

      let pdfBuffer;
      try {
        pdfBuffer = Buffer.from(body.pdfBase64, 'base64');
      } catch (err) {
        return jsonResponse({ ok: false, code: 'INVALID_BASE64', error: 'pdfBase64 is not valid base64' }, 400);
      }

      // 4. Upload with transactional D1 metadata commit & compensating rollback
      try {
        const uploadReceipt = await uploadSpacePdfWorker({
          r2: env.UNSEAL_PRIVATE,
          db: db,
          spaceId,
          pdfBuffer,
          filename: body.filename || 'document.pdf',
          uploaderAccountId: accountId,
          bucketName: 'unseal-private',
        });

        return jsonResponse({ ok: true, upload: uploadReceipt, uploader: accountId });
      } catch (err) {
        return jsonResponse({ ok: false, code: err.code || 'STORAGE_ERROR', error: err.message }, err.status || 500);
      }
    }

    // ── Route: POST /space/:spaceId/content ────────────────────────────────
    if (pathname.startsWith('/space/') && pathname.endsWith('/content')) {
      const match = pathname.match(/^\/space\/([^/]+)\/content$/);
      const spaceId = match ? safeDecode(match[1]) : null;
      if (!spaceId) return jsonResponse({ ok: false, code: 'MALFORMED_URI', error: 'Invalid space ID' }, 400);

      // 1. Authenticate identity
      const authRes = await this.fetch(new Request(new URL('/verify', request.url), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }), env, ctx);

      const authData = await authRes.json();
      if (authRes.status !== 200 || !authData.ok) {
        return jsonResponse(authData, authRes.status);
      }
      const { accountId } = authData;
      const { tokenId, contractId } = body;

      // 2. Space lookup
      const space = await getSpaceD1(db, spaceId);
      if (!space) return jsonResponse({ ok: false, code: 'UNKNOWN_SPACE', error: `Space "${spaceId}" does not exist` }, 404);

      // 3. Live on-chain access gating
      try {
        const provider = env.NEAR_PROVIDER || createProvider(env.NEAR_RPC_URL);
        await verifySpaceAccess({
          accountId,
          spaceId,
          tokenId,
          contractId,
          provider,
          spacesConfig: { [spaceId]: space },
        });
      } catch (err) {
        const status = err.status || (err.code === 'RPC_FAILURE' ? 503 : 403);
        return jsonResponse({ ok: false, code: err.code || 'ACCESS_DENIED', error: err.message }, status);
      }

      // 4. Stream PDF from private R2 bucket
      try {
        return await downloadSpacePdfWorker({
          r2: env.UNSEAL_PRIVATE,
          db: db,
          spaceId,
        });
      } catch (err) {
        return jsonResponse({ ok: false, code: err.code || 'STORAGE_ERROR', error: err.message }, err.status || 502);
      }
    }

    return jsonResponse({ ok: false, error: 'Not found' }, 404);
  },
};
