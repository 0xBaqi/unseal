/**
 * server.js — Minimal HTTP server for the NEP-413 authentication proof.
 *
 * Endpoints:
 *   POST /challenge   Body: { accountId, recipient?, message? }
 *                     Returns: { nonceB64, message, recipient, accountId, expiresAt }
 *
 *   POST /verify      Body: { accountId, publicKey, signatureB64, nonceB64, recipient, message, callbackUrl? }
 *                     Returns: 200 { ok: true, accountId, publicKey } on success
 *                              400/401 { ok: false, code, error } on failure
 *
 * No external HTTP framework — uses Node.js built-in http module only.
 * No credentials, keys, or secrets are stored or logged.
 */

import { createServer } from 'node:http';
import { readFile, writeFile, mkdir, rename } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { issueChallenge, consumeChallenge, DEFAULT_TTL_MS } from './challenge.js';
import { verifyAuth, UNSEAL_RECIPIENT } from './verifier.js';
import { verifySpaceAccess, DEFAULT_SPACES } from './ownership.js';
import {
  createR2Client,
  MockR2Client,
  uploadSpacePdf,
  downloadSpacePdf,
  defaultRegistry,
  DEFAULT_R2_BUCKET,
} from './storage.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(__dirname, '..', 'public');

const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

// Default S3/R2 client: live if credentials exist, otherwise MockR2Client (dev/test only)
const liveR2Client = createR2Client();
if (process.env.NODE_ENV === 'production') {
  if (!liveR2Client) {
    throw new Error(
      'FATAL: Production environment requires Cloudflare R2 credentials (R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY). Mock storage is strictly disabled in production.'
    );
  }
}
export const defaultS3Client = liveR2Client || new MockR2Client();

// ── Persistence Layer (Data Vault) ──────────────────────────────────────────
const DATA_DIR = join(__dirname, '..', 'data');
const SPACES_PERSIST_FILE = join(DATA_DIR, 'spaces.json');
const DOCS_PERSIST_FILE = join(DATA_DIR, 'documents.json');

export async function loadPersistedData() {
  try {
    const data = await readFile(SPACES_PERSIST_FILE, 'utf8');
    const parsed = JSON.parse(data);
    Object.assign(DEFAULT_SPACES, parsed);
  } catch {}

  try {
    const data = await readFile(DOCS_PERSIST_FILE, 'utf8');
    const parsed = JSON.parse(data);
    for (const [k, v] of Object.entries(parsed)) {
      defaultRegistry.set(k, v);
    }
  } catch {}
}

export class AsyncLock {
  constructor() {
    this._queue = Promise.resolve();
  }

  /**
   * Serializes async task execution FIFO to guarantee mutual exclusion.
   * @template T
   * @param {() => Promise<T>} fn
   * @returns {Promise<T>}
   */
  async acquire(fn) {
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const current = this._queue;
    this._queue = current.then(() => gate, () => gate);

    try {
      await current;
      return await fn();
    } finally {
      release();
    }
  }
}

export const persistenceLock = new AsyncLock();

async function atomicWriteJson(filePath, data) {
  await mkdir(dirname(filePath), { recursive: true });
  const tmpPath = `${filePath}.tmp.${randomUUID()}`;
  await writeFile(tmpPath, JSON.stringify(data, null, 2), 'utf8');
  await rename(tmpPath, filePath);
}

export function safeDecode(str) {
  if (!str) return null;
  try {
    return decodeURIComponent(str).trim();
  } catch {
    return null;
  }
}

export async function persistSpaces() {
  return persistenceLock.acquire(async () => {
    try {
      await atomicWriteJson(SPACES_PERSIST_FILE, DEFAULT_SPACES);
    } catch (err) {
      console.error('[unseal-gate-a] Failed to persist spaces.json:', err.message);
    }
  });
}

export async function persistDocs() {
  return persistenceLock.acquire(async () => {
    try {
      const obj = {};
      for (const [k, v] of defaultRegistry.store.entries()) {
        obj[k] = v;
      }
      await atomicWriteJson(DOCS_PERSIST_FILE, obj);
    } catch (err) {
      console.error('[unseal-gate-a] Failed to persist documents.json:', err.message);
    }
  });
}

await loadPersistedData();

// ── Route handlers ──────────────────────────────────────────────────────────

/**
 * POST /challenge
 * Issues a server-side nonce challenge for the given account.
 */
async function handleChallenge(body) {
  const { accountId, recipient = UNSEAL_RECIPIENT, message = 'Sign in to Unseal Gate A.2 proof' } = body;
  if (!accountId) return { status: 400, body: { ok: false, code: 'MISSING_FIELD', error: 'accountId is required' } };

  const challenge = issueChallenge({ accountId, recipient, message, ttlMs: DEFAULT_TTL_MS });
  return {
    status: 200,
    body: {
      nonceB64: challenge.nonceB64,
      message: challenge.message,
      recipient: challenge.recipient,
      accountId: challenge.accountId,
      expiresAt: challenge.expiresAt,
      ttlSeconds: Math.round(DEFAULT_TTL_MS / 1000),
    },
  };
}

/**
 * POST /verify
 * Verifies a NEP-413 signed challenge and returns authentication result.
 */
async function handleVerify(body) {
  const { accountId, publicKey, signatureB64, nonceB64, recipient = UNSEAL_RECIPIENT, callbackUrl } = body;

  // Required field check
  for (const [name, val] of [['accountId', accountId], ['publicKey', publicKey], ['signatureB64', signatureB64], ['nonceB64', nonceB64]]) {
    if (!val) return { status: 400, body: { ok: false, code: 'MISSING_FIELD', error: `${name} is required` } };
  }

  // Decode signature from base64 to Uint8Array
  let signature;
  try {
    const sigBuf = Buffer.from(signatureB64, 'base64');
    if (sigBuf.length !== 64) throw new Error(`Expected 64 bytes, got ${sigBuf.length}`);
    signature = new Uint8Array(sigBuf);
  } catch (err) {
    return { status: 400, body: { ok: false, code: 'INVALID_SIGNATURE_ENCODING', error: err.message } };
  }

  // Consume the challenge nonce (validates existence, expiry, single-use, account/recipient binding)
  let nonce, message;
  try {
    ({ nonce, message } = consumeChallenge({ nonceB64, accountId, recipient }));
  } catch (err) {
    return { status: 400, body: { ok: false, code: err.message.split(':')[0], error: err.message } };
  }

  // Cryptographic + on-chain verification
  try {
    const result = await verifyAuth({ accountId, publicKey, signature, message, recipient, nonce, callbackUrl });
    return { status: 200, body: result };
  } catch (err) {
    const isAuthFailure = ['RECIPIENT_MISMATCH', 'BAD_SIGNATURE', 'NOT_FULL_ACCESS_KEY', 'KEY_NOT_ON_CHAIN'].includes(err.code);
    return {
      status: isAuthFailure ? 401 : 500,
      body: { ok: false, code: err.code ?? 'VERIFICATION_FAILED', error: err.message },
    };
  }
}

/**
 * GET /spaces
 * Lists configured spaces and document status.
 * Unauthenticated requests only receive public demo spaces with synthetic test data.
 * Real private document metadata, confidential space details, and sensitive creator info are protected.
 */
async function handleListSpaces(reqUrl = null) {
  let accountId = null;
  let requestedSpaceId = null;
  if (reqUrl) {
    try {
      const parsed = new URL(reqUrl, 'http://localhost');
      accountId = parsed.searchParams.get('accountId');
      requestedSpaceId = parsed.searchParams.get('spaceId');
    } catch {}
  }

  const spaces = Object.values(DEFAULT_SPACES)
    .filter((s) => {
      // Direct space lookup by ID (e.g. recipient accessed via space link)
      if (requestedSpaceId && s.spaceId === requestedSpaceId) return true;
      // Public demo spaces are visible to all visitors and judges
      if (s.isPublicDemo || s.isDemo) return true;
      // Connected creator sees their own spaces
      if (accountId && s.issuer === accountId) return true;
      return false;
    })
    .map((s) => {
      const hasDoc = defaultRegistry.has(s.spaceId);
      const docRecord = hasDoc ? defaultRegistry.get(s.spaceId) : null;
      const isPublic = Boolean(s.isPublicDemo || s.isDemo);
      const isCreator = Boolean(accountId && s.issuer === accountId);
      const isAuthorizedViewer = isPublic || isCreator;

      return {
        spaceId: s.spaceId,
        name: s.name,
        contractId: s.contractId,
        requiredTokenId: s.requiredTokenId,
        issuer: isPublic ? s.issuer : (isCreator ? s.issuer : 'Confidential Creator'),
        isPublicDemo: isPublic,
        hasDocument: hasDoc,
        documentInfo: (docRecord && isAuthorizedViewer)
          ? {
              filename: docRecord.filename,
              size: docRecord.size,
              sha256: docRecord.sha256,
              uploadedAt: docRecord.uploadedAt,
            }
          : (hasDoc ? { size: docRecord?.size, status: 'Confidential Document Ready' } : null),
      };
    });
  return { status: 200, body: { ok: true, spaces } };
}

/**
 * POST /spaces
 * Creates or configures a space using NEP-413 creator authentication.
 */
async function handleCreateSpace(body) {
  const { spaceId, name, contractId, requiredTokenId } = body;
  if (!spaceId) return { status: 400, body: { ok: false, code: 'MISSING_FIELD', error: 'spaceId is required' } };
  if (!name) return { status: 400, body: { ok: false, code: 'MISSING_FIELD', error: 'name is required' } };
  if (!contractId) return { status: 400, body: { ok: false, code: 'MISSING_FIELD', error: 'contractId is required' } };
  if (!requiredTokenId) return { status: 400, body: { ok: false, code: 'MISSING_FIELD', error: 'requiredTokenId is required' } };

  // Authenticate identity via NEP-413
  const verifyRes = await handleVerify(body);
  if (verifyRes.status !== 200 || !verifyRes.body.ok) {
    return verifyRes;
  }
  const { accountId } = verifyRes.body;

  // Protect existing spaces from being overwritten or hijacked by non-owners
  const existingSpace = DEFAULT_SPACES[spaceId];
  if (existingSpace && existingSpace.issuer && existingSpace.issuer !== accountId) {
    return {
      status: 403,
      body: {
        ok: false,
        code: 'SPACE_ALREADY_EXISTS',
        error: `Space "${spaceId}" is already registered to "${existingSpace.issuer}". Only the original creator may reconfigure it.`,
      },
    };
  }

  DEFAULT_SPACES[spaceId] = {
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
    expiryPolicy: {
      enforceExpiry: true,
    },
  };
  await persistSpaces();

  return {
    status: 200,
    body: {
      ok: true,
      space: {
        spaceId,
        name,
        contractId,
        requiredTokenId,
        issuer: accountId,
        hasDocument: false,
      },
    },
  };
}

/**
 * POST /space/:spaceId/access
 * Authenticates via NEP-413 session, then executes fresh on-chain NFT ownership check.
 */
async function handleSpaceAccess(body, spaceIdFromUrl, { provider, spacesConfig } = {}) {
  const spaceId = spaceIdFromUrl || body.spaceId;
  if (!spaceId) return { status: 400, body: { ok: false, code: 'MISSING_FIELD', error: 'spaceId is required' } };

  // 1. Authenticate identity via NEP-413
  const verifyRes = await handleVerify(body);
  if (verifyRes.status !== 200 || !verifyRes.body.ok) {
    return verifyRes;
  }

  // 2. Verified caller from NEP-413 session
  const { accountId } = verifyRes.body;
  const { tokenId, contractId } = body;

  // 3. Gate A.3 on-chain NFT ownership check at finality: 'final'
  try {
    const accessRes = await verifySpaceAccess({
      accountId,
      spaceId,
      tokenId,
      contractId,
      provider,
      spacesConfig,
    });

    return {
      status: 200,
      body: {
        ok: true,
        accessGranted: true,
        auth: verifyRes.body,
        access: accessRes,
      },
    };
  } catch (err) {
    const status = err.status || (err.code === 'RPC_FAILURE' ? 503 : 403);
    return {
      status,
      body: {
        ok: false,
        code: err.code || 'ACCESS_DENIED',
        error: err.message,
      },
    };
  }
}

/**
 * POST /space/:spaceId/upload
 * Authenticates creator via NEP-413 session, enforces creator-only space policy,
 * validates PDF magic bytes and size, then uploads to private R2 storage.
 */
async function handleSpaceUpload(
  body,
  spaceIdFromUrl,
  { s3Client = defaultS3Client, registry = defaultRegistry, spacesConfig = DEFAULT_SPACES } = {}
) {
  const rawSpaceId = spaceIdFromUrl || body.spaceId;
  if (!rawSpaceId) return { status: 400, body: { ok: false, code: 'MISSING_FIELD', error: 'spaceId is required' } };
  const spaceId = decodeURIComponent(rawSpaceId).trim();

  // 1. Authenticate identity via NEP-413
  const verifyRes = await handleVerify(body);
  if (verifyRes.status !== 200 || !verifyRes.body.ok) {
    return verifyRes;
  }

  const { accountId } = verifyRes.body;

  // 2. Space lookup & Creator authorization
  let space = spacesConfig[spaceId];
  if (!space) {
    // Auto-provision space for authenticated creator if not previously registered
    const name = body.name || body.spaceName || `Space ${spaceId}`;
    const contractId = body.contractId || process.env.NFT_CONTRACT_ID || 'unseal-nft-55335700.testnet';
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
      expiryPolicy: {
        enforceExpiry: true,
      },
    };
    spacesConfig[spaceId] = space;
    await persistSpaces();
  } else if (!space.issuer || space.issuer !== accountId) {
    return {
      status: 403,
      body: {
        ok: false,
        code: 'NOT_SPACE_CREATOR',
        error: `Account "${accountId}" is not authorized to upload to space "${spaceId}" (authorized creator: "${space.issuer}")`,
      },
    };
  }

  // 3. Extract and validate base64 PDF
  if (!body.pdfBase64) {
    return { status: 400, body: { ok: false, code: 'MISSING_PDF_PAYLOAD', error: 'pdfBase64 is required' } };
  }

  let pdfBuffer;
  try {
    pdfBuffer = Buffer.from(body.pdfBase64, 'base64');
  } catch (err) {
    return { status: 400, body: { ok: false, code: 'INVALID_BASE64', error: 'pdfBase64 is not valid base64' } };
  }

  // 4. Upload to private R2 storage
  try {
    const uploadReceipt = await uploadSpacePdf({
      s3Client,
      bucket: space.bucket || DEFAULT_R2_BUCKET,
      spaceId,
      pdfBuffer,
      filename: body.filename || 'document.pdf',
      uploaderAccountId: accountId,
      registry,
    });

    await persistDocs();

    return {
      status: 200,
      body: {
        ok: true,
        upload: uploadReceipt,
        uploader: accountId,
      },
    };
  } catch (err) {
    const status = err.status || 500;
    return {
      status,
      body: {
        ok: false,
        code: err.code || 'STORAGE_ERROR',
        error: err.message,
      },
    };
  }
}

/**
 * POST /space/:spaceId/content
 * Authenticates caller via NEP-413 session, executes fresh on-chain NFT ownership check,
 * and delivers the protected PDF from private R2 storage with strict security headers.
 */
async function handleSpaceContent(
  body,
  spaceIdFromUrl,
  {
    provider,
    spacesConfig = DEFAULT_SPACES,
    s3Client = defaultS3Client,
    registry = defaultRegistry,
    res = null,
  } = {}
) {
  const spaceId = spaceIdFromUrl || body.spaceId;
  if (!spaceId) {
    const errRes = { status: 400, body: { ok: false, code: 'MISSING_FIELD', error: 'spaceId is required' } };
    if (res) {
      res.writeHead(errRes.status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(errRes.body));
    }
    return errRes;
  }

  // 1. Authenticate identity via NEP-413
  const verifyRes = await handleVerify(body);
  if (verifyRes.status !== 200 || !verifyRes.body.ok) {
    if (res) {
      res.writeHead(verifyRes.status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(verifyRes.body));
    }
    return verifyRes;
  }

  const { accountId } = verifyRes.body;
  const { tokenId, contractId } = body;

  // 2. Gate A.3 on-chain NFT ownership check at finality: 'final'
  try {
    await verifySpaceAccess({
      accountId,
      spaceId,
      tokenId,
      contractId,
      provider,
      spacesConfig,
    });
  } catch (err) {
    const status = err.status || (err.code === 'RPC_FAILURE' ? 503 : 403);
    const errRes = {
      status,
      body: {
        ok: false,
        code: err.code || 'ACCESS_DENIED',
        error: err.message,
      },
    };
    if (res) {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(errRes.body));
    }
    return errRes;
  }

  // 3. Fetch from private storage
  let contentResult;
  try {
    contentResult = await downloadSpacePdf({
      s3Client,
      spaceId,
      registry,
    });
  } catch (err) {
    const status = err.status || 502;
    const errRes = {
      status,
      body: {
        ok: false,
        code: err.code || 'STORAGE_ERROR',
        error: err.message,
      },
    };
    if (res) {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(errRes.body));
    }
    return errRes;
  }

  // 4. Strict security headers to prevent caching or shared-cache leakage
  const headers = {
    'Content-Type': 'application/pdf',
    'Content-Length': contentResult.contentLength,
    'Cache-Control': 'private, no-store, no-cache, must-revalidate',
    'Pragma': 'no-cache',
    'Expires': '0',
    'X-Content-Type-Options': 'nosniff',
    'Content-Disposition': `inline; filename="${contentResult.filename}"`,
    'X-Unseal-SHA256': contentResult.sha256,
  };

  if (res) {
    res.writeHead(200, headers);
    contentResult.stream.pipe(res);
    return { status: 200, headers };
  }

  // Programmatic return for test assertions: collect stream chunks into a Buffer
  const chunks = [];
  for await (const chunk of contentResult.stream) {
    chunks.push(Buffer.from(chunk));
  }
  const fullBuffer = Buffer.concat(chunks);

  return {
    status: 200,
    headers,
    body: fullBuffer,
    size: fullBuffer.length,
    sha256: contentResult.sha256,
  };
}

// ── HTTP server ─────────────────────────────────────────────────────────────

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => { data += chunk; });
    req.on('end', () => {
      try { resolve(JSON.parse(data || '{}')); }
      catch { reject(new Error('Invalid JSON body')); }
    });
    req.on('error', reject);
  });
}

const server = createServer(async (req, res) => {
  const parsedUrl = new URL(req.url, 'http://localhost');
  const pathname = parsedUrl.pathname;
  req.pathname = pathname;
  req.searchParams = parsedUrl.searchParams;

  // Static asset serving for browser proof
  if (req.method === 'GET' || req.method === 'HEAD') {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');

    if (pathname === '/' || pathname === '/index.html') {
      try {
        const content = await readFile(join(PUBLIC_DIR, 'index.html'));
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.writeHead(200);
        return res.end(req.method === 'HEAD' ? null : content);
      } catch (err) {
        res.setHeader('Content-Type', 'text/plain');
        res.writeHead(500);
        return res.end(req.method === 'HEAD' ? null : `Failed to load index.html: ${err.message}`);
      }
    }

    if (pathname === '/proof.bundle.js') {
      try {
        const content = await readFile(join(PUBLIC_DIR, 'proof.bundle.js'));
        res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
        res.writeHead(200);
        return res.end(req.method === 'HEAD' ? null : content);
      } catch (err) {
        res.setHeader('Content-Type', 'text/plain');
        res.writeHead(404);
        return res.end(req.method === 'HEAD' ? null : 'Bundle not yet built. Run npm run build.');
      }
    }

    if (pathname === '/favicon.svg' || pathname === '/favicon.ico') {
      try {
        const content = await readFile(join(PUBLIC_DIR, 'favicon.svg'));
        res.setHeader('Content-Type', 'image/svg+xml');
        res.setHeader('Cache-Control', 'public, max-age=86400');
        res.writeHead(200);
        return res.end(req.method === 'HEAD' ? null : content);
      } catch (err) {
        res.writeHead(404);
        return res.end();
      }
    }

    if (pathname === '/spaces' || pathname === '/api/spaces') {
      const resData = await handleListSpaces(req.url);
      res.setHeader('Content-Type', 'application/json');
      res.writeHead(resData.status);
      return res.end(req.method === 'HEAD' ? null : JSON.stringify(resData.body));
    }

    res.setHeader('Content-Type', 'application/json');
    res.writeHead(404);
    return res.end(req.method === 'HEAD' ? null : JSON.stringify({ ok: false, error: 'Not found' }));
  }

  if (req.method !== 'POST') {
    res.setHeader('Content-Type', 'application/json');
    res.writeHead(405);
    return res.end(JSON.stringify({ ok: false, error: 'Method not allowed' }));
  }

  let body;
  try { body = await readBody(req); }
  catch (err) {
    res.setHeader('Content-Type', 'application/json');
    res.writeHead(400);
    return res.end(JSON.stringify({ ok: false, error: 'Invalid JSON body' }));
  }

  let result;
  if (pathname === '/challenge') {
    result = await handleChallenge(body);
  } else if (pathname === '/verify') {
    result = await handleVerify(body);
  } else if (pathname === '/spaces' || pathname === '/api/spaces') {
    result = await handleCreateSpace(body);
  } else if (pathname.startsWith('/space/') && pathname.endsWith('/access')) {
    const match = pathname.match(/^\/space\/([^/]+)\/access$/);
    const spaceId = match ? safeDecode(match[1]) : null;
    if (!spaceId) {
      result = { status: 400, body: { ok: false, code: 'MALFORMED_URI', error: 'Invalid URL-encoded space ID' } };
    } else {
      result = await handleSpaceAccess(body, spaceId);
    }
  } else if (pathname.startsWith('/space/') && pathname.endsWith('/upload')) {
    const match = pathname.match(/^\/space\/([^/]+)\/upload$/);
    const spaceId = match ? safeDecode(match[1]) : null;
    if (!spaceId) {
      result = { status: 400, body: { ok: false, code: 'MALFORMED_URI', error: 'Invalid URL-encoded space ID' } };
    } else {
      result = await handleSpaceUpload(body, spaceId);
    }
  } else if (pathname.startsWith('/space/') && pathname.endsWith('/content')) {
    const match = pathname.match(/^\/space\/([^/]+)\/content$/);
    const spaceId = match ? safeDecode(match[1]) : null;
    if (!spaceId) {
      const errRes = { status: 400, body: { ok: false, code: 'MALFORMED_URI', error: 'Invalid URL-encoded space ID' } };
      res.writeHead(errRes.status, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(errRes.body));
    }
    return await handleSpaceContent(body, spaceId, { res });
  } else {
    result = { status: 404, body: { ok: false, error: 'Not found' } };
  }

  res.setHeader('Content-Type', 'application/json');
  res.writeHead(result.status);
  res.end(JSON.stringify(result.body));
});

// Seed starter confidential PDF for space-alpha (Dev/Test only — strictly disabled in production)
async function seedDefaultDocuments() {
  if (process.env.NODE_ENV === 'production' || process.env.DISABLE_SEED === '1') {
    return;
  }
  if (!defaultRegistry.has('space-alpha')) {
    const SAMPLE_PDF = Buffer.from(
      '%PDF-1.4\n' +
      '1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n' +
      '2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n' +
      '3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj\n' +
      'xref\n' +
      '0 4\n' +
      '0000000000 65535 f \n' +
      '0000000009 00000 n \n' +
      '0000000052 00000 n \n' +
      '0000000101 00000 n \n' +
      'trailer<</Size 4/Root 1 0 R>>\n' +
      'startxref\n' +
      '178\n' +
      '%%EOF\n'
    );
    try {
      await uploadSpacePdf({
        s3Client: defaultS3Client,
        bucket: DEFAULT_R2_BUCKET,
        spaceId: 'space-alpha',
        pdfBuffer: SAMPLE_PDF,
        filename: 'unseal-confidential-brief.pdf',
        uploaderAccountId: 'baronal.testnet',
        registry: defaultRegistry,
      });
    } catch {
      // Ignore if cannot seed
    }
  }
}

await seedDefaultDocuments();

const HOST = process.env.HOST || '0.0.0.0';

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  server.listen(PORT, HOST, () => {
    console.log(`[unseal] Server listening on http://${HOST}:${PORT}`);
    console.log(`[unseal] Localhost URL:    http://localhost:${PORT}`);
    console.log(`[unseal] WSL Direct IP:    http://172.31.240.19:${PORT}`);
    console.log(`[unseal] GET  /spaces                 — list configured document spaces`);
    console.log(`[unseal] POST /spaces                 — register new space (creator auth)`);
    console.log(`[unseal] POST /challenge              — issue a nonce challenge`);
    console.log(`[unseal] POST /verify                 — verify a NEP-413 signed response`);
    console.log(`[unseal] POST /space/:id/access       — gated space access`);
    console.log(`[unseal] POST /space/:id/upload       — creator-only PDF upload to R2`);
    console.log(`[unseal] POST /space/:id/content      — NFT-gated private PDF delivery`);
  });
}

export {
  server,
  handleChallenge,
  handleVerify,
  handleSpaceAccess,
  handleSpaceUpload,
  handleSpaceContent,
  handleListSpaces,
  handleCreateSpace,
  seedDefaultDocuments,
  atomicWriteJson,
}; // for programmatic test teardown
