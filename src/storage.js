/**
 * storage.js — Private PDF Storage and Delivery via Cloudflare R2 / S3.
 *
 * Implements Gate A.4 secure storage and gated delivery:
 *   1. Cloudflare R2 private bucket integration (unseal-private) via @aws-sdk/client-s3.
 *   2. PDF magic bytes (%PDF-) validation and strict file size enforcement.
 *   3. Unpredictable private object key generation (never guessable).
 *   4. Server-controlled space-to-object mapping (zero client trust).
 *   5. Safe streaming delivery through authorized backend with private no-store headers.
 *   6. Fail-closed error handling (no secrets or keys leaked).
 *   7. Dual-mode support: live Cloudflare R2 when credentials are configured,
 *      and high-fidelity in-memory S3 adapter for deterministic unit testing.
 */

import { randomUUID, createHash } from 'node:crypto';
import { Readable } from 'node:stream';
import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  DeleteObjectCommand,
} from '@aws-sdk/client-s3';

// ── Constants & Configuration ───────────────────────────────────────────────

export const DEFAULT_R2_BUCKET = process.env.R2_BUCKET_NAME || 'unseal-private';
export const MAX_PDF_SIZE_BYTES = 15 * 1024 * 1024; // 15 MB limit
export const PDF_MAGIC_BYTES = Buffer.from([0x25, 0x50, 0x44, 0x46, 0x2d]); // "%PDF-"

export class StorageError extends Error {
  /**
   * @param {string} code
   * @param {string} message
   * @param {number} [status=500]
   */
  constructor(code, message, status = 500) {
    super(`${code}: ${message}`);
    this.name = 'StorageError';
    this.code = code;
    this.status = status;
  }
}

// ── Validation Helpers ──────────────────────────────────────────────────────

/**
 * Validates a PDF file buffer:
 *  - Must be a non-empty Buffer or Uint8Array.
 *  - Must not exceed maxSizeBytes.
 *  - Must begin with standard PDF magic bytes: "%PDF-".
 *
 * @param {Buffer|Uint8Array} buffer
 * @param {number} [maxSizeBytes=MAX_PDF_SIZE_BYTES]
 * @returns {{ valid: boolean, size: number, sha256: string }}
 */
export function validatePdfBuffer(buffer, maxSizeBytes = MAX_PDF_SIZE_BYTES) {
  if (!buffer || !(Buffer.isBuffer(buffer) || buffer instanceof Uint8Array)) {
    throw new StorageError('INVALID_INPUT', 'PDF payload must be a Buffer or Uint8Array', 400);
  }

  if (buffer.length === 0) {
    throw new StorageError('EMPTY_FILE', 'PDF file is empty (0 bytes)', 400);
  }

  if (buffer.length > maxSizeBytes) {
    throw new StorageError(
      'PDF_TOO_LARGE',
      `PDF exceeds maximum allowed size of ${Math.round(maxSizeBytes / (1024 * 1024))}MB (received ${buffer.length} bytes)`,
      400
    );
  }

  // Check magic bytes: first 5 bytes must equal "%PDF-"
  const head = Buffer.from(buffer.subarray(0, 5));
  if (!head.equals(PDF_MAGIC_BYTES)) {
    throw new StorageError(
      'INVALID_PDF_MAGIC_BYTES',
      'Uploaded file does not have valid PDF magic bytes ("%PDF-")',
      400
    );
  }

  const sha256 = createHash('sha256').update(buffer).digest('hex');

  return {
    valid: true,
    size: buffer.length,
    sha256,
  };
}

/**
 * Generates an unpredictable, non-guessable private object key.
 * Format: spaces/{spaceId}/{uuid}.pdf
 *
 * @param {string} spaceId
 * @param {string} [originalFilename]
 * @returns {string}
 */
export function generateObjectKey(spaceId, originalFilename = 'document.pdf') {
  if (!spaceId) throw new StorageError('MISSING_SPACE_ID', 'spaceId is required', 400);
  const cleanSpace = spaceId.replace(/[^a-zA-Z0-9_-]/g, '_');
  const uuid = randomUUID();
  return `spaces/${cleanSpace}/${uuid}.pdf`;
}

// ── Space-to-Object Registry (Server-side Trusted State) ───────────────────

export class SpaceObjectRegistry {
  constructor(initialData = {}) {
    /** @type {Map<string, object>} */
    this.store = new Map(Object.entries(initialData));
  }

  /**
   * @param {string} spaceId
   * @param {object} record
   */
  set(spaceId, record) {
    this.store.set(spaceId, {
      ...record,
      updatedAt: new Date().toISOString(),
    });
  }

  /**
   * @param {string} spaceId
   * @returns {object|undefined}
   */
  get(spaceId) {
    return this.store.get(spaceId);
  }

  /**
   * @param {string} spaceId
   * @returns {boolean}
   */
  has(spaceId) {
    return this.store.has(spaceId);
  }

  /**
   * @param {string} spaceId
   * @returns {boolean}
   */
  delete(spaceId) {
    return this.store.delete(spaceId);
  }

  clear() {
    this.store.clear();
  }
}

export const defaultRegistry = new SpaceObjectRegistry();

// ── In-Memory Mock S3 Client (High-Fidelity Offline / Unit Tests) ───────────

export class MockR2Client {
  constructor() {
    /** @type {Map<string, { body: Buffer, contentType: string, metadata: object, size: number }>} */
    this.objects = new Map();
    this.shouldFail = false;
    this.failError = null;
  }

  setSimulatedFailure(shouldFail, error = null) {
    this.shouldFail = shouldFail;
    this.failError = error || new Error('Simulated R2 network / service error');
  }

  async send(command) {
    if (this.shouldFail) {
      throw this.failError;
    }

    const name = command.constructor?.name || command.name;

    if (name === 'PutObjectCommand') {
      const { Bucket, Key, Body, ContentType, Metadata } = command.input;
      const buf = Buffer.isBuffer(Body) ? Body : Buffer.from(Body);
      this.objects.set(`${Bucket}:${Key}`, {
        body: buf,
        contentType: ContentType || 'application/octet-stream',
        metadata: Metadata || {},
        size: buf.length,
      });
      return { $metadata: { httpStatusCode: 200 } };
    }

    if (name === 'GetObjectCommand') {
      const { Bucket, Key } = command.input;
      const record = this.objects.get(`${Bucket}:${Key}`);
      if (!record) {
        const notFound = new Error('NoSuchKey: The specified key does not exist.');
        notFound.name = 'NoSuchKey';
        notFound.$metadata = { httpStatusCode: 404 };
        throw notFound;
      }
      return {
        $metadata: { httpStatusCode: 200 },
        Body: Readable.from(record.body),
        ContentType: record.contentType,
        ContentLength: record.size,
        Metadata: record.metadata,
      };
    }

    if (name === 'HeadObjectCommand') {
      const { Bucket, Key } = command.input;
      const record = this.objects.get(`${Bucket}:${Key}`);
      if (!record) {
        const notFound = new Error('NotFound');
        notFound.name = 'NotFound';
        notFound.$metadata = { httpStatusCode: 404 };
        throw notFound;
      }
      return {
        $metadata: { httpStatusCode: 200 },
        ContentType: record.contentType,
        ContentLength: record.size,
        Metadata: record.metadata,
      };
    }

    if (name === 'DeleteObjectCommand') {
      const { Bucket, Key } = command.input;
      this.objects.delete(`${Bucket}:${Key}`);
      return { $metadata: { httpStatusCode: 204 } };
    }

    throw new Error(`MockR2Client: Unsupported command ${name}`);
  }
}

// ── Client Factory ─────────────────────────────────────────────────────────

/**
 * Creates an S3Client instance configured for Cloudflare R2 if credentials exist.
 * Returns null if credentials are not configured.
 *
 * @param {object} [opts]
 * @returns {S3Client|null}
 */
export function createR2Client(opts = {}) {
  const accountId = opts.accountId || process.env.R2_ACCOUNT_ID || process.env.CLOUDFLARE_ACCOUNT_ID;
  const accessKeyId = opts.accessKeyId || process.env.R2_ACCESS_KEY_ID;
  const secretAccessKey = opts.secretAccessKey || process.env.R2_SECRET_ACCESS_KEY;

  if (!accountId || !accessKeyId || !secretAccessKey) {
    return null;
  }

  const endpoint = opts.endpoint || `https://${accountId}.r2.cloudflarestorage.com`;

  return new S3Client({
    region: 'auto',
    endpoint,
    credentials: {
      accessKeyId,
      secretAccessKey,
    },
  });
}

// ── Upload & Download Operations ───────────────────────────────────────────

/**
 * Uploads a validated PDF file to private R2 storage and registers it to the space.
 *
 * @param {object} params
 * @param {S3Client|MockR2Client} params.s3Client
 * @param {string} [params.bucket]
 * @param {string} params.spaceId
 * @param {Buffer|Uint8Array} params.pdfBuffer
 * @param {string} [params.filename]
 * @param {string} params.uploaderAccountId
 * @param {SpaceObjectRegistry} [params.registry]
 * @returns {Promise<object>} Safe public upload receipt (zero credentials/keys exposed)
 */
export async function uploadSpacePdf({
  s3Client,
  bucket = DEFAULT_R2_BUCKET,
  spaceId,
  pdfBuffer,
  filename = 'document.pdf',
  uploaderAccountId,
  registry = defaultRegistry,
}) {
  if (!s3Client) {
    throw new StorageError('R2_CLIENT_UNAVAILABLE', 'R2 Storage client is not configured or available', 503);
  }
  if (!spaceId) {
    throw new StorageError('MISSING_SPACE_ID', 'spaceId is required', 400);
  }
  if (!uploaderAccountId) {
    throw new StorageError('MISSING_UPLOADER', 'uploaderAccountId is required', 400);
  }

  // 1. Validate PDF magic bytes and size
  const { size, sha256 } = validatePdfBuffer(pdfBuffer);

  // 2. Generate unpredictable private object key
  const objectKey = generateObjectKey(spaceId, filename);

  // 3. Put object into R2 private bucket
  try {
    await s3Client.send(
      new PutObjectCommand({
        Bucket: bucket,
        Key: objectKey,
        Body: pdfBuffer,
        ContentType: 'application/pdf',
        Metadata: {
          'unseal-space-id': spaceId,
          'unseal-uploader': uploaderAccountId,
          'unseal-sha256': sha256,
        },
      })
    );
  } catch (err) {
    throw new StorageError('R2_STORAGE_ERROR', `Failed to upload object to private storage: ${err.message}`, 502);
  }

  // 4. Update trusted server-side space-to-object mapping
  const safeFilename = filename.replace(/[^a-zA-Z0-9._-]/g, '_');
  const record = {
    spaceId,
    bucket,
    objectKey,
    filename: safeFilename,
    size,
    sha256,
    mimeType: 'application/pdf',
    uploadedBy: uploaderAccountId,
    uploadedAt: new Date().toISOString(),
  };

  registry.set(spaceId, record);

  // 5. Return receipt WITHOUT leaking internal credentials or bucket URLs
  return {
    ok: true,
    spaceId,
    filename: safeFilename,
    size,
    sha256,
    uploadedAt: record.uploadedAt,
  };
}

/**
 * Retrieves a space PDF stream and metadata from private R2 storage.
 *
 * @param {object} params
 * @param {S3Client|MockR2Client} params.s3Client
 * @param {string} [params.bucket]
 * @param {string} params.spaceId
 * @param {SpaceObjectRegistry} [params.registry]
 * @returns {Promise<object>} Content descriptor including readable stream and headers
 */
export async function downloadSpacePdf({
  s3Client,
  bucket = DEFAULT_R2_BUCKET,
  spaceId,
  registry = defaultRegistry,
}) {
  if (!s3Client) {
    throw new StorageError('R2_CLIENT_UNAVAILABLE', 'R2 Storage client is not configured or available', 503);
  }
  if (!spaceId) {
    throw new StorageError('MISSING_SPACE_ID', 'spaceId is required', 400);
  }

  // 1. Look up trusted server-side space mapping
  const record = registry.get(spaceId);
  if (!record) {
    throw new StorageError('NO_CONTENT_FOR_SPACE', `No document has been uploaded for space "${spaceId}"`, 404);
  }

  // 2. Fetch object from private R2 bucket
  try {
    const res = await s3Client.send(
      new GetObjectCommand({
        Bucket: record.bucket || bucket,
        Key: record.objectKey,
      })
    );

    return {
      stream: res.Body,
      contentType: 'application/pdf',
      contentLength: record.size,
      filename: record.filename,
      sha256: record.sha256,
    };
  } catch (err) {
    if (err.name === 'NoSuchKey' || err.$metadata?.httpStatusCode === 404) {
      throw new StorageError('OBJECT_NOT_FOUND', `Stored document object missing from storage: ${record.objectKey}`, 404);
    }
    throw new StorageError('R2_STORAGE_ERROR', `Failed to retrieve object from private storage: ${err.message}`, 502);
  }
}

// ── Durable R2 Metadata Persistence ────────────────────────────────────────

/**
 * Persists application metadata (spaces/documents) durably to Cloudflare R2.
 * @param {object} params
 * @param {S3Client|MockR2Client} params.s3Client
 * @param {string} [params.bucket]
 * @param {string} params.key
 * @param {object} params.data
 * @returns {Promise<boolean>}
 */
export async function persistMetadataToR2({ s3Client, bucket = DEFAULT_R2_BUCKET, key, data }) {
  if (!s3Client) return false;
  try {
    const body = Buffer.from(JSON.stringify(data, null, 2), 'utf8');
    await s3Client.send(
      new PutObjectCommand({
        Bucket: bucket,
        Key: key,
        Body: body,
        ContentType: 'application/json',
      })
    );
    return true;
  } catch (err) {
    console.error(`[storage] Failed to persist metadata to R2 (${key}):`, err.message);
    return false;
  }
}

/**
 * Loads durable application metadata from Cloudflare R2 across restarts.
 * @param {object} params
 * @param {S3Client|MockR2Client} params.s3Client
 * @param {string} [params.bucket]
 * @param {string} params.key
 * @returns {Promise<object|null>}
 */
export async function loadMetadataFromR2({ s3Client, bucket = DEFAULT_R2_BUCKET, key }) {
  if (!s3Client) return null;
  try {
    const res = await s3Client.send(
      new GetObjectCommand({
        Bucket: bucket,
        Key: key,
      })
    );
    if (!res || !res.Body) return null;
    const chunks = [];
    for await (const chunk of res.Body) {
      chunks.push(chunk);
    }
    const str = Buffer.concat(chunks).toString('utf8');
    return JSON.parse(str);
  } catch (err) {
    if (err.name === 'NoSuchKey' || err.$metadata?.httpStatusCode === 404) {
      return null;
    }
    console.warn(`[storage] Notice: Could not load metadata from R2 (${key}):`, err.message);
    return null;
  }
}
