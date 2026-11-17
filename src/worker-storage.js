/**
 * worker-storage.js — Cloudflare R2 Storage Adapter with Lifecycle Consistency.
 *
 * Implements native Worker R2 binding integration, strict PDF validation,
 * explicit document lifecycle states, compensating deletion on failure,
 * and orphan reconciliation.
 */

import { randomUUID, createHash } from 'node:crypto';
import { setDocumentD1, recordOrphanD1, deleteDocumentD1 } from './worker-d1.js';

export const DEFAULT_R2_BUCKET = 'unseal-private';
export const MAX_PDF_SIZE_BYTES = 15 * 1024 * 1024; // 15 MB
export const PDF_MAGIC_BYTES = Buffer.from([0x25, 0x50, 0x44, 0x46, 0x2d]); // "%PDF-"

export class StorageError extends Error {
  constructor(code, message, status = 500) {
    super(`${code}: ${message}`);
    this.name = 'StorageError';
    this.code = code;
    this.status = status;
  }
}

/**
 * Validates a PDF file buffer/Uint8Array:
 *  - Must begin with "%PDF-" magic bytes.
 *  - Must be <= 15MB.
 *  - Must not be empty.
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

export function generateObjectKey(spaceId, originalFilename = 'document.pdf') {
  if (!spaceId) throw new StorageError('MISSING_SPACE_ID', 'spaceId is required', 400);
  const cleanSpace = spaceId.replace(/[^a-zA-Z0-9_-]/g, '_');
  const uuid = randomUUID();
  return `spaces/${cleanSpace}/${uuid}.pdf`;
}

/**
 * Uploads a document to R2 with transactional D1 metadata commit.
 * Enforces compensating deletion on metadata failure to prevent orphaned storage.
 *
 * @param {object} params
 * @param {R2Bucket} params.r2 - Cloudflare R2 native bucket binding
 * @param {D1Database} params.db - Cloudflare D1 database binding
 * @param {string} params.spaceId
 * @param {Buffer|Uint8Array} params.pdfBuffer
 * @param {string} [params.filename]
 * @param {string} params.uploaderAccountId
 * @param {string} [params.bucketName]
 */
export async function uploadSpacePdfWorker({
  r2,
  db,
  spaceId,
  pdfBuffer,
  filename = 'document.pdf',
  uploaderAccountId,
  bucketName = DEFAULT_R2_BUCKET,
}) {
  if (!r2) {
    throw new StorageError('R2_BINDING_MISSING', 'Cloudflare R2 bucket binding (UNSEAL_PRIVATE) is missing', 503);
  }
  if (!db) {
    throw new StorageError('D1_BINDING_MISSING', 'Cloudflare D1 database binding (DB) is missing', 503);
  }

  // 1. Validate PDF payload
  const { size, sha256 } = validatePdfBuffer(pdfBuffer);
  const safeFilename = filename.replace(/[^a-zA-Z0-9._-]/g, '_');
  const objectKey = generateObjectKey(spaceId, safeFilename);

  // 2. Put object to private R2 bucket using native binding
  try {
    await r2.put(objectKey, pdfBuffer, {
      httpMetadata: {
        contentType: 'application/pdf',
      },
      customMetadata: {
        'unseal-space-id': spaceId,
        'unseal-uploader': uploaderAccountId,
        'unseal-sha256': sha256,
      },
    });
  } catch (err) {
    throw new StorageError('R2_UPLOAD_FAILED', `Failed to upload object to private R2 storage: ${err.message}`, 502);
  }

  // 3. Atomically persist metadata in D1 with explicit COMMITTED status
  const now = new Date().toISOString();
  const docRecord = {
    spaceId,
    bucket: bucketName,
    objectKey,
    filename: safeFilename,
    size,
    sha256,
    mimeType: 'application/pdf',
    uploadedBy: uploaderAccountId,
    uploadedAt: now,
    status: 'COMMITTED',
  };

  try {
    await setDocumentD1(db, docRecord);
  } catch (d1Err) {
    // COMPENSATING DELETION:
    // If D1 write fails, immediately delete the uploaded R2 object to prevent orphaned storage.
    console.error(`[unseal] Metadata write failed for space "${spaceId}". Executing compensating R2 deletion...`, d1Err.message);
    try {
      await r2.delete(objectKey);
      console.log(`[unseal] Successfully rolled back orphaned R2 object: ${objectKey}`);
    } catch (cleanupErr) {
      console.error(`[unseal] Critical: Compensating R2 deletion failed for ${objectKey}. Recording orphan reconciliation...`, cleanupErr.message);
      try {
        await recordOrphanD1(db, {
          bucket: bucketName,
          objectKey,
          reason: `Compensating deletion failed: ${cleanupErr.message} (Original D1 error: ${d1Err.message})`,
        });
      } catch {}
    }

    throw new StorageError('METADATA_PERSISTENCE_FAILED', `Failed to persist document metadata: ${d1Err.message}`, 500);
  }

  // 4. Return receipt only after metadata is durably committed
  return {
    ok: true,
    spaceId,
    filename: safeFilename,
    size,
    sha256,
    uploadedAt: now,
  };
}

/**
 * Downloads a space PDF using native R2 streaming with strict security headers.
 *
 * @param {object} params
 * @param {R2Bucket} params.r2
 * @param {D1Database} params.db
 * @param {string} params.spaceId
 */
export async function downloadSpacePdfWorker({ r2, db, spaceId }) {
  if (!r2) throw new StorageError('R2_BINDING_MISSING', 'R2 binding missing', 503);
  if (!db) throw new StorageError('D1_BINDING_MISSING', 'D1 binding missing', 503);

  // 1. Fetch metadata record from D1
  const doc = await db.prepare('SELECT * FROM documents WHERE space_id = ? AND status = "COMMITTED"').bind(spaceId).first();
  if (!doc) {
    throw new StorageError('NO_CONTENT_FOR_SPACE', `No document has been uploaded for space "${spaceId}"`, 404);
  }

  // 2. Fetch object from private R2 bucket via native binding
  const object = await r2.get(doc.object_key);
  if (!object) {
    throw new StorageError('OBJECT_NOT_FOUND', `Stored document object missing from storage: ${doc.object_key}`, 404);
  }

  const headers = new Headers({
    'Content-Type': 'application/pdf',
    'Content-Length': String(doc.size),
    'Cache-Control': 'private, no-store, no-cache, must-revalidate',
    'Pragma': 'no-cache',
    'Expires': '0',
    'X-Content-Type-Options': 'nosniff',
    'Content-Disposition': `inline; filename="${doc.filename}"`,
    'X-Unseal-SHA256': doc.sha256,
  });

  return new Response(object.body, {
    status: 200,
    headers,
  });
}

// ── In-Memory High-Fidelity Mock R2 Bucket for Testing ───────────────────────

export class MockR2Bucket {
  constructor() {
    this.store = new Map();
    this.failNextPut = false;
  }

  async put(key, value, options = {}) {
    if (this.failNextPut) {
      this.failNextPut = false;
      throw new Error('Simulated R2 service failure');
    }
    const buf = Buffer.isBuffer(value) ? value : Buffer.from(value);
    this.store.set(key, {
      body: buf,
      size: buf.length,
      httpMetadata: options.httpMetadata || {},
      customMetadata: options.customMetadata || {},
    });
    return { key, size: buf.length };
  }

  async get(key) {
    const entry = this.store.get(key);
    if (!entry) return null;
    return {
      key,
      size: entry.size,
      body: entry.body,
      httpMetadata: entry.httpMetadata,
      customMetadata: entry.customMetadata,
      arrayBuffer: async () => entry.body.buffer,
      text: async () => entry.body.toString('utf8'),
    };
  }

  async delete(key) {
    this.store.delete(key);
  }

  async head(key) {
    const entry = this.store.get(key);
    if (!entry) return null;
    return { key, size: entry.size, customMetadata: entry.customMetadata };
  }
}
