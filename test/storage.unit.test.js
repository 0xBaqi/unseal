import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  validatePdfBuffer,
  generateObjectKey,
  MockR2Client,
  persistMetadataToR2,
  loadMetadataFromR2,
  StorageError,
} from '../src/storage.js';

describe('Storage & R2 Metadata Persistence Unit Tests', () => {
  it('1. validatePdfBuffer accepts valid PDF magic bytes and computes sha256', () => {
    const validPdf = Buffer.from('%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF');
    const res = validatePdfBuffer(validPdf);
    assert.equal(res.valid, true);
    assert.equal(res.size, validPdf.length);
    assert.equal(typeof res.sha256, 'string');
    assert.equal(res.sha256.length, 64);
  });

  it('2. validatePdfBuffer rejects non-PDF buffer with INVALID_PDF_MAGIC_BYTES', () => {
    const invalid = Buffer.from('NOT A PDF FILE');
    assert.throws(
      () => validatePdfBuffer(invalid),
      (err) => err instanceof StorageError && err.code === 'INVALID_PDF_MAGIC_BYTES'
    );
  });

  it('3. generateObjectKey produces safe, unpredictable key under spaces/{spaceId}/', () => {
    const key = generateObjectKey('space-alpha', 'document.pdf');
    assert.match(key, /^spaces\/space-alpha\/[a-f0-9-]+\.pdf$/);
  });

  it('4. persistMetadataToR2 and loadMetadataFromR2 round-trip correctly', async () => {
    const mockClient = new MockR2Client();
    const testData = {
      'space-test': {
        spaceId: 'space-test',
        title: 'Persistent Space',
        creator: 'creator.testnet',
      },
    };

    const saved = await persistMetadataToR2({
      s3Client: mockClient,
      bucket: 'unseal-private',
      key: 'metadata/spaces.json',
      data: testData,
    });
    assert.equal(saved, true);

    const loaded = await loadMetadataFromR2({
      s3Client: mockClient,
      bucket: 'unseal-private',
      key: 'metadata/spaces.json',
    });
    assert.deepEqual(loaded, testData);
  });

  it('5. loadMetadataFromR2 returns null gracefully when key does not exist', async () => {
    const mockClient = new MockR2Client();
    const loaded = await loadMetadataFromR2({
      s3Client: mockClient,
      bucket: 'unseal-private',
      key: 'metadata/nonexistent.json',
    });
    assert.equal(loaded, null);
  });
});
