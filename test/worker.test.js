/**
 * worker.test.js — Cloudflare Workers Integration & Concurrency Test Suite.
 *
 * Validates:
 * 1. D1 atomic challenge nonce consumption and concurrent replay defense.
 * 2. R2 / D1 consistency, lifecycle states, and compensating rollback.
 * 3. Exact CPU time benchmarking for NEP-413 Ed25519 signature verification.
 * 4. End-to-end HTTP routing on the Worker fetch() interface.
 */

import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { issueChallengeD1, consumeChallengeD1, initializeD1 } from '../src/worker-d1.js';
import { uploadSpacePdfWorker, downloadSpacePdfWorker, MockR2Bucket, StorageError } from '../src/worker-storage.js';
import worker from '../src/worker.js';

// ── In-Memory Transactional D1 Database Mock ────────────────────────────────

export class MockD1Database {
  constructor() {
    this.tables = {
      spaces: new Map(),
      documents: new Map(),
      challenges: new Map(),
      orphan_reconciliation: [],
    };
    this._lock = Promise.resolve();
  }

  async _atomic(fn) {
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const current = this._lock;
    this._lock = current.then(() => gate, () => gate);
    try {
      await current;
      return await fn();
    } finally {
      release();
    }
  }

  async exec(sql) {
    // Schema creation is a no-op since tables are initialized in constructor
    return { success: true };
  }

  async batch(statements) {
    return this._atomic(async () => {
      const results = [];
      for (const stmt of statements) {
        results.push(await stmt._execute());
      }
      return results;
    });
  }

  prepare(query) {
    const db = this;
    return {
      _params: [],
      bind(...params) {
        this._params = params;
        return this;
      },
      async run() {
        return db._atomic(() => this._execute());
      },
      async first() {
        return db._atomic(async () => {
          const res = await this._execute();
          return res.results?.[0] || null;
        });
      },
      async all() {
        return db._atomic(async () => {
          const res = await this._execute();
          return { results: res.results || [] };
        });
      },
      async _execute() {
        const q = query.trim().replace(/\s+/g, ' ');
        const p = this._params;

        // INSERT challenges
        if (q.startsWith('INSERT INTO challenges')) {
          const [nonce_b64, account_id, recipient, message, expires_at] = p;
          db.tables.challenges.set(nonce_b64, {
            nonce_b64,
            account_id,
            recipient,
            message,
            expires_at,
            consumed_at: null,
          });
          return { success: true, results: [] };
        }

        // UPDATE challenges (ATOMIC CONDITIONAL REPLAY CHECK)
        if (q.startsWith('UPDATE challenges SET consumed_at = ? WHERE nonce_b64 = ?')) {
          const [consumed_at, nonce_b64, account_id, recipient, now] = p;
          const entry = db.tables.challenges.get(nonce_b64);
          if (
            entry &&
            entry.account_id === account_id &&
            entry.recipient === recipient &&
            entry.consumed_at === null &&
            entry.expires_at > now
          ) {
            entry.consumed_at = consumed_at;
            return {
              success: true,
              results: [{
                nonce_b64: entry.nonce_b64,
                account_id: entry.account_id,
                recipient: entry.recipient,
                message: entry.message,
                expires_at: entry.expires_at,
              }],
            };
          }
          return { success: true, results: [] };
        }

        // SELECT challenges by nonce_b64
        if (q.includes('FROM challenges WHERE nonce_b64 = ?')) {
          const [nonce_b64] = p;
          const entry = db.tables.challenges.get(nonce_b64);
          return { success: true, results: entry ? [entry] : [] };
        }

        // SELECT COUNT(*) FROM spaces
        if (q.includes('SELECT COUNT(*) as count FROM spaces')) {
          return { success: true, results: [{ count: db.tables.spaces.size }] };
        }

        // INSERT INTO spaces
        if (q.startsWith('INSERT INTO spaces')) {
          const [space_id, name, contract_id, required_token_id, issuer, is_public_demo, secret_payload, enforce_expiry, created_at, updated_at] = p;
          db.tables.spaces.set(space_id, {
            space_id,
            name,
            contract_id,
            required_token_id,
            issuer,
            is_public_demo,
            secret_payload,
            enforce_expiry,
            created_at,
            updated_at,
          });
          return { success: true, results: [] };
        }

        // SELECT * FROM spaces WHERE space_id = ?
        if (q.includes('SELECT * FROM spaces WHERE space_id = ?')) {
          const [space_id] = p;
          const row = db.tables.spaces.get(space_id);
          return { success: true, results: row ? [row] : [] };
        }

        // SELECT s.*, d.filename FROM spaces
        if (q.includes('FROM spaces s LEFT JOIN documents d')) {
          const list = [];
          for (const s of db.tables.spaces.values()) {
            const d = db.tables.documents.get(s.space_id);
            list.push({
              ...s,
              filename: d ? d.filename : null,
              size: d ? d.size : null,
              sha256: d ? d.sha256 : null,
              uploaded_at: d ? d.uploaded_at : null,
              doc_status: d ? d.status : null,
            });
          }
          return { success: true, results: list };
        }

        // INSERT INTO documents
        if (q.startsWith('INSERT INTO documents')) {
          const [space_id, bucket, object_key, filename, size, sha256, mime_type, uploaded_by, uploaded_at, status] = p;
          db.tables.documents.set(space_id, {
            space_id,
            bucket,
            object_key,
            filename,
            size,
            sha256,
            mime_type,
            uploaded_by,
            uploaded_at,
            status,
          });
          return { success: true, results: [] };
        }

        // SELECT * FROM documents WHERE space_id = ?
        if (q.includes('FROM documents WHERE space_id = ?')) {
          const [space_id] = p;
          const d = db.tables.documents.get(space_id);
          return { success: true, results: d ? [d] : [] };
        }

        // DELETE FROM documents WHERE space_id = ?
        if (q.startsWith('DELETE FROM documents WHERE space_id = ?')) {
          const [space_id] = p;
          db.tables.documents.delete(space_id);
          return { success: true, results: [] };
        }

        // INSERT INTO orphan_reconciliation
        if (q.startsWith('INSERT INTO orphan_reconciliation')) {
          const [bucket, object_key, reason, created_at] = p;
          db.tables.orphan_reconciliation.push({ bucket, object_key, reason, created_at });
          return { success: true, results: [] };
        }

        return { success: true, results: [] };
      },
    };
  }
}

// ── Test Suites ─────────────────────────────────────────────────────────────

describe('1. D1 Atomic Nonce Security & Replay Prevention', () => {
  let db;

  before(async () => {
    db = new MockD1Database();
    await initializeD1(db);
  });

  it('1.1 Issues a challenge and validates initial state', async () => {
    const ch = await issueChallengeD1(db, {
      accountId: 'alice.testnet',
      recipient: 'unseal-gate-a.proof',
      message: 'Sign in to Unseal',
    });

    assert.ok(ch.nonceB64);
    assert.equal(ch.accountId, 'alice.testnet');
    assert.equal(ch.recipient, 'unseal-gate-a.proof');
    assert.ok(ch.expiresAt > Date.now());
  });

  it('1.2 Consumes challenge once successfully', async () => {
    const ch = await issueChallengeD1(db, {
      accountId: 'bob.testnet',
      recipient: 'unseal-gate-a.proof',
      message: 'Sign in to Unseal',
    });

    const consumed = await consumeChallengeD1(db, {
      nonceB64: ch.nonceB64,
      accountId: 'bob.testnet',
      recipient: 'unseal-gate-a.proof',
    });

    assert.ok(consumed.nonce instanceof Uint8Array);
    assert.equal(consumed.nonce.length, 32);
    assert.equal(consumed.message, 'Sign in to Unseal');
  });

  it('1.3 Rejects immediate replay attempt with CHALLENGE_REPLAY', async () => {
    const ch = await issueChallengeD1(db, {
      accountId: 'charlie.testnet',
      recipient: 'unseal-gate-a.proof',
      message: 'Sign in to Unseal',
    });

    // First consumption succeeds
    await consumeChallengeD1(db, {
      nonceB64: ch.nonceB64,
      accountId: 'charlie.testnet',
      recipient: 'unseal-gate-a.proof',
    });

    // Second consumption MUST fail closed
    await assert.rejects(
      async () => {
        await consumeChallengeD1(db, {
          nonceB64: ch.nonceB64,
          accountId: 'charlie.testnet',
          recipient: 'unseal-gate-a.proof',
        });
      },
      (err) => err.code === 'CHALLENGE_REPLAY',
      'Replay attack must be detected and rejected'
    );
  });

  it('1.4 Concurrent Replay Test: 10 simultaneous requests to consume the same nonce results in exactly 1 success and 9 failures', async () => {
    const ch = await issueChallengeD1(db, {
      accountId: 'concurrent.testnet',
      recipient: 'unseal-gate-a.proof',
      message: 'Sign in to Unseal',
    });

    // Launch 10 simultaneous consumption promises in parallel
    const attempts = Array.from({ length: 10 }).map(() =>
      consumeChallengeD1(db, {
        nonceB64: ch.nonceB64,
        accountId: 'concurrent.testnet',
        recipient: 'unseal-gate-a.proof',
      })
        .then(() => ({ success: true }))
        .catch((err) => ({ success: false, code: err.code }))
    );

    const results = await Promise.all(attempts);
    const successes = results.filter((r) => r.success);
    const failures = results.filter((r) => !r.success);

    assert.equal(successes.length, 1, 'Exactly one concurrent request must win the atomic consumption');
    assert.equal(failures.length, 9, 'All other 9 concurrent attempts must fail');
    failures.forEach((f) => {
      assert.equal(f.code, 'CHALLENGE_REPLAY', 'Failures must specifically be CHALLENGE_REPLAY');
    });
  });
});

describe('2. R2 / D1 Consistency & Compensating Deletion Rollback', () => {
  let db;
  let r2;

  before(async () => {
    db = new MockD1Database();
    r2 = new MockR2Bucket();
    await initializeD1(db);
  });

  const SAMPLE_PDF = Buffer.from(
    '%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/MediaBox[0 0 612 792]>>endobj\nxref\n0 4\n0000000000 65535 f \ntrailer<</Size 4/Root 1 0 R>>\nstartxref\n178\n%%EOF'
  );

  it('2.1 Successfully uploads PDF to R2 and writes D1 metadata with status COMMITTED', async () => {
    const res = await uploadSpacePdfWorker({
      r2,
      db,
      spaceId: 'space-test-commit',
      pdfBuffer: SAMPLE_PDF,
      filename: 'audit-report.pdf',
      uploaderAccountId: 'alice.testnet',
    });

    assert.equal(res.ok, true);
    assert.equal(res.spaceId, 'space-test-commit');
    assert.equal(res.filename, 'audit-report.pdf');

    // Verify R2 object exists
    const docInDb = await db.prepare('SELECT * FROM documents WHERE space_id = ?').bind('space-test-commit').first();
    assert.ok(docInDb);
    assert.equal(docInDb.status, 'COMMITTED');

    const objInR2 = await r2.get(docInDb.object_key);
    assert.ok(objInR2);
    assert.equal(objInR2.size, SAMPLE_PDF.length);
  });

  it('2.2 Compensating Deletion: When D1 metadata write fails, R2 object is rolled back and deleted', async () => {
    // Intercept D1 to simulate database failure on insert
    const brokenDb = new MockD1Database();
    await initializeD1(brokenDb);
    const originalPrepare = brokenDb.prepare.bind(brokenDb);
    brokenDb.prepare = (query) => {
      if (query.trim().startsWith('INSERT INTO documents')) {
        return {
          bind: () => ({
            run: async () => { throw new Error('Simulated D1 Disk/Lock Failure'); },
          }),
        };
      }
      return originalPrepare(query);
    };

    let uploadedKey = null;
    const r2Tracker = new MockR2Bucket();
    const originalPut = r2Tracker.put.bind(r2Tracker);
    r2Tracker.put = async (key, val, opts) => {
      uploadedKey = key;
      return originalPut(key, val, opts);
    };

    await assert.rejects(
      async () => {
        await uploadSpacePdfWorker({
          r2: r2Tracker,
          db: brokenDb,
          spaceId: 'space-fail-rollback',
          pdfBuffer: SAMPLE_PDF,
          filename: 'confidential.pdf',
          uploaderAccountId: 'attacker.testnet',
        });
      },
      (err) => err instanceof StorageError && err.code === 'METADATA_PERSISTENCE_FAILED',
      'Must fail with METADATA_PERSISTENCE_FAILED'
    );

    // Verify that the compensating deletion deleted the uploaded R2 object!
    assert.ok(uploadedKey, 'R2 put must have been initially executed');
    const r2Check = await r2Tracker.get(uploadedKey);
    assert.equal(r2Check, null, 'Orphaned R2 object must be rolled back and deleted after D1 failure');

    // Verify that no document record exists in D1
    const d1Check = await brokenDb.prepare('SELECT * FROM documents WHERE space_id = ?').bind('space-fail-rollback').first();
    assert.equal(d1Check, null, 'No metadata record must exist in D1');
  });

  it('2.3 Rejects non-PDF payloads before R2 or D1 interaction', async () => {
    const invalidPayload = Buffer.from('NOT A PDF FILE');
    await assert.rejects(
      async () => {
        await uploadSpacePdfWorker({
          r2,
          db,
          spaceId: 'space-invalid',
          pdfBuffer: invalidPayload,
          filename: 'malicious.exe',
          uploaderAccountId: 'attacker.testnet',
        });
      },
      (err) => err instanceof StorageError && err.code === 'INVALID_PDF_MAGIC_BYTES'
    );
  });
});

describe('3. Cloudflare Workers CPU Time Compatibility & Benchmark', () => {
  it('3.1 Measures actual microsecond CPU time of cryptographic NEP-413 Ed25519 verification', async () => {
    // Benchmark 100 iterations of Ed25519 signature computation / verification
    const { generateKeyPairSync, sign } = await import('node:crypto');
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');

    const message = Buffer.from('NEAR NEP-413 Proof Benchmark Message');
    const signature = sign(null, message, privateKey);

    const ITERATIONS = 100;
    const startCpu = process.cpuUsage();
    const startWall = performance.now();

    const { verify } = await import('node:crypto');
    for (let i = 0; i < ITERATIONS; i++) {
      const isValid = verify(null, message, publicKey, signature);
      assert.equal(isValid, true);
    }

    const elapsedCpu = process.cpuUsage(startCpu);
    const elapsedWall = performance.now() - startWall;

    const totalCpuMicroseconds = elapsedCpu.user + elapsedCpu.system;
    const avgCpuMsPerVerification = (totalCpuMicroseconds / 1000) / ITERATIONS;

    console.log(`\n  =============================================================`);
    console.log(`  [CPU BENCHMARK RESULTS]`);
    console.log(`  Iterations:                   ${ITERATIONS}`);
    console.log(`  Total CPU time:               ${(totalCpuMicroseconds / 1000).toFixed(2)} ms`);
    console.log(`  Total wall-clock time:        ${elapsedWall.toFixed(2)} ms`);
    console.log(`  Avg CPU time per verification: ${avgCpuMsPerVerification.toFixed(3)} ms`);
    console.log(`  Workers Free Tier CPU Limit:  10.000 ms`);
    console.log(`  Headroom / Margin:            ${((10 - avgCpuMsPerVerification) / 10 * 100).toFixed(1)}%`);
    console.log(`  =============================================================\n`);

    assert.ok(
      avgCpuMsPerVerification < 5.0,
      `Average CPU time per Ed25519 verification (${avgCpuMsPerVerification.toFixed(3)} ms) must fit well within the 10 ms Free Worker limit`
    );
  });
});

describe('4. Worker Fetch Router & Security Endpoints', () => {
  let env;

  before(async () => {
    const db = new MockD1Database();
    await initializeD1(db);
    const r2 = new MockR2Bucket();

    env = {
      DB: db,
      UNSEAL_PRIVATE: r2,
      NEAR_RPC_URL: 'https://archival-rpc.testnet.near.org',
    };
  });

  it('4.1 GET /spaces returns public demo spaces with HTTP 200', async () => {
    const req = new Request('http://localhost/spaces', { method: 'GET' });
    const res = await worker.fetch(req, env);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.ok, true);
    assert.ok(Array.isArray(data.spaces));
    assert.ok(data.spaces.some((s) => s.spaceId === 'space-alpha'));
  });

  it('4.2 POST /challenge issues valid challenge with HTTP 200', async () => {
    const req = new Request('http://localhost/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ accountId: 'judge.testnet' }),
    });

    const res = await worker.fetch(req, env);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.ok(data.nonceB64);
    assert.equal(data.accountId, 'judge.testnet');
    assert.equal(data.recipient, 'unseal-gate-a.proof');
  });

  it('4.3 POST /verify with malformed signature returns HTTP 400', async () => {
    const req = new Request('http://localhost/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        accountId: 'judge.testnet',
        publicKey: 'ed25519:11111111111111111111111111111111',
        signatureB64: 'INVALID_BASE64_NOT_64_BYTES',
        nonceB64: Buffer.from(new Uint8Array(32)).toString('base64'),
      }),
    });

    const res = await worker.fetch(req, env);
    assert.equal(res.status, 400);
    const data = await res.json();
    assert.equal(data.code, 'INVALID_SIGNATURE_ENCODING');
  });

  it('4.4 POST /space/:spaceId/content returns 400 when missing auth', async () => {
    const req = new Request('http://localhost/space/space-alpha/content', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });

    const res = await worker.fetch(req, env);
    assert.equal(res.status, 400);
  });
});
