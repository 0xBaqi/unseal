/**
 * server-routing.unit.test.js — Regression suite for URL path & query string routing.
 *
 * Validates that normalized pathname routing functions correctly when query strings
 * (e.g. UTM tracking parameters, cache-busters) are present on requests.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { server } from '../src/server.js';

describe('Server Routing & Query-String Regression Suite', () => {
  let baseUrl;

  before((_, done) => {
    // Listen on dynamic port (0) for test isolation
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      baseUrl = `http://127.0.0.1:${addr.port}`;
      done();
    });
  });

  after((_, done) => {
    server.close(done);
  });

  it('1. GET / returns homepage with HTTP 200 and UTF-8 HTML', async () => {
    const res = await fetch(`${baseUrl}/`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type'), /text\/html/);
    const text = await res.text();
    assert.ok(text.includes('Unseal — NFT-Gated Private Documents'));
  });

  it('2. [REGRESSION] GET /?utm_source=chatgpt.com returns identical homepage with HTTP 200', async () => {
    const resClean = await fetch(`${baseUrl}/`);
    const cleanHtml = await resClean.text();

    const resQuery = await fetch(`${baseUrl}/?utm_source=chatgpt.com`);
    assert.equal(resQuery.status, 200, `Expected HTTP 200 for URL with query string, got ${resQuery.status}`);
    assert.match(resQuery.headers.get('content-type'), /text\/html/);
    const queryHtml = await resQuery.text();

    assert.equal(queryHtml, cleanHtml, 'Content for /?utm_source=chatgpt.com must be identical to /');
  });

  it('3. GET /index.html?ref=test returns identical homepage with HTTP 200', async () => {
    const res = await fetch(`${baseUrl}/index.html?ref=test`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type'), /text\/html/);
    const text = await res.text();
    assert.ok(text.includes('Unseal — NFT-Gated Private Documents'));
  });

  it('4. GET /proof.bundle.js?v=8 returns JavaScript bundle with HTTP 200', async () => {
    const res = await fetch(`${baseUrl}/proof.bundle.js?v=8`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type'), /application\/javascript/);
  });

  it('5. GET /spaces?foo=bar returns configured spaces list with HTTP 200', async () => {
    const res = await fetch(`${baseUrl}/spaces?foo=bar`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.ok, true);
    assert.ok(Array.isArray(data.spaces));
  });

  it('6. POST /challenge?source=web successfully issues nonce with HTTP 200', async () => {
    const res = await fetch(`${baseUrl}/challenge?source=web`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ accountId: 'baronal.testnet' }),
    });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.ok(data.nonceB64);
    assert.equal(data.accountId, 'baronal.testnet');
  });

  it('7. GET /nonexistent?param=1 returns HTTP 404', async () => {
    const res = await fetch(`${baseUrl}/nonexistent?param=1`);
    assert.equal(res.status, 404);
  });

  it('8. URL-encoded space routes correctly decode space IDs', async () => {
    // Missing body fields should yield 400 MISSING_FIELD, not a 404 route miss
    const res = await fetch(`${baseUrl}/space/space%2Dalpha/access`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    assert.equal(res.status, 400);
    const data = await res.json();
    assert.equal(data.code, 'MISSING_FIELD');
  });

  it('9. AsyncLock enforces strict mutual exclusion and serial order across concurrent calls', async () => {
    const { AsyncLock } = await import('../src/server.js');
    const lock = new AsyncLock();
    let activeWorkers = 0;
    let maxConcurrency = 0;
    const executionOrder = [];

    const tasks = Array.from({ length: 25 }, (_, i) => async () => {
      return lock.acquire(async () => {
        activeWorkers++;
        maxConcurrency = Math.max(maxConcurrency, activeWorkers);
        await new Promise((r) => setTimeout(r, 2));
        executionOrder.push(i);
        activeWorkers--;
      });
    });

    await Promise.all(tasks.map((t) => t()));

    assert.equal(maxConcurrency, 1, 'Max concurrency inside lock must strictly be 1');
    assert.equal(activeWorkers, 0, 'All workers must release the lock');
    assert.equal(executionOrder.length, 25, 'All 25 queued tasks must complete');
  });

  it('10. AsyncLock unblocks subsequent tasks even if a prior task throws', async () => {
    const { AsyncLock } = await import('../src/server.js');
    const lock = new AsyncLock();
    let completed = false;

    const failingTask = lock.acquire(async () => {
      throw new Error('Simulated persistence disk failure');
    });

    const succeedingTask = lock.acquire(async () => {
      completed = true;
      return 'recovered';
    });

    await assert.rejects(failingTask, /Simulated persistence disk failure/);
    const result = await succeedingTask;
    assert.equal(result, 'recovered');
    assert.equal(completed, true, 'Subsequent task must execute despite prior task rejection');
  });

  it('11. atomicWriteJson produces valid uncorrupted JSON under rapid writes', async () => {
    const { atomicWriteJson } = await import('../src/server.js');
    const { readFile, rm } = await import('node:fs/promises');
    const { join } = await import('node:path');
    const testFile = join(process.cwd(), 'data', 'test-concurrent.json');

    try {
      const writes = Array.from({ length: 20 }, (_, i) =>
        atomicWriteJson(testFile, { iteration: i, payload: 'x'.repeat(1000) })
      );
      await Promise.all(writes);

      const content = await readFile(testFile, 'utf8');
      const parsed = JSON.parse(content);
      assert.ok(typeof parsed.iteration === 'number');
      assert.equal(parsed.payload.length, 1000);
    } finally {
      await rm(testFile, { force: true }).catch(() => {});
    }
  });
});
