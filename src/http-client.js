/**
 * http-client.js — Robust Node.js IPv4 HTTP client for live NEAR testnet RPC.
 *
 * Resolves Node.js 24 undici happy-eyeballs timeout issues when IPv6 is unrouted.
 * Forces family: 4 (IPv4) on all outbound HTTPS RPC connections.
 */

import https from 'node:https';
import http from 'node:http';

export function ipv4Fetch(url, options = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const client = parsed.protocol === 'https:' ? https : http;

    const req = client.request(
      parsed,
      {
        method: options.method || 'GET',
        headers: options.headers || {},
        family: 4, // Explicit IPv4 to avoid ENETUNREACH on unrouted IPv6
        timeout: 30000,
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const bodyBuf = Buffer.concat(chunks);
          resolve({
            ok: res.statusCode >= 200 && res.statusCode < 300,
            status: res.statusCode,
            statusText: res.statusMessage,
            headers: {
              get: (headerName) => res.headers[headerName.toLowerCase()] ?? null,
              raw: () => res.headers,
            },
            text: async () => bodyBuf.toString('utf8'),
            json: async () => JSON.parse(bodyBuf.toString('utf8')),
          });
        });
      }
    );

    req.on('timeout', () => {
      req.destroy(new Error(`Connection to ${parsed.host} timed out after 30s`));
    });

    req.on('error', reject);

    if (options.body) {
      req.write(options.body);
    }
    req.end();
  });
}

// Ensure globalThis.fetch uses ipv4Fetch in Node environments
if (typeof globalThis !== 'undefined' && typeof window === 'undefined') {
  globalThis.fetch = ipv4Fetch;
}
