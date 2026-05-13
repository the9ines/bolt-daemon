#!/usr/bin/env node
/**
 * WEBTRANSPORT-BROWSER-APP-E2E-1: Real browser WebTransport validation.
 *
 * Spawns the Rust E2E echo server, then uses Playwright Chromium to:
 *   1. Connect via WebTransport with serverCertificateHashes
 *   2. Send a length-prefixed frame, verify echo
 *   3. Connect via WebSocket, send a message, verify echo
 *
 * Usage:
 *   cd bolt-daemon/tests/e2e-browser
 *   npm install
 *   npm test
 *
 * Prerequisites:
 *   - Rust toolchain with transport-webtransport,transport-ws features
 *   - Playwright Chromium browser installed
 */

import { spawn } from 'node:child_process';
import { chromium } from 'playwright';

const CARGO_ROOT = new URL('../../', import.meta.url).pathname.replace(/\/$/, '');
const TIMEOUT_MS = 30_000;

// ── Helpers ──────────────────────────────────────────────────

function log(tag, msg) {
  console.log(`[${tag}] ${msg}`);
}

function startServer() {
  return new Promise((resolve, reject) => {
    const proc = spawn(
      'cargo',
      ['run', '--example', 'wt_e2e_echo', '--features', 'transport-webtransport,transport-ws'],
      { cwd: CARGO_ROOT, stdio: ['pipe', 'pipe', 'pipe'] }
    );

    let stderr = '';
    proc.stderr.on('data', (d) => {
      stderr += d.toString();
      process.stderr.write(d); // pass through for visibility
    });

    // Read first line of stdout = JSON config
    let stdout = '';
    proc.stdout.on('data', (d) => {
      stdout += d.toString();
      const nl = stdout.indexOf('\n');
      if (nl >= 0) {
        try {
          const config = JSON.parse(stdout.slice(0, nl));
          resolve({ proc, config });
        } catch (e) {
          reject(new Error(`Server config parse error: ${e.message}\nstdout: ${stdout}`));
        }
      }
    });

    proc.on('error', (e) => reject(new Error(`Server spawn error: ${e.message}`)));
    proc.on('exit', (code) => {
      if (!stdout.includes('{')) {
        reject(new Error(`Server exited early (code ${code})\nstderr: ${stderr}`));
      }
    });

    setTimeout(() => reject(new Error('Server start timeout')), TIMEOUT_MS);
  });
}

function stopServer(proc) {
  proc.stdin.end(); // closes stdin → server exits
  return new Promise((resolve) => {
    proc.on('exit', resolve);
    setTimeout(() => { proc.kill('SIGTERM'); resolve(); }, 3000);
  });
}

// ── Main ─────────────────────────────────────────────────────

let server, browser;
let passed = 0, failed = 0;

async function runTest(name, fn) {
  try {
    await fn();
    log('PASS', name);
    passed++;
  } catch (e) {
    log('FAIL', `${name}: ${e.message}`);
    failed++;
  }
}

try {
  // 1. Start echo server
  log('SETUP', 'Building and starting E2E echo server...');
  const { proc, config } = await startServer();
  server = proc;
  log('SETUP', `Server ready: WT port=${config.wt_port}, WS port=${config.ws_port}`);
  log('SETUP', `Cert hash: ${config.cert_hash}`);

  // Convert hex hash to Uint8Array for serverCertificateHashes
  const certHashBytes = config.cert_hash.match(/.{2}/g).map((h) => parseInt(h, 16));

  // 2. Launch browser
  log('SETUP', 'Launching Chromium...');
  browser = await chromium.launch({
    executablePath: process.env.CHROME_PATH || undefined,
    channel: process.env.CHROME_PATH ? undefined : 'chrome',
    args: [
      '--enable-features=WebTransportCustomCertificates',
      '--ignore-certificate-errors',
    ],
  });
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  // WebTransport requires a secure context — navigate to HTTPS first
  await page.goto('https://example.com', { waitUntil: 'domcontentloaded', timeout: 10000 }).catch(() => {
    // If offline, try the WT server URL (will fail as page but establishes context)
    return page.goto(`https://127.0.0.1:${config.wt_port}`, { timeout: 5000 }).catch(() => {});
  });

  // ── Test 1: WebTransport feature detection ──
  await runTest('WT feature detection', async () => {
    const hasWT = await page.evaluate(() => typeof WebTransport !== 'undefined');
    if (!hasWT) throw new Error('WebTransport API not available in Chromium');
  });

  // ── Test 2: WebTransport connect + framed echo ──
  await runTest('WT connect + framed echo', async () => {
    const result = await page.evaluate(async ({ port, hashBytes }) => {
      try {
        const hashBuffer = new Uint8Array(hashBytes).buffer;
        const transport = new WebTransport(`https://127.0.0.1:${port}`, {
          serverCertificateHashes: [{ algorithm: 'sha-256', value: hashBuffer }],
        });

        await transport.ready;

        const stream = await transport.createBidirectionalStream();
        const writer = stream.writable.getWriter();
        const reader = stream.readable.getReader();

        // Send a length-prefixed frame: 4-byte BE length + payload
        const payload = new TextEncoder().encode('hello-from-browser');
        const frame = new Uint8Array(4 + payload.length);
        new DataView(frame.buffer).setUint32(0, payload.length, false);
        frame.set(payload, 4);
        await writer.write(frame);

        // Read echoed frame
        let received = new Uint8Array(0);
        while (received.length < frame.length) {
          const { done, value } = await reader.read();
          if (done) break;
          const merged = new Uint8Array(received.length + value.length);
          merged.set(received);
          merged.set(value, received.length);
          received = merged;
        }

        // Parse response
        const respLen = new DataView(received.buffer).getUint32(0, false);
        const respPayload = new TextDecoder().decode(received.slice(4, 4 + respLen));

        reader.releaseLock();
        writer.releaseLock();
        transport.close();

        return { ok: respPayload === 'hello-from-browser', payload: respPayload, len: respLen };
      } catch (e) {
        return { ok: false, error: e.message || String(e) };
      }
    }, { port: config.wt_port, hashBytes: certHashBytes });

    if (!result.ok) {
      throw new Error(result.error || `Echo mismatch: got "${result.payload}"`);
    }
  });

  // ── Test 3: WebSocket connect + echo ──
  await runTest('WS connect + echo', async () => {
    const result = await page.evaluate(async (port) => {
      return new Promise((resolve) => {
        try {
          const ws = new WebSocket(`ws://127.0.0.1:${port}`);
          ws.onopen = () => {
            ws.send('hello-ws-from-browser');
          };
          ws.onmessage = (e) => {
            resolve({ ok: e.data === 'hello-ws-from-browser', data: e.data });
            ws.close();
          };
          ws.onerror = () => resolve({ ok: false, error: 'WS connection error' });
          setTimeout(() => resolve({ ok: false, error: 'WS timeout' }), 5000);
        } catch (e) {
          resolve({ ok: false, error: e.message });
        }
      });
    }, config.ws_port);

    if (!result.ok) {
      throw new Error(result.error || `WS echo mismatch: got "${result.data}"`);
    }
  });

  // ── Test 4: WebTransport multi-frame ──
  await runTest('WT multi-frame round-trip', async () => {
    const result = await page.evaluate(async ({ port, hashBytes }) => {
      try {
        const hashBuffer = new Uint8Array(hashBytes).buffer;
        const transport = new WebTransport(`https://127.0.0.1:${port}`, {
          serverCertificateHashes: [{ algorithm: 'sha-256', value: hashBuffer }],
        });
        await transport.ready;

        const stream = await transport.createBidirectionalStream();
        const writer = stream.writable.getWriter();
        const reader = stream.readable.getReader();

        const messages = ['frame-1', 'frame-two-longer', 'x'.repeat(1000)];
        const results = [];

        for (const msg of messages) {
          const payload = new TextEncoder().encode(msg);
          const frame = new Uint8Array(4 + payload.length);
          new DataView(frame.buffer).setUint32(0, payload.length, false);
          frame.set(payload, 4);
          await writer.write(frame);

          // Read echoed frame
          let received = new Uint8Array(0);
          while (received.length < frame.length) {
            const { done, value } = await reader.read();
            if (done) break;
            const merged = new Uint8Array(received.length + value.length);
            merged.set(received);
            merged.set(value, received.length);
            received = merged;
          }

          const respLen = new DataView(received.buffer).getUint32(0, false);
          const respPayload = new TextDecoder().decode(received.slice(4, 4 + respLen));
          results.push(respPayload === msg);
        }

        reader.releaseLock();
        writer.releaseLock();
        transport.close();

        return { ok: results.every(Boolean), results };
      } catch (e) {
        return { ok: false, error: e.message || String(e) };
      }
    }, { port: config.wt_port, hashBytes: certHashBytes });

    if (!result.ok) {
      throw new Error(result.error || `Multi-frame mismatch: ${JSON.stringify(result.results)}`);
    }
  });

} finally {
  // Cleanup
  if (browser) await browser.close().catch(() => {});
  if (server) await stopServer(server);

  console.log();
  log('SUMMARY', `${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
}
