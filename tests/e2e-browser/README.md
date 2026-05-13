# Browser WebTransport E2E Test

Real-browser validation of the bolt-daemon WebTransport and WebSocket endpoints.

## Prerequisites

- Rust toolchain with `transport-webtransport` and `transport-ws` features
- Node.js 18+
- Playwright Chromium browser (`npx playwright install chromium`)

## Run

```bash
cd bolt-daemon/tests/e2e-browser
npm install
npm test
```

## What it does

1. Builds and starts the `wt_e2e_echo` Rust example (WT + WS echo server with self-signed cert)
2. Launches headless Chromium via Playwright
3. Tests:
   - WebTransport API feature detection
   - WebTransport connect + length-prefixed frame echo
   - WebSocket connect + text echo
   - WebTransport multi-frame round-trip
4. Reports pass/fail for each test
5. Cleans up server and browser

## Expected output

```
[SETUP] Building and starting E2E echo server...
[SETUP] Server ready: WT port=XXXXX, WS port=YYYYY
[SETUP] Launching Chromium...
[PASS] WT feature detection
[PASS] WT connect + framed echo
[PASS] WS connect + echo
[PASS] WT multi-frame round-trip

[SUMMARY] 4 passed, 0 failed
```
