# Bolt Daemon

Headless WebRTC transport for the Bolt Protocol.

## Current State: Phase 3D (LAN-only + browser interop + two-machine E2E verified)

Minimal Rust daemon that establishes a WebRTC DataChannel via
[libdatachannel](https://github.com/paullouisageneau/libdatachannel)
(headless, no browser) and exchanges a deterministic payload between two peers.

LAN-only by default: ICE candidates are filtered to private/link-local IPs.

### What This Proves

- libdatachannel compiles and links on macOS arm64 and x86_64 via the `datachannel` Rust crate
- WebRTC DataChannel establishes between two local headless peers
- WebRTC DataChannel establishes between two physical machines on the same LAN
- Ordered, reliable message delivery works (aligns with `TRANSPORT_CONTRACT.md` §1)
- LAN-only ICE policy enforced at candidate level (`TRANSPORT_CONTRACT.md` §5)
- Browser-to-daemon DataChannel interop via file-based signaling

### What This Does NOT Do

- No Bolt protocol encryption (NaCl box is in bolt-core-sdk, not here)
- No identity persistence or TOFU
- No signaling server integration (uses file-based exchange)

## Reproducible Builds

`Cargo.lock` is committed and required. This is a binary daemon — all dependency
versions must be pinned for reproducible builds across machines and CI.

```
cargo build
```

First build compiles libdatachannel + OpenSSL from source (~1 min).
Requires: Rust 1.70+, CMake, Xcode Command Line Tools (macOS).

## Run (headless-to-headless)

Open two terminals:

```bash
# Terminal 1 (offerer):
rm -rf /tmp/bolt-spike && mkdir -p /tmp/bolt-spike
cargo run -- --role offerer

# Terminal 2 (answerer — start after offerer writes offer.json):
cargo run -- --role answerer
```

Default signal paths: `/tmp/bolt-spike/offer.json`, `/tmp/bolt-spike/answer.json`.

Custom paths:

```bash
cargo run -- --role offerer --offer /tmp/my-offer.json --answer /tmp/my-answer.json
cargo run -- --role answerer --offer /tmp/my-offer.json --answer /tmp/my-answer.json
```

Use `-` for stdin/stdout (copy-paste mode):

```bash
cargo run -- --role offerer --offer - --answer -
```

### Expected Output

Both peers print `SUCCESS` and exit 0. Non-LAN candidates are explicitly rejected:

```
[pc] ICE candidate accepted (LAN): candidate:1 1 UDP ... 192.168.4.210 ...
[pc] ICE candidate REJECTED (non-LAN): candidate:4 1 UDP ... 100.74.48.28 ...
[offerer] SUCCESS — received matching payload
[bolt-daemon] exit 0
```

## Browser Interop

A minimal static HTML page is provided for testing daemon-to-browser DataChannel
connectivity without a signaling server.

### Setup

1. Serve the interop page (any static server):
   ```bash
   cd interop/browser
   python3 -m http.server 8080
   ```
   Open `http://localhost:8080` in a browser.

2. The page defaults to **Browser as Answerer** mode (daemon creates the offer).

### Test: daemon offerer, browser answerer

1. Start the daemon as offerer:
   ```bash
   rm -rf /tmp/bolt-spike && mkdir -p /tmp/bolt-spike
   cargo run -- --role offerer
   ```
2. Copy the contents of `/tmp/bolt-spike/offer.json` and paste into the
   "Paste Offer" textarea in the browser page.
3. Click **Apply Offer & Create Answer**.
4. Copy the answer JSON from the "Answer" textarea and write it to
   `/tmp/bolt-spike/answer.json`:
   ```bash
   pbpaste > /tmp/bolt-spike/answer.json
   ```
5. The daemon reads the answer, connects, sends `bolt-hello-v1`.
6. The browser auto-echoes the payload. Both sides log success.

### Test: browser offerer, daemon answerer

1. Select "Browser is Offerer" in the page. Click **Create Offer**.
2. Copy the offer JSON and write it to `/tmp/bolt-spike/offer.json`:
   ```bash
   pbpaste > /tmp/bolt-spike/offer.json
   ```
3. Start the daemon:
   ```bash
   cargo run -- --role answerer
   ```
4. Copy `/tmp/bolt-spike/answer.json` and paste into the "Paste Answer"
   textarea in the browser. Click **Apply Answer**.
5. Connection establishes, payload exchange succeeds.

### Signaling format

Both the daemon and the browser page use the same JSON format:

```json
{
  "description": { "sdp_type": "offer|answer", "sdp": "v=0\r\n..." },
  "candidates": [ { "candidate": "candidate:...", "mid": "0" } ]
}
```

## Test

```
cargo test
```

21 unit tests: 16 ICE filter (accept/reject table), 5 transport/signaling.

## Lint

```
cargo fmt
cargo clippy -- -W clippy::all
```

Both must be clean (0 warnings).

## LAN-Only ICE Policy

All ICE candidates are filtered at the `on_candidate` callback and on inbound
remote candidate application. The policy accepts:

| Range | Type |
|-------|------|
| `10.0.0.0/8` | RFC 1918 private |
| `172.16.0.0/12` | RFC 1918 private |
| `192.168.0.0/16` | RFC 1918 private |
| `169.254.0.0/16` | IPv4 link-local |
| `127.0.0.0/8` | Loopback |
| `fe80::/10` | IPv6 link-local |
| `fc00::/7` | IPv6 unique local |
| `::1` | IPv6 loopback |

Rejected: public IPs, mDNS (`.local`), any non-IP address.

No STUN or TURN servers are configured by default.

## Architecture

```
bolt-daemon/
├── Cargo.toml           # datachannel (vendored), webrtc-sdp, serde
├── Cargo.lock           # pinned (committed for reproducible builds)
├── src/
│   ├── main.rs          # CLI + handlers + signaling + E2E flow
│   └── ice_filter.rs    # LAN-only candidate filter + 16 tests
├── interop/
│   └── browser/
│       └── index.html   # Browser interop test page
├── docs/
│   └── E2E_LAN_TEST.md  # Two-machine LAN test procedure + troubleshooting
└── README.md
```

Key dependencies:
- [`datachannel`](https://crates.io/crates/datachannel) v0.16.0 — Rust bindings for libdatachannel
- `vendored` feature — compiles libdatachannel + OpenSSL from source (no system deps)
- [`webrtc-sdp`](https://crates.io/crates/webrtc-sdp) v0.3 — SDP parsing for signaling exchange

## Tag Convention

Per ecosystem governance: `daemon-vX.Y.Z[-suffix]`

Current: `daemon-v0.0.4-timeout5m`

## License

MIT
