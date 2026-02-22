# Bolt Daemon

Headless WebRTC transport for the Bolt Protocol.

## Current State: Phase 3G (rendezvous session + handshake)

Minimal Rust daemon that establishes a WebRTC DataChannel via
[libdatachannel](https://github.com/paullouisageneau/libdatachannel)
(headless, no browser) and exchanges a deterministic payload between two peers.

Two signaling modes:
- **File** (default) — exchange offer/answer via JSON files on disk
- **Rendezvous** — exchange offer/answer via bolt-rendezvous WebSocket server

Three network scope policies:
- **LAN** (default) — ICE candidates filtered to private/link-local IPs (LocalBolt)
- **Overlay** — LAN + CGNAT 100.64.0.0/10 (LocalBolt over Tailscale)
- **Global** — all valid IPs accepted including public and CGNAT (ByteBolt)

### What This Proves

- libdatachannel compiles and links on macOS arm64 and x86_64 via the `datachannel` Rust crate
- WebRTC DataChannel establishes between two local headless peers
- WebRTC DataChannel establishes between two physical machines on the same LAN
- Ordered, reliable message delivery works (aligns with `TRANSPORT_CONTRACT.md` §1)
- LAN-only ICE policy enforced at candidate level (`TRANSPORT_CONTRACT.md` §5)
- Browser-to-daemon DataChannel interop via file-based signaling
- Rendezvous signaling via bolt-rendezvous WebSocket server (no manual `scp`)
- Rendezvous hello/ack handshake validates peer identity, session, scope before offer
- Network scope policy cleanly separates LAN (LocalBolt) from Global (ByteBolt)

### What This Does NOT Do

- No Bolt protocol encryption (NaCl box is in bolt-core-sdk, not here)
- No identity persistence or TOFU
- No TURN integration yet

## Reproducible Builds

`Cargo.lock` is committed and required. This is a binary daemon — all dependency
versions must be pinned for reproducible builds across machines and CI.

```
cargo build
```

First build compiles libdatachannel + OpenSSL from source (~1 min).
Requires: Rust 1.70+, CMake, Xcode Command Line Tools (macOS).

## CLI Reference

```
bolt-daemon --role offerer|answerer [options]

Common flags:
  --role <offerer|answerer>       Required. Peer role.
  --network-scope <lan|overlay|global>  ICE filter policy (default: lan)
  --phase-timeout-secs <int>      Timeout per phase in seconds (default: 30)

File mode flags:
  --offer <path|->                Offer signal path (default: /tmp/bolt-spike/offer.json)
  --answer <path|->               Answer signal path (default: /tmp/bolt-spike/answer.json)

Rendezvous mode flags:
  --signal <file|rendezvous>      Signal mode (default: file)
  --rendezvous-url <url>          WebSocket URL (default: ws://127.0.0.1:3001)
  --room <string>                 Room discriminator (REQUIRED for rendezvous)
  --session <string>              Session discriminator (REQUIRED for rendezvous)
  --to <peer_code>                Target peer (REQUIRED for offerer + rendezvous)
  --expect-peer <peer_code>       Expected peer (REQUIRED for answerer + rendezvous)
  --peer-id <string>              Own peer code (optional, auto-generated)
```

## Run — File Mode (headless-to-headless)

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

## Run — Rendezvous Mode

Requires a running bolt-rendezvous server.

```bash
# Terminal 0: start rendezvous server
cd ~/Desktop/the9ines.com/bolt-ecosystem/bolt-rendezvous
cargo run

# Terminal 1 (offerer):
cargo run -- --role offerer --signal rendezvous --room test1 \
  --session s1 --peer-id alice --to bob

# Terminal 2 (answerer):
cargo run -- --role answerer --signal rendezvous --room test1 \
  --session s1 --peer-id bob --expect-peer alice
```

For two-machine tests with manual setup time:

```bash
cargo run -- --role offerer --signal rendezvous --room test1 \
  --session s1 --peer-id alice --to bob --phase-timeout-secs 300
```

### Rendezvous Hello/Ack Handshake

Before the offer/answer exchange, rendezvous mode performs a hello/ack handshake:

1. Offerer sends `msg_type="hello"` with peer identities, network scope, and session
2. Answerer validates hello fields (peer IDs, scope match, payload version)
3. Answerer replies `msg_type="ack"`
4. Offerer validates ack, then proceeds with offer

Any mismatch (wrong peer, scope mismatch, version mismatch) exits 1 immediately.

All rendezvous payloads carry `payload_version: 1` and a `session` discriminator.
Signals with a non-matching session are silently ignored (different test run).
Signals with an unknown `payload_version` cause exit 1 (fail-closed).

### Rendezvous Fail-Closed Rules

Rendezvous mode is **opt-in only**. There is no fallback to file mode.

- `--signal rendezvous` without `--room` → exit 1
- `--signal rendezvous` without `--session` → exit 1
- `--signal rendezvous --role offerer` without `--to` → exit 1
- `--signal rendezvous --role answerer` without `--expect-peer` → exit 1
- Rendezvous server unreachable → exit 1 (no silent behavior change)
- `payload_version` mismatch → exit 1
- Hello peer identity or scope mismatch → exit 1

### Expected Output

Both peers print `SUCCESS` and exit 0. Non-LAN candidates are explicitly rejected
(in LAN mode):

```
[bolt-daemon] role=Offerer signal=File scope=Lan timeout=30s
[pc] ICE candidate accepted (Lan): candidate:1 1 UDP ... 192.168.4.210 ...
[pc] ICE candidate REJECTED (Lan): candidate:4 1 UDP ... 100.74.48.28 ...
[offerer] SUCCESS — received matching payload
[bolt-daemon] exit 0
```

## Network Scope Policy

Controls which ICE candidates are accepted at the `on_candidate` callback
and on inbound remote candidate application.

### LAN mode (`--network-scope lan`, default)

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

Rejected: public IPs, CGNAT (`100.64.0.0/10`), mDNS (`.local`), any non-IP address.

### Overlay mode (`--network-scope overlay`)

Everything LAN accepts, plus:

| Range | Type |
|-------|------|
| `100.64.0.0/10` | CGNAT (Tailscale, other overlay networks) |

Rejected: public IPs, mDNS (`.local`), any non-IP address.

Use this for LocalBolt over Tailscale:
```bash
cargo run -- --role offerer --network-scope overlay
```

### Global mode (`--network-scope global`)

Accepts all valid IP addresses (private + public + CGNAT).

Still rejected: mDNS (`.local`), malformed candidates, empty IPs.

No STUN or TURN servers are configured by default.

## Local E2E Test (Rendezvous)

An automated script runs bolt-rendezvous + two bolt-daemon peers locally:

```bash
bash scripts/e2e_rendezvous_local.sh
```

Requires `bolt-rendezvous` at `../bolt-rendezvous` (sibling repo). Builds both,
starts the rendezvous server, runs offerer + answerer with hello/ack handshake,
and reports PASS/FAIL. Logs are preserved on failure for debugging.

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

55 unit tests: 33 ICE filter (LAN + Overlay + Global scope), 7 transport/signaling, 15 rendezvous protocol.

## Lint

```
cargo fmt
cargo clippy -- -W clippy::all
```

Both must be clean (0 warnings).

## Architecture

```
bolt-daemon/
├── Cargo.toml           # datachannel (vendored), webrtc-sdp, serde, tungstenite
├── Cargo.lock           # pinned (committed for reproducible builds)
├── src/
│   ├── main.rs          # CLI + handlers + signaling + E2E flow + file mode
│   ├── ice_filter.rs    # NetworkScope policy + candidate filter + 33 tests
│   └── rendezvous.rs    # WebSocket signaling via bolt-rendezvous + 15 tests
├── scripts/
│   └── e2e_rendezvous_local.sh  # Local E2E regression harness
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
- [`tungstenite`](https://crates.io/crates/tungstenite) v0.24 — sync WebSocket client for rendezvous signaling

## Tag Convention

Per ecosystem governance: `daemon-vX.Y.Z[-suffix]`

Current: `daemon-v0.0.9-rendezvous-session`

## License

MIT
