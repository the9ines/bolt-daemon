# Bolt Daemon

Headless WebRTC transport for the Bolt Protocol.

## Current State: Transport Spike (Phase 3A)

Minimal Rust daemon that establishes a WebRTC DataChannel via
[libdatachannel](https://github.com/paullouisageneau/libdatachannel)
(headless, no browser) and exchanges a deterministic payload between two peers.

### What This Proves

- libdatachannel compiles and links on macOS arm64 via the `datachannel` Rust crate
- WebRTC DataChannel establishes between two local headless peers
- Ordered, reliable message delivery works (aligns with `TRANSPORT_CONTRACT.md` §1)
- File-based signaling exchange (SDP + ICE candidates as JSON)

### What This Does NOT Do

- No Bolt protocol encryption (NaCl box is in bolt-core-sdk, not here)
- No identity persistence or TOFU
- No signaling server integration (uses file-based exchange)
- No LAN-only ICE filtering beyond omitting STUN/TURN servers (see Limitations)

## Build

Requires: Rust 1.70+, CMake, Xcode Command Line Tools (macOS).

```
cargo build
```

First build compiles libdatachannel + OpenSSL from source (~1 min).

## Run

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

Both peers print `SUCCESS` and exit 0:

```
[offerer] SUCCESS — received matching payload
[bolt-daemon] exit 0
```

```
[answerer] SUCCESS — echoed matching payload
[bolt-daemon] exit 0
```

## Test

```
cargo test
```

5 unit tests: payload determinism, signaling JSON roundtrip, type mappings.

## Lint

```
cargo fmt
cargo clippy -- -W clippy::all
```

Both must be clean (0 warnings).

## Architecture

```
bolt-daemon
├── Cargo.toml       # datachannel (vendored), webrtc-sdp, serde
├── src/main.rs      # CLI + handlers + signaling + E2E flow
└── README.md
```

Key dependencies:
- [`datachannel`](https://crates.io/crates/datachannel) v0.16.0 — Rust bindings for libdatachannel
- `vendored` feature — compiles libdatachannel + OpenSSL from source (no system deps)
- [`webrtc-sdp`](https://crates.io/crates/webrtc-sdp) v0.3 — SDP parsing for signaling exchange

## Limitations

### LAN-Only ICE Filtering

The spike omits all ICE servers (no STUN, no TURN), which means only host candidates
(local network IPs) are gathered. This effectively provides LAN-only connectivity.

However, proper LAN-only enforcement per `TRANSPORT_CONTRACT.md` §5 requires:
- Explicit candidate filtering (reject non-private IPs)
- mDNS candidate support for browser interop

These are **not implemented** in the spike. They require ICE candidate inspection
at the `on_candidate` callback level. Marked as TODO for Phase 3B.

### Signaling

File-based SDP exchange (no signaling server). Production integration with
`bolt-rendezvous` is out of scope for this spike.

## Tag Convention

Per ecosystem governance: `daemon-vX.Y.Z[-suffix]`

Current: `daemon-v0.0.2-spike`

## License

MIT
