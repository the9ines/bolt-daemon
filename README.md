# Bolt Daemon

Local protocol authority for Bolt P2P file transfer.

## Architecture Overview

Headless Rust daemon providing browser↔desktop direct transport. Default
transport is WebSocket (WS) with optional WebTransport (WT/HTTP3) and QUIC
transports behind feature flags.

Two runtime modes:
- **WsEndpoint** (default) — WS server for browser↔desktop direct transport, optional WT alongside
- **Simulate** — IPC-only mode for testing pairing/transfer event round-trip

Key capabilities:
- NaCl-box encrypted HELLO handshake with capability negotiation
- Profile Envelope v1 framing with Bolt Transfer Ratchet (BTR) encryption
- IPC channel (Unix socket / Windows named pipe) for native shell integration
- Identity persistence (TOFU) and pairing approval (trust store)
- Rendezvous signaling via bolt-rendezvous WebSocket server

> **Zero WebRTC runtime.** All WebRTC/DataChannel code was removed in
> DEWEBRTC-2 (`f730501`). The `datachannel` and `webrtc-sdp` crates are no
> longer dependencies. The cross-impl E2E test harness (`tests/ts-harness/`)
> retains `node-datachannel` intentionally for browser-fidelity testing —
> this is the only WebRTC surface in the repo.

## Reproducible Builds

`Cargo.lock` is committed and required. This is a binary daemon — all dependency
versions must be pinned for reproducible builds across machines and CI.

```
cargo build
```

Requires: Rust 1.70+.

## CLI Reference

```
bolt-daemon [options]

Mode:
  --mode <ws-endpoint|simulate>      Runtime mode (default: ws-endpoint)

WsEndpoint mode:
  --ws-listen <addr>                 WS listen address (REQUIRED, e.g. 127.0.0.1:9557)
  --socket-path <path>               IPC Unix socket path (default: /tmp/bolt-daemon.sock)
  --data-dir <path>                  Data dir for identity key, trust store, and signal files
  --pairing-policy <ask|allow|deny>  Pairing approval policy (default: ask)
  --phase-timeout-secs <int>         Per-phase timeout in seconds (default: 30)

WebTransport (requires --features transport-webtransport):
  --no-wt                            Force-disable WT even if feature is compiled in

Simulate mode:
  --simulate-event <type>            pairing-request | incoming-transfer (REQUIRED)
```

Legacy flags (`--role`, `--signal`, `--offer`, `--answer`, `--interop-*`) exit 1.
These belonged to the pre-DEWEBRTC-2 WebRTC architecture.

## Running

### WsEndpoint Mode (default)

```bash
cargo run -- --mode ws-endpoint --ws-listen 127.0.0.1:9557
```

The daemon:
1. Starts a WebSocket server on the specified address
2. Generates an ephemeral TLS certificate and starts a WebTransport endpoint
   on the adjacent port (9558) if the `transport-webtransport` feature is enabled
3. Writes WT metadata (`wt_info.json`) to `--data-dir` for the native shell to read
4. Starts an IPC server on `/tmp/bolt-daemon.sock` for native shell communication
5. Waits for browser or native app connections

When a browser connects, the session lifecycle is:
- NaCl-box encrypted HELLO handshake with capability negotiation
- Profile Envelope v1 framing for all post-HELLO messages
- BTR (Bolt Transfer Ratchet) encrypted file transfers when negotiated

### Signal Files

The native shell (e.g. Tauri app) communicates with the daemon via signal files
in the `--data-dir` directory. The daemon polls for these at 250–500ms intervals.

| Signal File | Purpose |
|-------------|---------|
| `send_file.signal` | Write a file path → daemon sends it to the connected browser |
| `connect_remote.signal` | Write a WS URL → daemon connects outbound to a remote peer |
| `disconnect_session.signal` | Touch → daemon disconnects the active session |
| `transfer_pause.signal` | Touch → pause the active transfer |
| `transfer_resume.signal` | Touch → resume a paused transfer |

### Simulate Mode

IPC-only mode for testing the pairing/transfer event flow without a real connection:

```bash
cargo run -- --mode simulate --simulate-event pairing-request
```

Emits a simulated IPC event and waits up to 30s for a decision from a connected
UI client. Exits 0 on decision received, 1 on timeout (fail-closed deny).

## Test

```
cargo test
```

See `docs/STATE.md` for current test breakdown (lib, integration, IPC, session,
relay, cross-impl E2E).

### Test Harness Note

The cross-impl E2E harness (`tests/ts-harness/`) uses `node-datachannel` for
browser-fidelity testing. This is **test-only** — no WebRTC code runs in the
daemon at runtime.

Legacy E2E scripts in `scripts/` (e.g. `e2e_rendezvous_local.sh`) exercise
pre-DEWEBRTC-2 code paths and require `--features legacy-webrtc`.

## Lint

```
cargo fmt
cargo clippy -- -W clippy::all
```

Both must be clean (0 warnings).

## Architecture

```
bolt-daemon/
├── Cargo.toml              # bolt-core, bolt-btr, tungstenite, tokio, serde
├── Cargo.lock              # pinned (committed for reproducible builds)
├── src/
│   ├── main.rs             # CLI, mode dispatch, boot diagnostics
│   ├── lib.rs              # Module exports for integration-test access
│   ├── ws_endpoint.rs      # WS server, session lifecycle, file transfer
│   ├── wt_endpoint.rs      # WebTransport/HTTP3 server (feature-gated)
│   ├── wt_cert.rs          # Ephemeral TLS cert generation for WT
│   ├── ws_btr.rs           # BTR key derivation + chunk encrypt/decrypt
│   ├── ws_validation.rs    # Send-path validation (size, path traversal)
│   ├── web_hello.rs        # NaCl-box encrypted HELLO handshake
│   ├── envelope.rs         # Profile Envelope v1 codec, router, error framing
│   ├── dc_messages.rs      # Inner message types (ping, pong, file ops)
│   ├── session.rs          # SessionContext: HELLO outcome persistence
│   ├── identity_store.rs   # Ed25519 identity keypair persistence
│   ├── transfer.rs         # Transfer state types
│   ├── ice_filter.rs       # NetworkScope policy (retained, not active in WS/WT)
│   ├── ipc/                # IPC server, transport, trust store, event types
│   ├── relay.rs            # Relay protocol
│   ├── relay_main.rs       # bolt-relay binary entry point
│   ├── ipc_client_main.rs  # bolt-ipc-client dev harness
│   └── quic_transport.rs   # QUIC transport (feature-gated)
├── tests/
│   ├── ts-harness/         # Node.js cross-impl E2E (node-datachannel, test-only)
│   ├── e2e-browser/        # Browser E2E tests
│   ├── vectors/            # Golden test vectors
│   └── *.rs                # Integration tests (BTR, QUIC, WS, identity, etc.)
├── scripts/                # E2E regression scripts (some legacy, pre-DEWEBRTC-2)
├── interop/browser/        # Legacy WebRTC interop page (pre-DEWEBRTC-2, not runtime)
└── docs/                   # Contracts, changelog, state, test procedures
```

Key dependencies:
- [`bolt-core`](../bolt-core-sdk/rust/bolt-core) — canonical hash, encoding, crypto primitives
- [`bolt-btr`](../bolt-core-sdk/rust/bolt-btr) — Bolt Transfer Ratchet (per-transfer DH ratchet + ChaCha20-Poly1305)
- [`bolt-transfer-core`](../bolt-core-sdk/rust/bolt-transfer-core) — transport-agnostic transfer state machine
- [`tungstenite`](https://crates.io/crates/tungstenite) v0.24 — sync WebSocket client for rendezvous signaling
- [`tokio-tungstenite`](https://crates.io/crates/tokio-tungstenite) v0.24 — async WebSocket (WS endpoint)
- [`wtransport`](https://crates.io/crates/wtransport) v0.7 — WebTransport/HTTP3 (optional, feature-gated)

## Tag Convention

Per ecosystem governance: `daemon-vX.Y.Z[-suffix]`

Current: `daemon-v0.2.49-dewebrtc2-docs-reconcile`

## License

MIT
