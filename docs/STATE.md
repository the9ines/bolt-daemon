# Bolt Daemon — Current State

## Latest Release

| Field | Value |
|-------|-------|
| Tag | `daemon-v0.1.9-event-0-ipc-skeleton` |
| Commit | `e9ada46` (merge `c314c25`) |
| Branch | `main` |
| Phase | EVENT-0 — daemon ↔ UI IPC skeleton for approval prompts |

## Test Status

- 122 tests (107 bolt-daemon + 15 relay)
- `cargo fmt --check` clean
- `cargo clippy -- -D warnings` 0 warnings
- E2E harness (`scripts/e2e_rendezvous_local.sh`) PASS

## Daemon Modes

| Mode | Status | Notes |
|------|--------|-------|
| Default | Stable | WebRTC transport with file or rendezvous signaling |
| Smoke | Stable | Deterministic payload transfer + SHA-256 verification |
| Simulate | NEW | IPC-only mode for testing event/decision round-trip |

## Signaling Modes

| Mode | Status | Notes |
|------|--------|-------|
| File | Stable | Default mode, JSON files on disk |
| Rendezvous | Stable | WebSocket via bolt-rendezvous, hello/ack handshake |

## Network Scope Policies

| Scope | Status | Use Case |
|-------|--------|----------|
| LAN | Stable (default) | Private/link-local IPs only |
| Overlay | Stable | LAN + CGNAT 100.64.0.0/10 (Tailscale) |
| Global | Stable | All valid IPs (ByteBolt) |

## IPC Channel (EVENT-0)

- Transport: Unix domain socket at `/tmp/bolt-daemon.sock` (chmod 600)
- Protocol: NDJSON (line-delimited JSON, 1 MiB cap per line)
- Client policy: single-client, new connection kicks old
- Fail-closed: no UI connected = pending/deny
- Event types: `pairing.request`, `transfer.incoming.request`, `daemon.status`
- Decision types: `pairing.decision`, `transfer.incoming.decision`
- Decision variants: `allow_once`, `allow_always`, `deny_once`, `deny_always`
- Request IDs: monotonic `evt-<counter>`

## Rendezvous Protocol

- Payload version: 1 (version mismatch → exit 1)
- Session discriminator required (session mismatch → ignore)
- Hello/ack handshake: validates peer identity, network scope, version
- Hello retry: offerer retries on peer-not-found with backoff (100ms→1s)

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| datachannel | 0.16.0 | WebRTC DataChannel (vendored libdatachannel) |
| webrtc-sdp | 0.3 | SDP parsing |
| tungstenite | 0.24 | Sync WebSocket client (rendezvous signaling) |
| bolt-core | path | Canonical hash, encoding, crypto primitives |
| bolt-rendezvous-protocol | 0.1.0 | Canonical signaling types (git dep, tag-pinned) |
| serde/serde_json | 1.x | Serialization |
| rand | 0.8 | Peer ID generation |

## Architecture

```
src/main.rs            — CLI, args, handlers, file mode, simulate mode, E2E flow
src/ipc/mod.rs         — IPC module root
src/ipc/types.rs       — IpcMessage, IpcKind, event/decision payload structs
src/ipc/server.rs      — IpcServer, bounded reader, client handler
src/ipc/id.rs          — Monotonic request ID generator
src/ipc_client_main.rs — bolt-ipc-client dev binary
src/smoke.rs           — Smoke-test harness (sha256 via bolt-core)
src/ice_filter.rs      — NetworkScope policy + candidate filtering (33 tests)
src/rendezvous.rs      — WebSocket signaling via bolt-rendezvous
src/relay_main.rs      — bolt-relay binary
scripts/               — E2E regression harness
interop/browser/       — Browser interop test page
docs/                  — Test procedures, changelog, state
```

## Binaries

| Binary | Source | Purpose |
|--------|--------|---------|
| bolt-daemon | src/main.rs | Main daemon (transport + IPC) |
| bolt-relay | src/relay_main.rs | Relay server |
| bolt-ipc-client | src/ipc_client_main.rs | Dev harness for IPC testing |
