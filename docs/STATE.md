# Bolt Daemon — Current State

## Latest Release

| Field | Value |
|-------|-------|
| Tag | `daemon-v0.1.7-relay-skeleton` |
| Commit | `276b5ad` |
| Branch | `main` |
| Phase | A2 — consume bolt-rendezvous-protocol shared types |

## Test Status

- 93 tests (78 main binary + 15 relay binary)
- `cargo fmt --check` clean
- `cargo clippy -- -W clippy::all` 0 warnings
- E2E harness (`scripts/e2e_rendezvous_local.sh`) PASS

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
| bolt-rendezvous-protocol | 0.1.0 | Canonical signaling types (git dep, tag-pinned) |
| serde/serde_json | 1.x | Serialization |

## Architecture

```
src/main.rs          — CLI, args, handlers, file mode, E2E flow
src/ice_filter.rs    — NetworkScope policy + candidate filtering (33 tests)
src/rendezvous.rs    — WebSocket signaling via bolt-rendezvous (consumes bolt-rendezvous-protocol types)
scripts/             — E2E regression harness
interop/browser/     — Browser interop test page
docs/                — Test procedures, changelog, state
```
