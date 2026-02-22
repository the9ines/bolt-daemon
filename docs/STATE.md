# Bolt Daemon — Current State

## Latest Release

| Field | Value |
|-------|-------|
| Tag | `daemon-v0.0.9-rendezvous-hello-retry` |
| Commit | `0d7658e` |
| Branch | `main` |
| Phase | 3G — rendezvous session + handshake + hello retry |

## Test Status

- 58 tests (33 ICE filter + 7 transport/signaling + 18 rendezvous protocol)
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
| serde/serde_json | 1.x | Serialization |

## Architecture

```
src/main.rs          — CLI, args, handlers, file mode, E2E flow
src/ice_filter.rs    — NetworkScope policy + candidate filtering (33 tests)
src/rendezvous.rs    — WebSocket signaling via bolt-rendezvous (18 tests)
scripts/             — E2E regression harness
interop/browser/     — Browser interop test page
docs/                — Test procedures, changelog, state
```
