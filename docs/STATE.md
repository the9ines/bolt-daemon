# Bolt Daemon — Current State

## Latest Release

| Field | Value |
|-------|-------|
| Tag (main) | `daemon-v0.2.4-interop-4-min-msgset` |
| Commit (main) | `719752d` (merge of `d7a79c4`) |
| Tag (feature) | `daemon-v0.2.5-h3-golden-vectors` |
| Commit (feature) | `3751118` |
| Branch | `feature/h4-panic-elimination` (current), `feature/h3-golden-vectors` (H3 tagged) |
| Phase | H4 — Panic surface elimination (in-flight) |

## Test Status

- 215+ tests (with `--features test-support`, on feature branch)
- 210 tests (main, without test-support feature)
- `cargo fmt --check` clean
- `cargo clippy -- -D warnings` 0 warnings
- E2E harness (`scripts/e2e_rendezvous_local.sh`) PASS

## H-Phase Status

| Phase | Status | Notes |
|-------|--------|-------|
| H3 | DONE | Golden vector tests, `daemon-v0.2.5-h3-golden-vectors` (`3751118`), feature branch |
| H4 | In-flight | Panic surface elimination, `feature/h4-panic-elimination` |
| H5 | Planned | Downgrade resistance + error code validation |

## Daemon Modes

| Mode | Status | Notes |
|------|--------|-------|
| Default | Stable | WebRTC transport with file or rendezvous signaling |
| Smoke | Stable | Deterministic payload transfer + SHA-256 verification |
| Simulate | NEW | IPC-only mode for testing event/decision round-trip |

## Interop Modes

| Flag | Values | Default | Notes |
|------|--------|---------|-------|
| `--interop-signal` | `daemon_v1`, `web_v1` | `daemon_v1` | Inner signaling payload format |
| `--interop-hello` | `daemon_hello_v1`, `web_hello_v1` | `daemon_hello_v1` | HELLO handshake protocol |
| `--interop-dc` | `daemon_dc_v1`, `web_dc_v1` | `daemon_dc_v1` | Post-HELLO DataChannel mode |

- `web_dc_v1` requires `--interop-hello web_hello_v1` (and transitively rendezvous + web_v1)
- `web_hello_v1` requires `--signal rendezvous` + `--interop-signal web_v1` (fail-closed validation)
- `web_v1` signaling uses `{type, data, from, to}` schema matching bolt-transport-web
- `web_hello_v1` uses NaCl-box encrypted JSON HELLO over DataChannel
- `web_dc_v1` enables post-HELLO envelope recv loop with Profile Envelope v1

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

## Post-HELLO Message Set (INTEROP-4)

- Inner message types: ping, pong, app_message (serde-tagged enum)
- Offerer sends initial ping + app_message immediately after HELLO
- Periodic ping: 2s interval from offerer via Instant bookkeeping
- Answerer responds: ping → pong reply, app_message → echo
- All sends go through encode_envelope (NaCl box encrypted)
- route_inner_message() in envelope.rs handles dispatch
- E2E script: `scripts/e2e_interop_4_local.sh`
- Log markers: `[INTEROP-4]`

## Session Context + Profile Envelope v1 (INTEROP-3)

- SessionContext persists HELLO outcome: local_keypair, remote_public_key, negotiated_capabilities, HelloState
- Profile Envelope v1: `{"type":"profile-envelope","version":1,"encoding":"base64","payload":"<sealed>"}`
- Encryption: NaCl box via bolt_core::crypto (same primitives as HELLO)
- Post-HELLO DC recv loop: decode envelope → minimal router (error → Err, unhandled → log+drop)
- No-downgrade: envelope cap required in web_dc_v1; non-envelope messages = protocol violation
- Error framing: `{"type":"error","code":"<CODE>","message":"<detail>"}` sent on DC before disconnect
- Log markers: `[INTEROP-3]`, `[INTEROP-3_NO_ENVELOPE_CAP]`, `[INTEROP-3_ENVELOPE_ERR]`, `[INTEROP-3_UNHANDLED]`

## Web HELLO Handshake (INTEROP-2)

- Identity keypairs: ephemeral per process run (`generate_identity_keypair`)
- Key exchange: identity public keys carried in signaling `publicKey` field
- Outer frame: `{"type":"hello","payload":"<sealed base64>"}`
- Inner plaintext: `{"type":"hello","version":1,"identityPublicKey":"<b64>","capabilities":[...]}`
- Encryption: NaCl box via `bolt_core::crypto::{seal_box_payload, open_box_payload}`
- Capabilities: `["bolt.profile-envelope-v1"]` (negotiated via set intersection)
- Offerer sends HELLO first; answerer receives, then replies
- No-downgrade: legacy `b"bolt-hello-v1"` rejected in `web_hello_v1` mode

## Pairing Approval (EVENT-1)

- Answerer-only: offerer explicitly chose to connect
- Trust store: `~/.config/bolt-daemon/trust.json` keyed by `from_peer`
- `--pairing-policy {ask, deny, allow}` CLI flag (default: ask)
- Fail-closed: no IPC server or no UI connected → deny all
- Stored decisions: `allow_always` / `deny_always` persist; `_once` variants do not

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
src/dc_messages.rs     — Inner DC message types: ping, pong, app_message (INTEROP-4)
src/session.rs         — SessionContext: HELLO outcome for post-handshake DC operations
src/envelope.rs        — Profile Envelope v1 codec: encode/decode, route, DcErrorMessage, EnvelopeError
src/web_hello.rs       — Web HELLO handshake: NaCl-box encrypted JSON, capability negotiation
src/web_signal.rs      — Web inner signaling payloads: {type,data,from,to} schema
src/ipc/mod.rs         — IPC module root
src/ipc/types.rs       — IpcMessage, IpcKind, event/decision payload structs
src/ipc/server.rs      — IpcServer, bounded reader, client handler
src/ipc/id.rs          — Monotonic request ID generator
src/ipc/trust.rs       — TrustStore persistence + check_pairing_approval()
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
