# Bolt Daemon — Current State

## Latest Release

| Field | Value |
|-------|-------|
| Tag (main) | `daemon-v0.2.50-dewebrtc2-readme-complete` |
| Branch | `main` |
| Phase | DEWEBRTC-2-DOCS: Documentation reconciliation COMPLETE |

## Test Status

- 436 tests pass (186 lib + 131 integration + 50 ipc + 15 sa1-sep + 13 sa1-store + 12 session + 11 en3-e2e + 5 relay + others), 0 failures
- `cargo fmt --check` clean
- `cargo clippy -- -D warnings` 0 warnings
- `scripts/check_no_panic.sh` PASS
- E2E harness (`scripts/e2e_rendezvous_local.sh`) PASS

## H-Phase Status

| Phase | Status | Notes |
|-------|--------|-------|
| H3 | DONE-MERGED | Golden vector tests, `daemon-v0.2.5-h3-golden-vectors` (`3751118`) |
| H3.1 | DONE-MERGED | Hermetic vector vendoring, `daemon-v0.2.8-h3.1-vectors-hermetic` (`e6c8851`) |
| H4 | DONE-MERGED | Panic surface elimination, `daemon-v0.2.6-h4-panic-elimination` (`678c808`) |
| H5 | DONE-MERGED | Downgrade resistance + error code alignment (R7), `daemon-v0.2.7-h5-downgrade-validation` |
| H6 | DONE-MERGED | CI enforcement, `daemon-v0.2.9-h6-ci-enforcement` (`398a63d`) |
| P1 | DONE | Inbound error validation hardening, `daemon-v0.2.12-p1-inbound-error-validation` (`8c45819`) |
| B3-P3 | DONE | Sender-side transfer MVP, `daemon-v0.2.29-b3-transfer-sm-p3-sender` (`4fd55e3`) |
| D-E2E-B | DONE | Cross-impl bidirectional TS↔Rust E2E transfer, `daemon-v0.2.30-d-e2e-b-cross-impl` (`a8cf108`) |
| B-DEP-N2 | DONE | IPC version handshake + daemon.status in default mode, `daemon-v0.2.31-bdep-n2-ipc-unblock` |
| N6-B1 | DONE | `--socket-path` and `--data-dir` CLI flags (B-DEP-N1-1), `daemon-v0.2.32-n6b1-path-flags` |
| N6-B2 | DONE | Windows named pipe transport (B-DEP-N2-3), `daemon-v0.2.33-n6b2-windows-pipe` |
| REL-ARCH1 | DONE | Multi-arch build/package matrix, `daemon-v0.2.38-relarch1-multiarch-matrix` (`ab56606`) |
| EN3e | DONE | Session + transfer IPC events, `daemon-v0.2.43-en3e-ipc-session-events` |
| EN3f | DONE | Transfer lifecycle IPC events, `daemon-v0.2.44-en3f-transfer-ipc-events` |
| N-STREAM-TIMEOUT | DONE | Post-HELLO deadline decoupled from signaling phase; heartbeat-driven sessions. Live two-device proof: 253s stable, 3 reconnect cycles. `daemon-v0.2.45-nstream-timeout-hardening` (`ed74bae`), `daemon-v0.2.46-nstream-operational-proof` (`fcf7a85`) |
| DEWEBRTC-2-DOCS | DONE | Post-DEWEBRTC-2 docs/metadata reconciliation (2 passes). `daemon-v0.2.49-dewebrtc2-docs-reconcile` (`e092dcc`): metadata + top-level identity. `daemon-v0.2.50-dewebrtc2-readme-complete` (`c5b7ea8`): operational README rewrite. No runtime code modified. |

## Runtime Architecture

**Zero WebRTC.** All WebRTC/DataChannel runtime code removed (DEWEBRTC-2, `f730501`).

| Transport | Status | Feature Flag | Default |
|-----------|--------|-------------|---------|
| WebSocket (WS) | Active | `transport-ws` | Yes (default feature) |
| WebTransport (WT/HTTP3) | Active | `transport-webtransport` | Optional |
| QUIC | Reference | `transport-quic` | Optional |

The `datachannel` and `webrtc-sdp` crates are no longer dependencies.
`tests/ts-harness/` retains `node-datachannel` for cross-impl E2E testing only.

## Release Artifacts

Release workflow (`.github/workflows/release.yml`) triggers on `daemon-v*` tag push or `workflow_dispatch`.

### Target Matrix

| Target | Runner | Strategy | Shipped Binaries |
|--------|--------|----------|-----------------|
| `x86_64-apple-darwin` | `macos-14` | Native (cross-compile) | bolt-daemon, bolt-relay |
| `aarch64-apple-darwin` | `macos-14` | Native | bolt-daemon, bolt-relay |
| `x86_64-pc-windows-msvc` | `windows-latest` | Native | bolt-daemon.exe, bolt-relay.exe |
| `x86_64-unknown-linux-gnu` | `ubuntu-latest` | Native | bolt-daemon, bolt-relay |
| `aarch64-unknown-linux-gnu` | `ubuntu-latest` | Cross (native gcc toolchain) | bolt-daemon, bolt-relay |

### Archive Naming

- macOS/Linux: `bolt-daemon-<version>-<target>.tar.gz`
- Windows: `bolt-daemon-<version>-<target>.zip`
- Checksums: `SHA256SUMS.txt` (consolidated, one entry per archive)

### Excluded Binaries

- `bolt-ipc-client` — dev harness, not shipped in release archives

### Residual

- Code signing / notarization: not implemented (follow-on)
- `aarch64-pc-windows-msvc`: deferred (no GA GitHub Actions runner)

## Daemon Modes

| Mode | Status | Notes |
|------|--------|-------|
| Default (WsEndpoint) | Stable | WS server for browser↔desktop direct transport |
| Smoke | Stable | Deterministic payload transfer + SHA-256 verification |
| Simulate | NEW | IPC-only mode for testing event/decision round-trip |

## Interop Modes

| Flag | Values | Default | Notes |
|------|--------|---------|-------|
| `--interop-signal` | `daemon_v1`, `web_v1` | `daemon_v1` | Inner signaling payload format |
| `--interop-hello` | `daemon_hello_v1`, `web_hello_v1` | `daemon_hello_v1` | HELLO handshake protocol |
| `--interop-dc` | `daemon_dc_v1`, `web_dc_v1` | `daemon_dc_v1` | Post-HELLO DataChannel mode |
| `--socket-path` | `<path>` | `/tmp/bolt-daemon.sock` | IPC Unix socket path |
| `--data-dir` | `<path>` | `~/.bolt` (identity), `~/.config/bolt-daemon` (trust) | Data directory for identity key + TOFU pins |

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
- B3-P3: FileAccept and Cancel carved out to Ok(None) for loop-level send-side interception
- Pause and Resume remain INVALID_STATE in route_inner_message
- Inbound error validation (P1): `validate_inbound_error()` validates `{type:"error"}` messages
  against `CANONICAL_ERROR_CODES` registry. Unknown/malformed codes → PROTOCOL_VIOLATION + disconnect.
- E2E script: `scripts/e2e_interop_4_local.sh`
- Log markers: `[INTEROP-4]`, `[P1_REMOTE_ERROR]`

## Session Context + Profile Envelope v1 (INTEROP-3)

- SessionContext persists HELLO outcome: local_keypair, remote_public_key, negotiated_capabilities, HelloState
- Profile Envelope v1: `{"type":"profile-envelope","version":1,"encoding":"base64","payload":"<sealed>"}`
- Encryption: NaCl box via bolt_core::crypto (same primitives as HELLO)
- Post-HELLO DC recv loop: decode envelope → minimal router (error → Err, unhandled → log+drop)
- No-downgrade: envelope cap required in web_dc_v1; non-envelope messages = ENVELOPE_REQUIRED
- Error framing: `{"type":"error","code":"<CODE>","message":"<detail>"}` sent on DC before disconnect
- Error framing (I5): `build_error_payload()` wraps errors in profile-envelope when envelope-v1 negotiated
- Wire error codes aligned with PROTOCOL_ENFORCEMENT.md Appendix A (H5)
- Log markers: `[INTEROP-3]`, `[INTEROP-3_NO_ENVELOPE_CAP]`, `[INTEROP-3_ENVELOPE_ERR]`, `[INTEROP-3_UNHANDLED]`

## Error Code Registry Alignment (H5)

Daemon wire error codes aligned with PROTOCOL_ENFORCEMENT.md Appendix A:

| Appendix A Code | Daemon Error Type | Status |
|----------------|-------------------|--------|
| ENVELOPE_REQUIRED | `EnvelopeError::EnvelopeRequired` | Emitted |
| ENVELOPE_INVALID | `EnvelopeError::Invalid` / `ParseError` | Emitted |
| ENVELOPE_DECRYPT_FAIL | `EnvelopeError::DecryptFail` | Emitted |
| ENVELOPE_UNNEGOTIATED | `EnvelopeError::Unnegotiated` | Emitted |
| HELLO_PARSE_ERROR | `HelloError::ParseError` | Emitted |
| HELLO_DECRYPT_FAIL | `HelloError::DecryptFail` | Emitted |
| HELLO_SCHEMA_ERROR | `HelloError::SchemaError` | Emitted |
| KEY_MISMATCH | `HelloError::KeyMismatch` | Emitted |
| DUPLICATE_HELLO | `HelloError::DuplicateHello` | Emitted |
| INVALID_MESSAGE | `EnvelopeError::InvalidMessage` | Emitted |
| UNKNOWN_MESSAGE_TYPE | `EnvelopeError::UnknownMessageType` | Emitted |
| INVALID_STATE | `EnvelopeError::InvalidState` | Emitted |
| PROTOCOL_VIOLATION | `EnvelopeError::ProtocolViolation` / `HelloError::DowngradeAttempt` | Emitted |
| LIMIT_EXCEEDED | *(none)* | Deferred — no daemon rate-limit/size-cap infrastructure |

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
- Trust store default: `~/.config/bolt-daemon/trust.json`
- Trust store with `--data-dir`: `<data-dir>/pins/trust.json`
- `--pairing-policy {ask, deny, allow}` CLI flag (default: ask)
- Fail-closed: no IPC server or no UI connected → deny all
- Stored decisions: `allow_always` / `deny_always` persist; `_once` variants do not

## IPC Channel (EVENT-0)

- Transport: Unix domain socket (chmod 600) or Windows named pipe (DACL current-user-only)
- Default path: `/tmp/bolt-daemon.sock` (Unix) or `\\.\pipe\bolt-daemon` (Windows)
  (override via `--socket-path <path>`)
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
| bolt-btr | path | Bolt Transfer Ratchet (per-transfer DH ratchet) |
| tokio-tungstenite | 0.24 | Async WebSocket (WS endpoint, feature-gated) |
| wtransport | 0.7 | WebTransport/HTTP3 (optional, feature-gated) |
| tungstenite | 0.24 | Sync WebSocket client (rendezvous signaling) |
| bolt-core | path | Canonical hash, encoding, crypto primitives |
| bolt-transfer-core | path | Transport-agnostic transfer state machine |
| bolt-rendezvous-protocol | 0.1.0 | Canonical signaling types (git dep, tag-pinned) |
| serde/serde_json | 1.x | Serialization |
| rand | 0.8 | Peer ID generation |
| windows-sys | 0.59 (cfg(windows)) | Win32 named pipe, security descriptor APIs |

## Architecture

```
src/main.rs            — CLI, args, handlers, file mode, simulate mode, E2E flow
src/dc_messages.rs     — Inner DC message types: ping, pong, app_message (INTEROP-4)
src/session.rs         — SessionContext: HELLO outcome for post-handshake DC operations
src/envelope.rs        — Profile Envelope v1 codec: encode/decode, route, DcErrorMessage, EnvelopeError
src/web_hello.rs       — Web HELLO handshake: NaCl-box encrypted JSON, capability negotiation
src/web_signal.rs      — Web inner signaling payloads: {type,data,from,to} schema
src/ipc/mod.rs         — IPC module root
src/ipc/transport.rs   — Transport abstraction: IpcListener/IpcStream (Unix + Windows named pipe)
src/ipc/types.rs       — IpcMessage, IpcKind, event/decision payload structs
src/ipc/server.rs      — IpcServer, bounded reader, client handler (transport-agnostic)
src/ipc/id.rs          — Monotonic request ID generator
src/ipc/trust.rs       — TrustStore persistence + check_pairing_approval()
src/ipc_client_main.rs — bolt-ipc-client dev binary
src/smoke.rs           — Smoke-test harness (sha256 via bolt-core)
src/ice_filter.rs      — NetworkScope policy + candidate filtering (33 tests)
src/rendezvous.rs      — WebSocket signaling via bolt-rendezvous
src/relay_main.rs      — bolt-relay binary
scripts/               — E2E regression harness
interop/browser/       — Browser interop test page
tests/ts-harness/      — Node.js E2E harness (node-datachannel, tweetnacl, ws)
docs/                  — Test procedures, changelog, state
```

## Binaries

| Binary | Source | Purpose |
|--------|--------|---------|
| bolt-daemon | src/main.rs | Main daemon (transport + IPC) |
| bolt-relay | src/relay_main.rs | Relay server |
| bolt-ipc-client | src/ipc_client_main.rs | Dev harness for IPC testing |
