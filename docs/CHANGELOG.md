# Changelog

All notable changes to bolt-daemon. Newest first.

## INTEROP-4 — Minimal post-HELLO message set (d7a79c4)

Prove the INTEROP-3 session + profile-envelope-v1 path works end-to-end
with real post-HELLO messages: ping/pong heartbeat and app_message echo.

### Added
- `src/dc_messages.rs` (NEW) — DcMessage enum (Ping, Pong, AppMessage) with
  serde tag="type", parse_dc_message/encode_dc_message helpers, now_ms(); 9 tests
- `route_inner_message()` in envelope.rs — routes decrypted inner messages:
  ping → pong reply, pong → log, app_message → log + echo. All replies go
  through encode_envelope (no plaintext sends)
- `EnvelopeError::Protocol` variant for inner message parse failures
- Offerer sends initial ping + app_message after HELLO, periodic ping every 2s
- Answerer responds to ping with pong, echoes app_message
- `scripts/e2e_interop_4_local.sh` — E2E test: rendezvous + offerer + answerer
  in full web interop mode, validates HELLO, envelope, ping/pong, app_message

### Changed
- `src/envelope.rs` — added Protocol error variant, route_inner_message function
- `src/rendezvous.rs` — replaced minimal router stub with route_inner_message
  in both offerer and answerer loops; offerer sends initial messages + periodic ping
- `src/main.rs` — added `pub(crate) mod dc_messages`

### Design
- Inner messages: `{"type":"ping","ts_ms":N}`, `{"type":"pong","ts_ms":N,"reply_to_ms":N}`,
  `{"type":"app_message","text":"..."}`
- All sends go through encode_envelope (NaCl box encrypted)
- Offerer-initiated: sends ping + app_message immediately after HELLO
- Periodic ping: 2s interval from offerer, via Instant bookkeeping in recv loop
- No file transfer, no TOFU, no persistence — minimal validation set only

### Tests
- 210 total (195 bolt-daemon + 15 relay)

## INTEROP-3 — Session Context + Profile Envelope v1 (a39fefc)

Persist HELLO outcome in SessionContext, implement Profile Envelope v1
encrypt/decrypt for DataChannel messages, add post-HELLO DC recv loop
gated by `--interop-dc web_dc_v1`, enforce no-downgrade semantics.

### Added
- `src/session.rs` (NEW) — SessionContext struct storing local_keypair,
  remote_public_key, negotiated_capabilities, HelloState; helpers for
  capability checks and hello completion state; 8 tests
- `src/envelope.rs` (NEW) — ProfileEnvelopeV1 serde type, DcErrorMessage serde
  type, EnvelopeError enum with typed error codes (ENVELOPE_UNNEGOTIATED,
  ENVELOPE_INVALID, ENVELOPE_DECRYPT_FAIL, INVALID_STATE), encode_envelope,
  decode_envelope, make_error_message; 12 tests
- `--interop-dc {daemon_dc_v1, web_dc_v1}` CLI flag (default: daemon_dc_v1)
- Fail-closed validation: web_dc_v1 requires --interop-hello web_hello_v1
  (and transitively --signal rendezvous + --interop-signal web_v1)
- Post-HELLO DC envelope recv loop in offerer + answerer rendezvous paths
- Minimal router: error → Err, unhandled → log `[INTEROP-3_UNHANDLED]` and drop
- No-downgrade: envelope cap required, non-envelope messages rejected in web mode

### Changed
- `src/web_hello.rs` — removed `#[allow(dead_code)]` from HelloState, made `pub(crate)`
- `src/main.rs` — InteropDcMode enum, `--interop-dc` CLI parsing, fail-closed
  validation block, Args.interop_dc field, startup log update
- `src/rendezvous.rs` — SessionContext construction after HELLO exchange,
  post-HELLO DC envelope loop (offerer + answerer), envelope error handling
  with DC error message send + disconnect

### Design
- Profile Envelope v1: `{"type":"profile-envelope","version":1,"encoding":"base64","payload":"<sealed>"}`
- Encryption: NaCl box via bolt_core::crypto (same primitives as HELLO)
- SessionContext carries HELLO outcome for post-handshake DC operations
- HelloState wired into runtime (no longer dead_code)
- daemon_dc_v1 preserves current behavior (return after HELLO, no loop)
- Log markers: `[INTEROP-3]`, `[INTEROP-3_NO_ENVELOPE_CAP]`,
  `[INTEROP-3_ENVELOPE_ERR]`, `[INTEROP-3_UNHANDLED]`

### INTEROP-2 gaps resolved
- HelloState wired into runtime via SessionContext
- Negotiated capabilities persisted in SessionContext (no longer dropped)

### Tests
- 201 total (186 bolt-daemon + 15 relay)

## INTEROP-2 — Web HELLO handshake compatibility (dd82669)

Add web-compatible encrypted HELLO handshake over DataChannel, gated by
`--interop-hello {daemon_hello_v1, web_hello_v1}`. When web_hello_v1 is
enabled, the daemon performs the same NaCl-box encrypted JSON HELLO
exchange that bolt-transport-web uses.

### Added
- `src/web_hello.rs` (NEW) — InteropHelloMode enum, WebHelloOuter/WebHelloInner
  serde types, build_hello_message/parse_hello_message (NaCl box via bolt-core),
  capability negotiation, HelloState exactly-once guard, decode_public_key helper
- `--interop-hello {daemon_hello_v1, web_hello_v1}` CLI flag (default: daemon_hello_v1)
- Fail-closed validation: web_hello_v1 requires --signal rendezvous + --interop-signal web_v1
- No-downgrade: legacy `b"bolt-hello-v1"` rejected in web_hello_v1 mode
- 20 new tests in web_hello.rs (serde, crypto roundtrip, bidirectional, failure, capabilities)

### Changed
- `src/web_signal.rs` — `public_key_b64: Option<String>` added to ParsedWebSignal::Offer
  and ::Answer; encode_web_offer/encode_web_answer/bundle_to_web_payloads accept
  identity_pk_b64 parameter; 4 new tests
- `src/rendezvous.rs` — identity keypair generation, publicKey threading through
  send_web_payloads/receive_web_bundle, encrypted web HELLO exchange in offerer
  and answerer flows
- `src/main.rs` — `pub(crate) mod web_hello`, Args.interop_hello field, startup log

### Design
- Identity keypairs: ephemeral per process run (generate_identity_keypair)
- Key exchange: identity public keys carried in signaling publicKey field
- Outer frame: `{"type":"hello","payload":"<sealed base64>"}`
- Inner plaintext: `{"type":"hello","version":1,"identityPublicKey":"<b64>","capabilities":[...]}`
- Encryption: NaCl box via bolt_core::crypto::{seal_box_payload, open_box_payload}
- Capabilities: `["bolt.profile-envelope-v1"]` (negotiated via set intersection)
- Offerer sends HELLO first; answerer receives, then replies

### Known gaps (INTEROP-3 prerequisites)
- HelloState not yet wired into runtime (low-risk: single-shot flows)
- Negotiated capabilities logged and dropped (no session context struct yet)

### Tests
- 181 total (166 bolt-daemon + 15 relay)

## INTEROP-1 — Web inner signaling payload mode (14c7448)

Add `--interop-signal {daemon_v1, web_v1}` CLI flag for web-compatible inner
signaling payloads. When web_v1 is enabled, the daemon uses `{type, data, from, to}`
schema matching bolt-transport-web instead of daemon-native bundled schema.

### Added
- `src/web_signal.rs` (NEW) — InteropSignal enum, WebSignalPayload/WebOfferData/
  WebAnswerData/WebSdp/WebIceCandidateData serde types, ParsedWebSignal enum,
  parse_web_payload, encode_web_offer/encode_web_answer/encode_web_ice_candidate,
  bundle_to_web_payloads, conversion helpers, 18 tests
- `--interop-signal {daemon_v1, web_v1}` CLI flag (default: daemon_v1)
- send_web_payloads() and receive_web_bundle() in rendezvous.rs
- 3s ICE collection window for trickled candidates in web_v1 mode
- Daemon-format fallback in receive_web_bundle (defensive compat)

### Changed
- `src/rendezvous.rs` — offerer/answerer branching on interop_signal for offer
  send and answer receive
- `src/main.rs` — `pub(crate) mod web_signal`, Args.interop_signal field, startup log

### Tests
- 157 total (142 bolt-daemon + 15 relay)

## EVENT-1 — Pairing approval hook (6328ce2)

Wire pairing approval into the rendezvous answerer handshake. When the
answerer receives a hello from a remote peer, it consults the trust store
and (if needed) emits pairing.request over IPC for a UI decision.

### Added
- `src/ipc/trust.rs` — TrustStore (JSON persistence at ~/.config/bolt-daemon/trust.json),
  PairingPolicy enum (ask/deny/allow), check_pairing_approval() function
- `--pairing-policy {ask, deny, allow}` CLI flag (default: ask)
- 12 new trust tests

### Changed
- `src/rendezvous.rs` — pairing approval gate in run_answerer_rendezvous
  (after hello validation, before ack)
- `src/main.rs` — IPC server start in Default mode, trust_path plumbing,
  Args.pairing_policy field
- `src/ipc/mod.rs` — `pub mod trust;`

### Design
- Answerer-only: offerer explicitly chose to connect
- Trust keyed by from_peer (session-specific; will re-key to identity keys later)
- Fail-closed: no IPC server or no UI connected → deny all
- Policy override: --pairing-policy allow bypasses IPC, deny rejects all

### Tests
- 142 total (127 bolt-daemon + 15 relay)

## EVENT-0 — Daemon ↔ UI IPC skeleton (e9ada46)

Add local Unix-socket NDJSON IPC between bolt-daemon and a UI client.
Defines event/decision schema (pairing.request, transfer.incoming.request,
daemon.status), strict bounded parser (1 MiB cap), request correlation,
and a dev client + simulator to prove round-trip. Fail-closed when UI
is disconnected.

### Added
- `src/ipc/` module: types.rs, server.rs, id.rs, mod.rs
- `src/ipc_client_main.rs` — bolt-ipc-client dev binary
- `--mode simulate --simulate-event` CLI (standalone, no --role required)
- 28 new unit tests (3 id + 15 types + 10 server)

### Changed
- `src/main.rs` — DaemonMode::Simulate, SimulateEvent enum, run_simulate(),
  role made Option<Role> (optional for simulate mode)
- `src/rendezvous.rs` — handle Option<Role>
- `Cargo.toml` — add [[bin]] bolt-ipc-client

### Design
- Socket: `/tmp/bolt-daemon.sock` (chmod 600, single-client, kick-old policy)
- IDs: `evt-<monotonic counter>` (deterministic, no rand)
- Channel: event_tx in daemon, decision_rx in daemon; server holds receivers
- Bounded reader: `read_until(b'\n')` with 1 MiB cap
- Decision variants: allow_once, allow_always, deny_once, deny_always

### Tests
- 122 total (107 bolt-daemon + 15 relay)

## NATIVE-1 — Adopt Rust bolt-core (b3ebb85)

Replaces local `sha2` + `hex` crate usage in `smoke.rs` with canonical
`bolt_core::hash::sha256_hex`. Removes direct `sha2` and `hex` dependencies.
bolt-core is now a path dependency (`../bolt-core-sdk/rust/bolt-core`).

### Changed
- `Cargo.toml` — added `bolt-core` path dependency, removed `sha2 = "0.10"`
  and `hex = "0.4"`.
- `src/smoke.rs` — `sha256_hex()` now delegates to `bolt_core::hash::sha256_hex`.
  Removed `use sha2::{Digest, Sha256}`.

### Tests
- 94 tests (79 main + 15 relay). Added `sha256_hex_matches_bolt_core_canonical`
  adoption test.

## Phase A2 — Consume bolt-rendezvous-protocol (276b5ad)

Replaces inline `ClientMsg`, `ServerMsg`, `PeerInfo` definitions with
canonical types from `bolt-rendezvous-protocol` crate. Zero wire format
changes. Zero new transitive dependencies (serde + serde_json already
present).

### Changed
- `Cargo.toml` — added git dependency: `bolt-rendezvous-protocol`
  pinned to `rendezvous-protocol-v0.1.0` tag.
- `src/rendezvous.rs` — removed `ClientMsg`, `ServerMsg`, `PeerInfo`
  inline definitions. Imports `ClientMessage`, `ServerMessage`,
  `PeerData`, `DeviceType` from `bolt_rendezvous_protocol`.
  `device_type: "desktop".to_string()` → `device_type: DeviceType::Desktop`.
  `SignalPayload` stays local (daemon-specific).

### Tests
- 93 tests (78 main + 15 relay). No test changes (wire format preserved).

## daemon-v0.0.9-rendezvous-hello-retry (0d7658e)

Phase 3G — Rendezvous session + hello/ack handshake + hello retry.

- Add `--session` CLI flag (REQUIRED for rendezvous mode, fail-closed)
- Extend `SignalPayload` with `payload_version` (must be 1) and `session` fields
- Hello/ack handshake validates peer identity, network scope, and payload version
  before offer/answer exchange
- Offerer retries hello send with backoff (100ms→1s) when target peer not yet
  registered (peer-not-found is the only retryable error)
- Version mismatch → exit 1 (fatal). Session mismatch → ignore (non-fatal).
- `scope_to_str()` helper in rendezvous.rs (ice_filter.rs unchanged)
- Local E2E test script (`scripts/e2e_rendezvous_local.sh`)
- 58 tests pass, clippy 0 warnings, E2E PASS

Files changed:
  src/main.rs, src/rendezvous.rs, scripts/e2e_rendezvous_local.sh,
  README.md, docs/E2E_LAN_TEST.md

## daemon-v0.0.8-overlay-scope (a0cf64d)

Phase 3F — Overlay network scope for Tailscale.

- Add `--network-scope overlay` accepting LAN + CGNAT 100.64.0.0/10
- 11 overlay-specific ICE filter tests
- 50 total tests

## daemon-v0.0.7-network-scope (61f6858)

Phase 3E-B — Network scope policy (LAN vs Global).

- `--network-scope <lan|global>` CLI flag (default: lan)
- ICE candidate filtering at outbound (on_candidate) and inbound (apply_remote_signal)
- Global mode accepts all valid IPs (private + public + CGNAT)
- 39 total tests (22 ICE filter + 7 transport + 10 rendezvous)

## daemon-v0.0.6-rendezvous (c3afcdc)

Phase 3E-A — Rendezvous signaling via bolt-rendezvous WebSocket server.

- `--signal rendezvous` mode with fail-closed behavior (no fallback to file mode)
- `--rendezvous-url`, `--room`, `--to`, `--expect-peer`, `--peer-id` flags
- `--phase-timeout-secs` configurable deadline (default: 30s)
- Mirrors bolt-rendezvous protocol types in rendezvous.rs
- 17 total tests
