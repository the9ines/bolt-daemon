# Changelog

All notable changes to bolt-daemon. Newest first.

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
