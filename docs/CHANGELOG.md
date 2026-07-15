# Changelog

All notable changes to bolt-daemon. Newest first.

## security: reject legacy no-identity WS HELLO (EA2 bypass closure) — 2026-07-14

Authorization hardening (EA2). A `legacy: true` WS HELLO carries no identity, so it
cannot be trust-enforced, SAS-verified, or attributed to a peer — yet the daemon
ACCEPTED it and entered the shared session loop and transfer handling with no identity,
no SAS, and no `enforce_session_trust`. Both WS legacy branches now fail closed with an
explicit `[PROTOCOL_VIOLATION]` error instead of a silent downgrade:
- Inbound/answerer (`handle_connection`): a legacy HELLO is rejected before any legacy
  response is sent and before any session is built. The daemon no longer emits a legacy
  HELLO response or `session.connected`; the connection closes.
- Outbound/offerer (`connect_to_remote_ws`): a legacy HELLO *response* is rejected
  instead of running the session with a zero identity key and an empty SAS.

Modern clients always send an identity HELLO (the web SDK was hardened under SA10), so
no supported flow depends on legacy. No protocol crypto, wire envelope format, product
UX, or pin semantics changed; no reliance on `ACTIVE_SESSION` (EA27 stays separate).

Tests: the old `ws_legacy_hello_establishes_session` (which asserted the bypass) is
replaced by adversarial `ws_legacy_hello_rejected_no_session` (inbound: the daemon
closes, sends no legacy response, emits no `session.connected`) and new
`ws_client_rejects_legacy_hello_response` (outbound: `connect_to_remote_ws` returns an
explicit `PROTOCOL_VIOLATION` and emits no session). Mutation-verified: restoring either
legacy-accept makes the corresponding test fail. Full daemon lib 259/259 (default),
290/290 (native-full). Authorization gating only: nothing is verified or pinned.

## test: pin the WebTransport trust gate with mutation-verified deny tests — 2026-07-14

Follow-up to the item-3 WT gate (`2ae6af7`). A code red-team found the WT enforcement
was not actually pinned by any test: the deny test discarded the daemon's HELLO
response, sent no file chunk, and never asserted the denial came from the gate — it
tripped only on a 5s timeout; the "allow" test used `PairingPolicy::Allow`
(pass-through), so it would have stayed green even if the gate were deleted. No test
exercised a policy-driven denial, so a wrong-role regression (Answerer->Offerer, which
routes an unpinned peer through Stage B to Allow) would have shipped green.

Strengthened tests, NO production change:
- `wt_session_missing_trust_config_denies_before_transfer` now completes a full,
  well-formed handshake (parsing the HELLO response to prove Step 7 is reached), sends
  a real encrypted `FileChunk`, and asserts the returned error is the gate's
  (`[PAIRING_DENIED] ... WT_SESSION`), that no `transfer.started/complete` fires, and
  that `ACTIVE_SESSION` stays `None`.
- NEW `wt_session_deny_policy_blocks_established_peer`: the differential twin of the
  allow test — identical valid handshake + chunk, but a VALID `Deny` policy. Because the
  ONLY difference from the passing allow test is the policy, it fails if the gate is
  deleted or wired to the wrong role.
- Shared `wt_drive_handshake_and_send_chunk` / `wt_saw_transfer_for` test helpers.

Mutation-verified (temporary gate breaks, reverted): role Answerer->Offerer makes the
deny-policy test FAIL while the missing-config test still passes (it structurally cannot
catch a role bug — the gap the new test closes); making the gate non-blocking makes BOTH
deny tests FAIL. Restored: WT lib 3/3, full daemon lib suite 265/265, `wt_endpoint.rs`
clippy-clean. Clears the code-red-team test-quality blocker on EA3. Also registers the
pre-existing `ACTIVE_SESSION` single-global production race (EA27) and the WT
`session.connected`/`session.sas` observability gap (EA28) the review surfaced — both
out of scope for this change.

## security: gate WebTransport sessions through the trust enforcement path (item 3) — 2026-07-14

Authorization gating (EA3). The WebTransport handler never called
`enforce_session_trust`, so an inbound WT session reached the shared session loop
and transfer handling UNGATED, while WS and QUIC already gate. Now `WtEndpointConfig`
carries a `trust_config` (threaded from main.rs exactly like WS/QUIC), and
`handle_incoming_session` calls the same Answerer trust gate right after the
HELLO/identity exchange and BEFORE `run_session_with_outbound`. A missing
`trust_config` denies (item 2 fail-closed); Ask/Deny/Allow match the current policy;
a denied WT peer never reaches transfer. Authorization gating ONLY: not verification,
pins nothing. `enforce_session_trust` + `SessionTrustRole` are now `pub(crate)`, and
the EA26 test-serialization lock was promoted to a crate-visible static so the WT
session tests share it (WT sessions also register the global `ACTIVE_SESSION`).
Tests: adversarial (missing `trust_config` denies before transfer) and the existing
WT session test now passes an explicit allow config. WT 6/6 single-threaded,
native-full session+WT parallel 5/5, default WS parallel 5/5.

## test: serialize session tests to fix the EA26 parallel `cargo test` flake — 2026-07-14

The WS and QUIC session tests drive the process-global `ACTIVE_SESSION` / `IPC_TX`
singletons; run in parallel they clobbered each other's session slot, so
`cargo test` flaked intermittently (`ws_transfer_pause_resume` failed ~5/6 under
default parallel; QUIC session tests failed ~6/6 under `transport-quic`). Test-only
fix: a shared `tokio::sync::Mutex` (`SESSION_GLOBALS_LOCK`) that the 10
session-establishing tests (7 WS + 3 QUIC) hold for their duration, serializing
them. NO production code changed (the daemon runs a single native session), and no
protocol / trust / crypto / product behavior changed. Verified: default WS parallel
10/10 green (was ~5/6), `transport-quic` session parallel 5/5 green (was ~6/6 fail).
Closes EA26.

## security: fail-closed daemon trust gate on missing trust_config — 2026-07-14

Authorization hardening (trust-gate near-term item 2). `enforce_session_trust`
returned `Ok` (allow) when `trust_config` was `None` — a silent-open a mis-wired
transport could ride through. It now DENIES on a missing config. Production is
unaffected: `main.rs` always builds a `SessionTrustConfig` from `--pairing-policy`
(default `Ask`), so `None` never reaches the gate in production; only test fixtures
passed `None` and relied on the fail-open, and they now pass an explicit
auto-accept config. New adversarial test proves a `None` config denies for both
roles. This is authorization hardening only: it is NOT cryptographic verification
and introduces no verified/pin semantics. (Note: the pre-existing EA26 parallel
test-isolation flake on `ws_transfer_pause_resume` is orthogonal and confirmed on
the prior commit; not introduced here.)

## refactor(ipc): async, Send, concurrent-safe pairing-decision channel — 2026-07-14

Foundational step of the trust-gate near-term hardening (enables the EA2/EA3/EA4
wiring; not those fixes themselves). `IpcServer` held a `std::sync::mpsc::Receiver`,
making it `!Send` so it could not cross into async session tasks, and
`await_decision` was a blocking 30s sleep-poll that discarded any decision whose
`request_id` did not match the single caller (concurrent pairings cross-cancelled).
Now a dedicated router thread owns the receiver and fans each decision by
`request_id` to a per-request `tokio::sync::oneshot`; `await_decision` is async with
`tokio::time::timeout`, fail-closed on timeout with waiter cleanup (no leak). The
daemon hands out a cheap `Send` + `Clone` `ApprovalHandle` (event sender + waiter
map + ui-connected flag) that async tasks can move across `tokio::spawn`.
`check_pairing_approval` is now async. NO product/session behavior is wired yet and
NO verified/pin semantics are introduced. Tests: `Send` assertion, concurrent
routing by request_id, timeout fail-closed + no-leak.

## security: fix panic on a non-ASCII transfer_id (EA17) — 2026-07-14

`parse_transfer_id_bytes` guarded on `tid.len()` (a byte count), so a non-ASCII
32-byte transfer_id passed the length check, then `&tid[i*2..i*2+2]` could slice
inside a multi-byte UTF-8 char and panic — network-reachable via
`ws_btr::decrypt_chunk_btr`. Now uses `tid.get(range)`, which yields None on a
non-char-boundary, and fails closed with an error. UNIT + ADVERSARIAL regression
tests added (8-char emoji = 32 bytes; a euro-prefixed mid-boundary slice). Part of
the 2026-07-14 EA-series audit remediation.

## security: bump anyhow, rand, rustls-webpki for 6 RUSTSEC advisories (EA25) — 2026-07-14

Surgical non-cascading pins (0 crates added or removed): anyhow 1.0.103, rand 0.8.6
and 0.9.3, rustls-webpki 0.103.13. Clears RUSTSEC-2026-0190 (anyhow), -0097 (rand),
and the rustls-webpki CRL/name-constraint advisories -0104/-0098/-0099/-0049.
cargo-audit clean; cargo check clean.

## security: bump quinn-proto to 0.11.15 for RUSTSEC-2026-0185 (EA10) — 2026-07-14

quinn-proto 0.11.14 carried a remote memory-exhaustion DoS in the bundled
QUIC/WebTransport reassembly path. Surgical `--precise 0.11.15` (avoided 0.11.16's
rand-0.10 + 8-crate cascade). CI unaffected (default features are transport-ws).

## Drop native-tls/OpenSSL — daemon is pure-ring and cross-compiles for Linux/Windows — 2026-07-03

The daemon depended on `native-tls` (OpenSSL) via a `tungstenite` feature flag, but it was
vestigial: the WS transport only ever speaks plain `ws://` (the Bolt envelope layer provides
NaCl encryption; QUIC/WT carry their own rustls/ring TLS). native-tls pulled OpenSSL, which
blocked cross-compiling the daemon for Linux from macOS (no target `libssl`) and would have
added an OpenSSL runtime dependency to a Steam Deck Flatpak / Windows build.

Removed the `native-tls` feature + direct dep. `openssl`, `openssl-sys`, and `native-tls` are
now entirely absent from the tree — crypto is pure-ring. Behavior-preserving (plain ws://
unchanged; 380 tests green, fmt+clippy clean). Verified: the daemon now cross-compiles for
`x86_64-unknown-linux-gnu` (the Steam Deck arch) via cargo-zigbuild. De-risks the Linux/Windows
release tracks.

## TRANSPORT-UNIFY-1 cleanup — neutral session-loop log tags + rename ws_endpoint.rs — 2026-07-03

Finishes the transport-unification cleanup now that all three transports share one
session loop. Two changes, behavior-preserving:

1. Log tags: the shared session loop (`run_session_with_outbound` + `run_read_loop`),
   the outbound send path (`send_file_to_browser`), and the pause/resume/disconnect
   controls now log transport-neutral `[SESSION]`/`[TRANSFER]` instead of
   `[WS_SESSION]`/`[WS_TRANSFER]` — they fire for WS, QUIC, and WebTransport alike, so
   the `[WS_*]` prefix was misleading (a WebTransport transfer logged `[WS_TRANSFER]`).
   WS-endpoint-specific paths (accept, WS upgrade, WS HELLO establishment) keep `[WS_*]`.
2. Rename: `src/ws_endpoint.rs` -> `src/session_loop.rs` (`mod ws_endpoint` ->
   `mod session_loop`). The file's defining role post-unification is the shared session
   loop, not WS-specific code. All references across 10 files updated; module doc header
   rewritten. (`session` was already taken by the `bolt_core::session` re-export shim.)

Runtime-confirmed: the WebTransport session test now logs only `[SESSION]`/`[TRANSFER]`,
no `[WS_*]`. 380 tests pass; fmt + clippy clean.

## APP-TO-APP-DIAL-FIX-1 — bound the QUIC handshake so app-to-app falls back to WS fast — 2026-07-03

Fixes the native app-to-app "waiting for encrypted channel" hang. The native app
correctly writes a QUIC-complete `connect_remote` signal (wsUrl + quicAddr +
quicCertHash), and the daemon tries QUIC first, falling back to WS on error. But the
QUIC handshake (`QuicDialer::connect_with_config`) had no short timeout — a stalled or
unreachable QUIC peer blocked ~30s on the idle timeout before erroring, delaying the
(working) WS fallback and reading as a connection hang.

Fix: bound the handshake with `QUIC_CONNECT_TIMEOUT` (5s). A stalled QUIC connect now
errors in 5s and the connect watcher falls back to WS immediately. Reproduced
same-machine: a QUIC-complete signal with an unreachable quicAddr + valid wsUrl now
establishes the WS session in ~6s (was ~35s). Healthy QUIC is unaffected (LAN
handshakes complete in milliseconds). New regression test
`connect_handshake_fails_fast_for_unreachable_peer`. 380 tests pass; fmt + clippy clean.

Corrects the earlier app-to-app root-cause note: the defect is daemon-side QUIC dial
timing, NOT a missing dial in the localbolt-app Swift wiring (the app wiring is correct).

## TRANSPORT-UNIFY-1 Phase 2 test — WebTransport session IPC integration test — 2026-07-03

Closes the coverage gap flagged during Phase 2 review: no test exercised the
WebTransport post-HELLO session path (it was never covered, even for the recovered
May code). New `wt_session_emits_ipc_transfer_events_on_receive` (in `wt_endpoint.rs`
test module) stands up a real wtransport client + server, drives
`handle_incoming_session` through the full HELLO handshake, sends one NaCl-sealed file
chunk, and asserts the daemon emits `transfer.started` + `transfer.complete` via the
threaded `ipc_tx` (the shared read loop) and saves the exact bytes. This runtime-proves
the Phase 2 fold (WT -> shared loop) and the `ipc_tx` threading end to end — the log
shows `[WT_SESSION] entering shared session loop` -> `[BTR] engine initialized` ->
`[WS_TRANSFER] saved`. 379 tests pass; fmt + clippy (project gate) clean.

## TRANSPORT-UNIFY-1 Phase 2 — fold WebTransport onto the shared session loop — 2026-07-03

Behavior-preserving refactor. WebTransport now routes through the same
`ws_endpoint::run_session_with_outbound` + `run_read_loop` that WS and QUIC use.
Added `session_frame::{WtFrameSink, wt_message_stream}` (mirroring the QUIC adapters;
`wt_message_stream` wraps the existing `read_frame` via `stream::unfold`, preserving
the 4-byte length-prefix wire framing and retaining in-flight reads across select
cancellations). Deleted `wt_endpoint::run_message_loop` (~280 lines — the
recovered-May-code BTR/transfer copy) plus WT's own `DISCONNECT_REQUESTED` flag;
WT inherits BTR, `transfer.*` IPC events, and disconnect handling from the shared
loop. `wt_endpoint.rs` 855 -> 478 lines.

Key correctness (the one real risk): `ipc_tx` is threaded `main.rs` ->
`run_wt_endpoint` -> `handle_incoming_session` -> `run_session_with_outbound`. The
shared loop emits via `emit_ipc(ipc_tx)` (a no-op on `None`); the threaded sender and
the global `IPC_TX` are clones of the same channel, so IPC delivery is identical to
the old `emit_ipc_global` path. `create_dir_all` was lifted into the shared loop to
preserve WT's destination-dir creation (a strict improvement for WS/QUIC too).

Validation: `cargo test --features native-full -- --test-threads=1` -> 378 passing;
fmt + clippy clean; WS-only and QUIC-only builds compile (WT cfg-gated). A 3-agent
adversarial review of the diff returned CLEAN — all six identified risks handled or
benign. Open follow-up: no test exercises the WT post-HELLO session path (a
pre-existing gap, never covered even for the recovered May code); a WT session/IPC
integration test is the top NOW item. A runtime browser-over-WT check was attempted
but blocked by an environmental Chrome WebTransport cert-handshake issue unrelated to
this change (the WT endpoint was confirmed listening).

## TRANSPORT-UNIFY-1 Phase 1 — unify WS+QUIC session loop onto a frame seam — 2026-07-03

Behavior-preserving refactor (architecture debt paydown). Added `session_frame.rs`
— a transport-neutral `FrameSink` seam plus WS/QUIC adapters. The session lifecycle
(`run_session_with_outbound` + `run_read_loop`) is now written once; QUIC routes
through it via a `FrameSink` sender adapter and a `Stream<Message>` receiver adapter
(`quic_message_stream`). Deleted the duplicate `run_quic_session_with_outbound` and
`run_quic_read_loop` (~390 lines); `ws_endpoint.rs` 3188 -> 2801 lines.

No protocol, wire-format, or cryptographic change — adapters translate frames in
memory only. Validation: `cargo test --features native-full -- --test-threads=1`
-> 378 passing (incl. rc3_btr_over_quic, rc3_quic_e2e, rc5_btr_over_ws,
wti5_btr_over_wt); `cargo fmt`/`clippy` clean; WS-only default build compiles (QUIC
seam is cfg-gated).

Known cosmetic follow-up: QUIC sessions now log under the shared loop's `[WS_*]`
tags (no behavior/wire/test impact); log-tag neutralization + the misnamed
`ws_endpoint.rs`/loop rename are deferred. WebTransport folds onto the same seam in
Phase 2.

## WT-BTR-RECEIVE-1 — BTR decrypt + IPC transfer events on WT receive — 2026-07-03

Recovered May-era working-tree progress (found uncommitted during the
Governance OS sweep, kept per PM direction). The WebTransport receive path now
initializes a BtrEngine when `bolt.transfer-ratchet-v1` is negotiated, decrypts
chunks via `decode_envelope_with_btr`/`decrypt_chunk_btr` with per-transfer
receive contexts and `end_transfer()` cleanup, and falls back to static NaCl
box when BTR is not negotiated. WT receive also emits
`transfer.started/progress/complete/error` IPC events (parity with WS/QUIC).

Validation: `cargo test --features native-full -- --test-threads=1` → 378
passed, 0 failed (incl. `wti5_btr_over_wt`); `cargo fmt --check` clean; clippy
no warnings. Automated-test-validated per `os/rules/validation-protocol.md`.

## LOCALBOLT-NATIVE-QUIT-TEARDOWN-1 — Parent-Death Watchdog (`bffbc02`) — 2026-04-26

When the native LocalBolt.app quits (Cmd+Q), normal termination hooks
(`deinit`, `willTerminateNotification`, `applicationWillTerminate`, `atexit`)
do not run — behavior consistent with `_exit`-style termination in the SwiftUI
lifecycle. The bundled bolt-daemon child process survived as an orphan
reparented to launchd (ppid=1).

### Fixed
- `src/main.rs` — ppid watchdog thread in `DaemonMode::WsEndpoint`: polls
  `libc::getppid()` every 1s, exits via `libc::_exit(0)` when parent dies.
  `_exit` is required because `std::process::exit` deadlocks on tokio atexit
  handlers when the stderr pipe to the dead parent is broken.
- Diagnostic log written to `{data_dir}/watchdog_exit.log` before exit.

### Added
- `Cargo.toml` — `libc = "0.2"` dependency for `getppid()` and `_exit()`.

### Rejected Approaches
- `NSApplication.willTerminateNotification` — does not fire in SwiftUI lifecycle apps.
- `NSApplicationDelegateAdaptor.applicationWillTerminate` — does not fire.
- `atexit()` — not called; consistent with `_exit`-style termination bypassing `exit()` handlers.
- FFI shell watchdog (spawn `/bin/sh` monitor) — could not be validated reliably when launched via Launch Services.

### Validation (Mac Studio)
- App PID gone after Cmd+Q
- Daemon PID gone within 2s (watchdog log confirms detection)
- Browser detects disconnect, resets to device discovery
- Zero orphan bolt-daemon processes

### Scope Note
WT disconnect changes (`wt_endpoint::request_disconnect`, IPC lifecycle events)
are separate work, unstaged/uncommitted, and not part of this fix.

### Commit
- `bffbc02` — `fix(daemon): exit ws endpoint when parent app dies`

## DEWEBRTC-2-DOCS — Documentation Reconciliation (daemon-v0.2.49, daemon-v0.2.50) — 2026-04-10

Complete documentation reconciliation following DEWEBRTC-2 removal of all
WebRTC runtime code. Two-pass approach: metadata first, then operational README.

### Pass 1: Metadata + Top-Level (daemon-v0.2.49)
- README.md: "Headless WebRTC transport" → current WS/WT/QUIC architecture overview
- Cargo.toml: package description updated
- docs/STATE.md: Default mode description, dependency table (datachannel/webrtc-sdp → bolt-btr/tokio-tungstenite/wtransport)
- docs/CHANGELOG.md: shipped binary description
- src/main.rs: removed orphaned "Re-export legacy WebRTC types" comment

### Pass 2: Operational README (daemon-v0.2.50)
- CLI Reference: WebRTC-era --role/--signal/--offer/--answer → current --mode/--ws-listen/--data-dir flags
- Removed stale sections: File Mode, Rendezvous Mode, Network Scope Policy, Browser Interop, Expected Output
- Added: WsEndpoint running guide, signal files table, simulate mode, test harness note
- Architecture tree: updated to 20+ current source files
- Tag convention: updated current tag

### Runtime Architecture Statement
Zero WebRTC runtime. WS default, WT optional, QUIC optional.
No runtime code was modified in either commit.

### Tags
- `daemon-v0.2.49-dewebrtc2-docs-reconcile` (`e092dcc`) — metadata + top-level
- `daemon-v0.2.50-dewebrtc2-readme-complete` (`c5b7ea8`) — operational README

## N-STREAM-TIMEOUT — Post-HELLO Deadline Decoupling (daemon-v0.2.45, daemon-v0.2.46) — 2026-03-16

Decoupled the post-HELLO session loop deadline from the signaling-phase timeout.
Sessions are now heartbeat-driven with no wall-clock deadline after connection.

### Fixed
- `src/rendezvous.rs` — `run_post_hello_loop()` deadline parameter changed from
  `Instant` to `Option<Instant>`. Production callers pass `None` (no deadline).
  Test callers pass `Some(bounded_deadline)` for deterministic tests.
- Eliminates the ~30s session drop caused by the signaling deadline leaking into
  the connected data exchange loop.

### Added
- 3 regression tests: `b6_no_deadline_runs_until_disconnect`,
  `b6_some_deadline_still_enforced`, `b6_no_deadline_survives_beyond_30s_window`
- `docs/NSTREAM_TIMEOUT_EVIDENCE.md` — root cause, code change, test matrix,
  live two-device operational proof (Mac Studio + MacBook Pro, 253s stable,
  3 reconnect cycles, 0 failures)

### Tags
- `daemon-v0.2.45-nstream-timeout-hardening` (`ed74bae`) — code fix + unit tests
- `daemon-v0.2.46-nstream-operational-proof` (`fcf7a85`) — live drill evidence

## EN3f — Transfer Lifecycle IPC Events (daemon-v0.2.44-en3f-transfer-ipc-events) — 2026-03-15

### Added
- Transfer lifecycle IPC events in rendezvous post-HELLO loop:
  `transfer.started`, `transfer.progress`, `transfer.completed`, `transfer.failed`

## EN3e — Session + Transfer IPC Events (daemon-v0.2.43-en3e-ipc-session-events) — 2026-03-15

### Added
- Session lifecycle IPC events: `session.connected`, `session.sas`,
  `session.disconnected`

## REL-ARCH1 — Multi-Arch Build/Package Matrix (daemon-v0.2.38-relarch1-multiarch-matrix) — 2026-03-09

Deterministic multi-architecture release workflow for bolt-daemon. Produces
platform archives with checksums for 5 targets, published to GitHub Releases.

### Added
- `.github/workflows/release.yml` (NEW) — multi-arch release workflow:
  - 5-target matrix: x86_64-apple-darwin, aarch64-apple-darwin,
    x86_64-pc-windows-msvc, x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu
  - Native build on macos-14/windows-latest/ubuntu-latest
  - Cross-compilation via native gcc toolchain for aarch64-unknown-linux-gnu
  - Windows: Strawberry Perl + NASM forced via PERL env var for OpenSSL vendored build
  - Per-target archive packaging (tar.gz for macOS/Linux, zip for Windows)
  - SHA256SUMS.txt consolidated checksum file
  - Inventory check: fail-closed if any required archive is missing
  - GitHub Release publishing via softprops/action-gh-release@v2
  - Dual trigger: tag push (`daemon-v*`) + `workflow_dispatch` manual rebuild
  - Validation gates per native row: fmt, clippy, test, smoke

### Fixed
- `.github/workflows/ci.yml` — added missing `bolt-core-sdk` checkout step.
  Path dependencies (`bolt-core`, `bolt-transfer-core`) require sibling checkout
  that was absent since T-STREAM-0 introduced the `bolt-transfer-core` dep.
- `src/rendezvous.rs` — pre-existing `cargo fmt` violation corrected
- `src/identity_store.rs` — Windows path separator fix in `resolve_path_uses_home` test

### Shipped Binaries (per archive)
- `bolt-daemon` — headless transport daemon
- `bolt-relay` — self-hosted relay server
- `bolt-ipc-client` excluded (dev harness, not user-facing)

### Evidence
- CI run 22845910794: all 5 targets green + publish success
- 362 tests pass (macOS/Linux), 178 pass (Windows — 177 lib + 1 fixed)
- `cargo fmt --check` clean (all platforms)
- `cargo clippy -- -D warnings` clean (all platforms)

### Residual
- Code signing / notarization: not implemented (follow-on)
- `aarch64-pc-windows-msvc`: deferred (no GA GitHub Actions runner)

### Files Changed
- `.github/workflows/release.yml` (NEW)
- `.github/workflows/ci.yml`
- `src/rendezvous.rs`
- `src/identity_store.rs`
- `docs/STATE.md`
- `docs/CHANGELOG.md`

**Tag:** `daemon-v0.2.38-relarch1-multiarch-matrix` (`ab56606`)

---

## T-STREAM-0 — Transfer Core Adapter (daemon-v0.2.36-tstream0-adapter) — 2026-03-08

Daemon now consumes `bolt-transfer-core` crate instead of inline state machines.
`src/transfer.rs` becomes a thin adapter/facade re-exporting from the core crate.

### Changed
- `src/transfer.rs` — replaced 1,188-line inline SM with thin adapter (47 lines):
  - Re-exports `ReceiveSession`, `SendSession`, `TransferState`, `TransferError`, etc.
  - Legacy type aliases (`TransferSession`, `SendState`) for backward compat
  - `Sha256Verifier` — daemon-specific `IntegrityVerifier` impl using `bolt_core::hash`
- `src/rendezvous.rs` — adapted to new `on_file_finish()` signature (verifier param)
  and `begin_send()` signature (caller-provided transfer_id and hash)
- `src/lib.rs` — added `Sha256Verifier` to test_support re-exports
- `Cargo.toml` — added `bolt-transfer-core` path dependency

### Evidence
- 362 tests pass (195 lib + 128 main + 15 relay + 13 n6b1 + 11 n6b2), 0 regressions
- `cargo clippy -- -D warnings` clean
- `scripts/check_no_panic.sh` PASS
- Zero duplicated SM logic (all state machines in bolt-transfer-core)

### Files Changed
- `Cargo.toml`
- `src/transfer.rs`
- `src/rendezvous.rs`
- `src/lib.rs`
- `docs/STATE.md`
- `docs/CHANGELOG.md`

**Tag:** `daemon-v0.2.36-tstream0-adapter`

---

## N6-B2 — Windows Named Pipe Transport (B-DEP-N2-3)

Resolves B-DEP-N2-3: transport abstraction supporting both Unix domain
sockets (existing) and Windows named pipes (new). Preserves locked N2
handshake semantics, single-client kick-on-reconnect, and fail-closed
behavior across both transports.

### Added
- `src/ipc/transport.rs` (NEW) — transport abstraction layer:
  - `IpcListener` enum (Unix / NamedPipe variants, `#[cfg]`-gated)
  - `IpcStream` enum with `Read`/`Write` for owned and `&` references
  - `is_windows_pipe_path()` — detects `\\.\pipe\` path format
  - `DEFAULT_IPC_PATH` — platform-dependent default IPC endpoint
  - `cleanup_ipc_endpoint()` — shutdown cleanup (removes socket on Unix)
  - `#[cfg(windows)] mod windows_pipe` — full Win32 named pipe impl:
    `NamedPipeListener::bind()` with SDDL current-user-only DACL,
    `NamedPipeStream` with `ReadFile`/`WriteFile`, `PeekNamedPipe`-based
    read timeout, handle duplication for `try_clone()`
- `windows-sys` dependency (cfg(windows) only) with Win32 features:
  `Win32_Foundation`, `Win32_Security`, `Win32_Security_Authorization`,
  `Win32_Storage_FileSystem`, `Win32_System_Pipes`, `Win32_System_Threading`
- 10 unit tests in `transport.rs` (path detection + Unix transport)
- 8 Unix transport unit tests (bind, accept, read/write, clone, timeout,
  cleanup, permissions, prepare_next)
- `tests/n6b2_windows_pipe.rs` — 11 integration tests:
  6 transport detection (all platforms), 2 default path, 3 Unix regression
  (N2 handshake ordering, kick-on-reconnect, incompatible version fail-closed)
- 3 Windows-only integration tests (cfg(windows) gated: bind, wouldblock,
  connection lifecycle)
- Public re-exports in `lib.rs`: `IPC_DEFAULT_PATH`,
  `ipc_transport_is_windows_pipe()`, `ipc_server_start()`

### Changed
- `src/ipc/server.rs` — refactored to use transport abstraction:
  replaced `UnixListener`/`UnixStream` with `IpcListener`/`IpcStream`,
  `listener_loop()` calls `listener.prepare_next()` after each client,
  `Drop` impl calls `transport::cleanup_ipc_endpoint()`
- `src/ipc/mod.rs` — added `pub mod transport`
- `src/lib.rs` — added `pub mod ipc` and thin public wrappers for
  integration test access
- `src/main.rs` — `ipc` module now comes from `lib.rs` via re-export
- `src/ipc/trust.rs` — added `Default` impl for `TrustStore` (clippy fix)

### Transport Architecture
- Enum dispatch (not trait objects) — zero dynamic dispatch overhead
- `IpcListener::bind()` detects path format, creates appropriate listener
- `IpcListener::prepare_next()` — `DisconnectNamedPipe` on Windows, no-op
  on Unix
- `IpcStream` implements `Read`/`Write` for both owned and `&` references
- Windows read timeout: `PeekNamedPipe` polling with 10ms sleep + deadline
- Windows security: SDDL `D:P(A;;GA;;;<SID>)` restricts pipe to current
  user only (0600-equivalent)

### Windows Security Model
- Named pipe created with explicit DACL via `ConvertStringSecurityDescriptorToSecurityDescriptorW`
- SID lookup: `OpenProcessToken` + `GetTokenInformation(TokenUser)` +
  `ConvertSidToStringSidW`
- SDDL format: `D:P(A;;GA;;;<current-user-SID>)` — Protected DACL,
  Generic All for current user only
- No inheritance, no other users, no SYSTEM access

### B1 Integration
- `is_windows_pipe_path()` integrates with `--socket-path` flag from N6-B1
- Pipe paths (`\\.\pipe\...`) route to `NamedPipeListener`
- Unix paths route to `UnixListener` (existing behavior preserved)

### Invariants
- No changes to N2 handshake semantics (version.handshake → version.status
  → daemon.status)
- No changes to single-client kick-on-reconnect policy
- No changes to message parsing, routing, envelope schema, or trust logic
- No new DcMessage variants, EnvelopeError variants, or canonical error codes

### Tests
- Default: 389 (was 360, +29 new)
- test-support: 458 + 3 ignored (was 440 + 3 ignored, +18 new)

**Tag:** `daemon-v0.2.33-n6b2-windows-pipe`

---

## N6-B1 — `--socket-path` and `--data-dir` CLI Flags (B-DEP-N1-1)

Resolves B-DEP-N1-1: daemon path configurability for platform-appropriate
filesystem locations. The app (localbolt-app) can now pass platform-correct
socket and data paths when spawning the daemon as a sidecar.

### Added
- `--socket-path <path>` CLI flag — overrides default IPC socket location
  (`/tmp/bolt-daemon.sock`). Used by app to place socket at
  platform-appropriate runtime path (e.g. `$XDG_RUNTIME_DIR`,
  `$TMPDIR`, `\\.\pipe\` on Windows).
- `--data-dir <path>` CLI flag — overrides default data directory. When
  set, identity key resolves to `<data-dir>/identity.key` and trust
  store to `<data-dir>/pins/trust.json`. Supersedes `BOLT_IDENTITY_PATH`
  env var and `default_trust_path()`.
- `resolve_identity_path_from_data_dir()` in `src/identity_store.rs`
- `trust_path_from_data_dir()` in `src/ipc/trust.rs`
- 13 integration tests in `tests/n6b1_path_flags.rs` covering CLI parse,
  path resolution, custom socket, stale cleanup, identity persistence,
  trust store structure, containment, and regression
- 6 unit tests in `src/main.rs` for CLI parse of new flags
- 4 unit tests in `src/identity_store.rs` and `src/ipc/trust.rs` for
  path resolution functions

### Changed
- `run_offerer_rendezvous()` now accepts `trust_path: &Path` parameter
  instead of calling `default_trust_path()` internally — both offerer
  and answerer trust paths now flow from `fn main()` resolution
- Default mode startup logs now include `socket_path` and `data_dir`
  values, and prints resolved `identity_path` and `trust_path`
- Startup log includes new fields for observability

### Data Dir Contract
- Identity key: `<data-dir>/identity.key`
- TOFU pin store: `<data-dir>/pins/trust.json`
- No config currently persisted by daemon (N/A)
- No writes outside `data-dir` for daemon-owned state

### Safe Defaults (flags omitted)
- Socket: `/tmp/bolt-daemon.sock` (unchanged)
- Identity: `$BOLT_IDENTITY_PATH` or `$HOME/.bolt/identity.key` (unchanged)
- Trust: `$HOME/.config/bolt-daemon/trust.json` (unchanged)

### N2 Wire Contract
- No changes to IPC message types, payloads, or handshake
- No changes to version compatibility rules
- `--socket-path` and `--data-dir` are daemon-side only (not in IPC)

---

## B-DEP-N2 — IPC Version Handshake + daemon.status in Default Mode

Implements B-DEP-N2-1 and B-DEP-N2-2 to unblock N-STREAM-1 N6 execution.
IPC clients must now send `version.handshake` as their first message after
connecting. Daemon replies with `version.status` (compatibility result),
then emits `daemon.status` if compatible. Strict enforcement from day one
— no grace mode. Fail-closed on incompatible, malformed, missing, or late
handshake.

### Added
- `VersionHandshakePayload` and `VersionStatusPayload` structs in
  `src/ipc/types.rs` — typed payloads for version contract messages
- `check_version_compatible()` in `src/ipc/server.rs` — strict
  `major.minor` match rule (patch may differ)
- Version handshake phase in `handle_client()` — synchronous blocking
  read of first message, validation, version.status response, then
  daemon.status emission before entering normal event/decision loop
- `version.handshake` and `version.status` added to `parse_ipc_line()`
  known message types
- `HANDSHAKE_TIMEOUT` (5 seconds) and `DAEMON_VERSION` constants
- IPC Version Handshake Contract section in `docs/DAEMON_CONTRACT.md`
- daemon.status Emission section in `docs/DAEMON_CONTRACT.md`
- Version handshake in `bolt-ipc-client` dev harness — sends
  `version.handshake` as first message after connecting
- 20 new tests: 5 payload type tests, 8 version compatibility tests,
  7 handshake integration tests (full Unix socket round-trip)

### Changed
- `handle_client()` now accepts `ui_connected: &Arc<Mutex<bool>>` and
  sets it only after successful handshake (was set unconditionally in
  `listener_loop` before)
- `listener_loop()` no longer sets `ui_connected = true` before calling
  `handle_client()` — handshake must complete first
- `daemon.status` is now emitted by the IPC server after successful
  handshake, replacing manual emission in `run_simulate()`
- `run_simulate()` no longer emits `daemon.status` manually (removed
  `DaemonStatusPayload` construction + `emit_event` call)
- Event ordering: `version.status` → `daemon.status` → normal events
  (pre-handshake events drained per existing stale event drain)

### Log Tokens
- `[IPC_VERSION_COMPATIBLE]` — handshake succeeded
- `[IPC_VERSION_INCOMPATIBLE]` — version mismatch, closing
- `[IPC_HANDSHAKE_FAIL]` — malformed/missing/wrong first message

### Invariants
- No new DcMessage variants
- No new EnvelopeError variants
- No new canonical error codes
- No protocol wire format changes
- No cryptographic changes
- Existing WebRTC/HELLO/envelope/transfer flows unchanged

### Tests
- Default: 338 (was 318, +20 new)
- test-support: 418 + 3 ignored (was 398 + 3 ignored, +20 new)

**Tag:** `daemon-v0.2.31-bdep-n2-ipc-unblock`

---

## D-E2E-B — Cross-Implementation Bidirectional E2E Transfer (a8cf108)

Cross-implementation bidirectional file transfer between Node.js offerer
(tests/ts-harness) and Rust daemon answerer via real bolt-rendezvous.
Proves full interop: signaling, HELLO handshake, capability negotiation,
and bidirectional transfer with SHA-256 hash verification in both
directions. Pattern A (4096 B) flows JS→daemon, Pattern B (6144 B)
flows daemon→JS.

### Added
- Node.js test harness (`tests/ts-harness/harness.mjs`) — full ESM
  implementation of Bolt protocol: WebSocket rendezvous signaling,
  WebRTC DataChannel via `node-datachannel`, NaCl box envelope v1 via
  `tweetnacl`, encrypted HELLO exchange, bidirectional file transfer
  with SHA-256 verification. CLI with deterministic payload input and
  expected hash/size validation.
- `tests/ts-harness/package.json` + `package-lock.json` — pinned deps:
  `node-datachannel@0.32.1`, `tweetnacl@1.0.3`, `ws@8.19.0`
- Test-only send trigger in `src/rendezvous.rs` (30 lines, all
  `#[cfg(feature = "test-support")]`) — reads `BOLT_TEST_SEND_PAYLOAD_PATH`
  env var after receiving a file and sends it back via SendSession
- `tests/d_e2e_bidirectional.rs` — two `#[ignore]` integration tests:
  happy-path bidirectional transfer + negative integrity mismatch
- Deterministic payloads: Pattern A = `((i+1)*31) & 0xFF` (4096 B),
  Pattern B = `((i+1)*37) & 0xFF` (6144 B)

### Invariants
- No new DcMessage variants
- No new EnvelopeError variants
- No new canonical error codes
- No protocol wire format changes
- No cryptographic changes
- Existing receive/send state machines (B3-P2, B3-P3) unchanged

### Tests
- Default: 318 (unchanged — new tests are #[ignore])
- test-support: 398 + 3 ignored (was 398 + 1 ignored, +2 ignored E2E)

**Tag:** `daemon-v0.2.30-d-e2e-b-cross-impl`

---

## B3-P3 — Sender-Side Transfer MVP (4fd55e3)

Sender-side transfer state machine with cursor-driven chunk streaming.
Daemon can now build and send FileOffer (with SHA-256 hash when
bolt.file-hash negotiated), wait for FileAccept, stream FileChunk
messages deterministically, and send FileFinish. Handles Cancel from
receiver. Separate SendSession struct independent from receive-side
TransferSession.

### Added
- `SendSession` struct in `src/transfer.rs` — outbound transfer state
  machine (Idle → OfferSent → Sending → Completed/Cancelled)
- `SendState`, `SendOffer`, `SendChunk` types for send-side metadata
- `begin_send()` — computes metadata, generates transfer_id, optional
  SHA-256 hash via `bolt_core::hash::sha256_hex`
- `on_accept()` — transitions OfferSent → Sending on matching transfer_id
- `on_cancel()` — transitions OfferSent/Sending → Cancelled
- `next_chunk()` — cursor-driven, returns one chunk at a time
  (DEFAULT_CHUNK_SIZE = 16,384 bytes), returns None when exhausted
- `finish()` — validates all chunks yielded, transitions Sending → Completed
- Loop-level FileAccept/Cancel interception in `run_post_hello_loop`:
  drives send-side SM when active, absorbed gracefully when idle
- FileAccept and Cancel carved out from `route_inner_message` to `Ok(None)`
  (previously INVALID_STATE disconnect)
- Pause and Resume remain INVALID_STATE in `route_inner_message`
- test_support re-exports: SendSession, SendState, SendOffer, SendChunk
- 10 unit tests (send lifecycle, hash/no-hash, cancel, wrong ID, chunk
  correctness), 3 loop integration tests (FileAccept/Cancel absorption,
  Pause disconnect), 3 envelope routing tests (net +3 from 1 replaced)

### Invariants
- No new DcMessage variants
- No new EnvelopeError variants
- No new canonical error codes
- dc_messages.rs unchanged (READ-ONLY)
- run_post_hello_loop signature unchanged
- No disk IO, no async, no new dependencies
- Existing receive-side TransferSession unchanged

### Tests
- Default: 318 (was 302, +16)
- test-support: 398 + 1 ignored (was 382 + 1 ignored, +16)
- Delta: +10 unit (transfer.rs), +3 loop (rendezvous.rs), +3 net envelope (envelope.rs)

**Tag:** `daemon-v0.2.29-b3-transfer-sm-p3-sender`

---

## P1 — Inbound Error Validation Hardening (8c45819)

Strict structural + registry validation for inbound `{type:"error"}`
messages in the post-HELLO DataChannel path. Unknown or malformed error
codes from remote peers are now treated as `PROTOCOL_VIOLATION` with
disconnect, rather than being misclassified as `UNKNOWN_MESSAGE_TYPE`.

### Added
- `CANONICAL_ERROR_CODES` constant — 8 wire codes from Appendix A registry
- `validate_inbound_error()` — single validator helper for inbound errors:
  validates `code` exists + is string + is in registry; validates `message`
  is string if present
- P1 intercept in `route_inner_message()` — pre-parses inner JSON to
  intercept `type:"error"` before DcMessage serde dispatch
- `"error"` added to `KNOWN_TYPES` in dc_messages.rs (defense-in-depth)
- 5 new tests: known code accepted, unknown code rejected, missing code
  rejected, non-string code rejected, non-string message rejected

### Invariants
- All inbound error validation routes through `validate_inbound_error()`
- No envelope decode logic changed
- No pre-HELLO plaintext handling changed
- All existing H5 downgrade tests remain green

### Tests
- 276 total with test-support (60 lib + 146 main + 15 relay + 5 vectors + 50 H5)
- Delta: +5 (from 271)

**Tag:** `daemon-v0.2.12-p1-inbound-error-validation`

---

## I5 — Interop Error Framing Fix (600fef4)

Post-envelope error framing divergence: error messages sent before
disconnect were plaintext even after envelope-v1 negotiation. Added
`build_error_payload()` helper that wraps errors in profile-envelope
when session has envelope-v1 negotiated, falls back to plaintext for
pre-HELLO or no-capability sessions. All 4 error send sites in
rendezvous.rs updated.

**Tag:** `daemon-v0.2.11-interop-error-framing`

---

## H6 — CI Enforcement (398a63d)

Clippy -W→-D warnings, test-support feature gate, panic checker script.

**Tag:** `daemon-v0.2.9-h6-ci-enforcement`

---

## H3.1 — Hermetic Vector Vendoring (e6c8851)

Vendor H3 golden vectors into repo for hermetic tests.

**Tag:** `daemon-v0.2.8-h3.1-vectors-hermetic`

---

## H5 — Downgrade Resistance & Enforcement Validation

Align daemon wire error codes with PROTOCOL_ENFORCEMENT.md Appendix A
registry (14 codes). Prove envelope-required mode cannot be bypassed,
WebHelloV1 cannot be downgraded, and fail-closed state progression holds.

Audit Item: R7 — Error Code Registry Alignment.

### Added
- `HelloError` enum in `web_hello.rs` — typed HELLO-phase error codes:
  HELLO_PARSE_ERROR, HELLO_DECRYPT_FAIL, HELLO_SCHEMA_ERROR, KEY_MISMATCH,
  DUPLICATE_HELLO, PROTOCOL_VIOLATION (downgrade attempt)
- `parse_hello_typed()` function — returns `Result<WebHelloInner, HelloError>`
  with typed error codes per Appendix A
- `DcParseError` enum in `dc_messages.rs` — distinguishes `UnknownType`
  (UNKNOWN_MESSAGE_TYPE) from `InvalidMessage` (INVALID_MESSAGE) and `NotUtf8`
- `EnvelopeError::EnvelopeRequired` — plaintext frame in envelope-required session
- `EnvelopeError::UnknownMessageType` — unrecognized inner message type field
- `EnvelopeError::InvalidState` — message in unexpected session state
- `EnvelopeError::ProtocolViolation` — catch-all for violations not covered by specific codes
- `tests/h5_downgrade_validation.rs` — 50 integration tests across 6 sections:
  envelope enforcement, downgrade guard, error code strictness, state machine
  integrity, downgrade resistance, legacy mode boundary

### Changed
- `EnvelopeError` — removed `NotEnvelope` (replaced by `EnvelopeRequired`),
  removed `Protocol(String)` (split into `InvalidMessage`, `UnknownMessageType`,
  `InvalidState`, `ProtocolViolation`)
- `decode_envelope()` — non-envelope frame now returns `EnvelopeRequired`
  (when envelope negotiated) or `InvalidState` (when not negotiated)
- `route_inner_message()` — maps `DcParseError::UnknownType` to
  `EnvelopeError::UnknownMessageType`, other parse errors to `InvalidMessage`
- `parse_dc_message()` — returns `Result<DcMessage, DcParseError>` (was `Result<DcMessage, String>`)
  with two-phase parsing: extract type field, check against known types, then full parse
- `parse_hello_message()` — delegates to `parse_hello_typed()` for typed error handling
- `HelloState` — visibility widened from `pub(crate)` to `pub` for test-support re-export
- `lib.rs` test_support — expanded exports: EnvelopeError, HelloError, HelloState,
  DcMessage, DcParseError, encode/decode helpers

### Wire Code Alignment
- 13 of 14 Appendix A codes now emitted by daemon
- LIMIT_EXCEEDED deferred (no daemon rate-limit/size-cap infrastructure)

### Tests
- 262 total (51 lib + 146 main + 15 relay + 50 H5 integration)

**Tag:** `daemon-v0.2.7-h5-downgrade-validation`

---

## H4 — Panic Surface Elimination (678c808)

Eliminate all unwrap/expect/panic from production code.

**Tag:** `daemon-v0.2.6-h4-panic-elimination`

---


## H3 — Golden Vector Integration Tests (3751118)

Add HELLO-open and envelope-open golden vector tests consuming shared
vector files from bolt-core-sdk. Feature-gated behind `test-support`
to avoid exposing test internals in production builds.

### Added
- `tests/` golden vector tests for HELLO-open and envelope-open operations
  using shared vector files from bolt-core-sdk
- `test-support` cargo feature gating test internals (pub(crate) → pub)

### Changed
- `Cargo.toml` — `test-support` feature added
- Test internals in `web_hello.rs` and `envelope.rs` conditionally public

### Tests
- 215+ total (with `--features test-support`)

**Tag:** `daemon-v0.2.5-h3-golden-vectors`
**Commit:** `3751118`
**Branch:** `feature/h3-golden-vectors` → `feature/h4-panic-elimination` (not yet merged to main)

---

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
