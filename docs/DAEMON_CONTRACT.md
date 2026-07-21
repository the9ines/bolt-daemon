# Bolt Daemon — Operator Contract

Normative surface contract for bolt-daemon. Downstream tooling, CI scripts,
and operator procedures MAY depend on the behavior documented here. Changes
to this surface MUST be versioned and documented in `docs/CHANGELOG.md`.
`scripts/contract_smoke.sh` verifies the checkable parts of this contract.

Keywords: RFC 2119 (MUST, MUST NOT, REQUIRED, SHALL, SHOULD, MAY).

## Runtime Modes

bolt-daemon has two runtime modes, selected via `--mode`:

| Mode | Value | Description |
|------|-------|-------------|
| WsEndpoint | `ws-endpoint` (default) | WS server for browser/native↔desktop direct transport. Optional WT and QUIC endpoints alongside when compiled in. Runs until killed. |
| Simulate | `simulate` | IPC-only harness: emits one simulated pairing/transfer event, awaits a UI decision, exits. |

Any other `--mode` value MUST exit 1. The pre-DEWEBRTC-2 WebRTC modes no
longer exist.

## CLI Flags

### Common

| Flag | Default | Notes |
|------|---------|-------|
| `--mode` | `ws-endpoint` | `ws-endpoint` or `simulate`. Invalid value → exit 1. |
| `--socket-path` | `/tmp/bolt-daemon.sock` | IPC Unix socket path (Windows: named pipe). |
| `--data-dir` | identity `~/.bolt`, trust `~/.config/bolt-daemon` | Unified data directory. When set: identity at `<dir>/identity.key`, trust at `<dir>/pins/trust.json`, signal files and endpoint metadata in `<dir>`. |
| `--pairing-policy` | `ask` | `ask`, `allow`, or `deny`. Invalid value → exit 1. |
| `--phase-timeout-secs` | `30` | Per-phase timeout in seconds. Unparseable values are ignored and the default applies (the flag is not validated). |

### WsEndpoint Mode

| Flag | Default | Notes |
|------|---------|-------|
| `--ws-listen` | — | REQUIRED. `ip:port` (e.g. `127.0.0.1:9557`). Missing → exit 1. Unparseable address → exit 1. |

WebTransport flags (`--wt-listen`, `--wt-cert`, `--wt-key`, `--no-wt`) exist
only in builds with the `transport-webtransport` feature. QUIC
(`transport-quic` feature) adds no flags: the QUIC endpoint starts on the
port adjacent to the WS port and advertises itself via `quic_info.json` in
the data dir.

### Simulate Mode

| Flag | Values | Notes |
|------|--------|-------|
| `--simulate-event` | `pairing-request`, `incoming-transfer` | REQUIRED in simulate mode. Missing or invalid → exit 1. |

### Legacy Flags (Retired)

`--role`, `--signal`, `--offer`, `--answer`, and `--interop*` belonged to the
pre-DEWEBRTC-2 WebRTC architecture. Passing any of them MUST exit 1 (stderr:
`Legacy flag '<flag>' requires --features legacy-webrtc`; no such feature is
shipped — these flags are permanently retired).

### Unknown Flags

Unknown non-legacy flags are ignored (the parser is tolerant; a following
non-flag token is consumed as the ignored flag's value). There is no `--help`
flag. Tooling MUST NOT rely on unknown flags being rejected.

## Startup Sequence (WsEndpoint)

1. Startup banner on stderr: `[bolt-daemon] mode=... pairing=... timeout=...s socket_path=... data_dir=...`
2. Parent-death watchdog starts when the daemon has a real parent process
   (sidecar deployment): if the parent exits, the daemon exits 0.
3. IPC server binds `--socket-path`. Bind failure is a WARNING, not fatal.
4. Identity keypair is loaded or created (`identity.key`, owner-only).
5. `--ws-listen` is validated (missing/invalid → FATAL, exit 1).
6. Ephemeral WT certificate is generated; when a data dir is set, WT metadata
   is written to `wt_info.json` (WT port = WS port + 1).
7. WS endpoint serves until the process is killed.

The IPC socket is bound and the identity file may be created BEFORE
`--ws-listen` validation. Isolated runs (tests, smoke checks) SHOULD pass
`--socket-path` and `--data-dir` pointing at a scratch directory.

## Exit Codes

| Mode | Code | Meaning |
|------|------|---------|
| ws-endpoint | runs | Serves until killed; exits 0 when the parent process dies (watchdog). |
| ws-endpoint | 1 | Fatal startup error: missing/invalid `--ws-listen`, identity failure, runtime failure. |
| simulate | 0 | Decision received from the connected UI client. |
| simulate | 1 | Fail-closed: no IPC client within 10s, no decision within 30s, or internal error. |

## Log Tokens

Stable stderr substrings that downstream tooling MAY match. The daemon MUST
NOT change these without a `docs/CHANGELOG.md` entry.

| Token | Context | Meaning |
|-------|---------|---------|
| `[bolt-daemon] mode=` | Startup | Banner; mode/pairing/timeout/paths echo |
| `[bolt-daemon] FATAL:` | Any | Fatal error, exit 1 follows |
| `[bolt-daemon] parent-death watchdog active` | Sidecar | Watchdog armed against parent PID |
| `[IPC] listening on` | Startup | IPC server bound |
| `[WS_ENDPOINT] starting on` | Startup | WS endpoint about to serve |
| `[WT_CERT] hash=` | Startup | Ephemeral WT certificate generated |
| `[WT_INFO] wrote` | Startup | WT metadata written to data dir |
| `[QUIC_INFO] wrote` | Startup (QUIC builds) | QUIC metadata written to data dir |
| `[simulate]` | Simulate | All simulate-mode progress lines |
| `[IPC_VERSION_COMPATIBLE]` | IPC | Version handshake succeeded |
| `[IPC_VERSION_INCOMPATIBLE]` | IPC | Version mismatch — closing |
| `[IPC_HANDSHAKE_FAIL]` | IPC | Handshake failed (malformed/missing/wrong type) — fail-closed |

## Signal Files

The native shell drives the daemon by writing signal files into the data
dir. The daemon polls at 250–500ms intervals.

| Signal File | Purpose |
|-------------|---------|
| `send_file.signal` | File path → daemon sends it to the connected peer |
| `connect_remote.signal` | Legacy WS URL or structured JSON (`wsUrl`, optional `quicAddr`/`quicCertHash`) → daemon connects outbound |
| `disconnect_session.signal` | Touch → disconnect the active session |
| `transfer_pause.signal` | Touch → pause the active transfer |
| `transfer_resume.signal` | Touch → resume a paused transfer |

## IPC Version Handshake

The IPC socket enforces a strict version handshake as the first message
exchange after client connection. No grace mode exists. Full message schemas
live in [docs/IPC_CONTRACT.md](IPC_CONTRACT.md).

1. Client MUST send `version.handshake` (kind: `decision`) first, carrying
   `app_version` (`major.minor.patch`).
2. Daemon replies `version.status` with `daemon_version` and `compatible`.
3. Compatible (`major.minor` equal, patch free): daemon emits `daemon.status`,
   then enters the normal event/decision loop.
4. Incompatible, malformed, wrong-type, or missing handshake: `version.status`
   with `compatible: false`, then disconnect (fail-closed). Handshake timeout:
   disconnect without response.

`daemon.status` (`{"connected_peers": <u32>, "ui_connected": <bool>, "version": "<string>"}`)
is emitted in both runtime modes immediately after a successful handshake.
The app SHOULD NOT enable transfer UI until `daemon.status` is received.

## Data Plane

- **Transports:** WS (default feature), WebTransport and QUIC optional
  feature-gated endpoints. Zero WebRTC at runtime.
- **Session protection:** NaCl-box encrypted HELLO with capability
  negotiation, Profile Envelope v1 framing post-HELLO, BTR-encrypted
  transfers when negotiated. Protocol violations fail closed.
- **Discovery/signaling** is an app-layer concern. The daemon takes direct
  connect instructions (`connect_remote.signal`) and serves inbound
  connections; it does not talk to a rendezvous server at runtime.
- **Trust:** TOFU identity pinning plus pairing approval via the trust store
  and `--pairing-policy`. Approval gates sessions; it is authorization only,
  not verified-device identity.
