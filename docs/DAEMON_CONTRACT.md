# Bolt Daemon — Operator Contract

Normative surface contract for bolt-daemon. Downstream tooling, CI scripts,
and operator procedures MAY depend on the behavior documented here. Changes
to this surface MUST be versioned and documented in `docs/CHANGELOG.md`.

Keywords: RFC 2119 (MUST, MUST NOT, REQUIRED, SHALL, SHOULD, MAY).

## Signal Modes

bolt-daemon supports two signaling modes, selected via `--signal`:

| Mode | Value | Description |
|------|-------|-------------|
| File | `file` (default) | Exchange offer/answer via JSON files on disk |
| Rendezvous | `rendezvous` | Exchange offer/answer via bolt-rendezvous WebSocket server |

The mode MUST be selected at startup. There is no runtime fallback between modes.

## CLI Flags

### Required

| Flag | Values | Notes |
|------|--------|-------|
| `--role` | `offerer`, `answerer` | REQUIRED. No default. Missing → exit 1. |

### File Mode Flags

| Flag | Default | Notes |
|------|---------|-------|
| `--offer` | `/tmp/bolt-spike/offer.json` | Path or `-` for stdin/stdout |
| `--answer` | `/tmp/bolt-spike/answer.json` | Path or `-` for stdin/stdout |

### Rendezvous Mode Flags

| Flag | Default | Required | Notes |
|------|---------|----------|-------|
| `--signal` | `file` | No | Set to `rendezvous` to enable rendezvous mode |
| `--rendezvous-url` | `ws://127.0.0.1:3001` | No | WebSocket URL of bolt-rendezvous server |
| `--room` | — | YES | Room discriminator. Missing → exit 1. |
| `--session` | — | YES | Session discriminator. Missing → exit 1. |
| `--to` | — | Offerer only | Target peer code. Missing for offerer → exit 1. |
| `--expect-peer` | — | Answerer only | Expected peer code. Missing for answerer → exit 1. |
| `--peer-id` | auto-generated | No | 8-char hex if omitted |

### Common Flags

| Flag | Default | Notes |
|------|---------|-------|
| `--phase-timeout-secs` | `30` | Positive integer. Controls all phase deadlines. |
| `--network-scope` | `lan` | Values: `lan`, `overlay`, `global` |
| `--socket-path` | `/tmp/bolt-daemon.sock` | IPC Unix socket path. Non-empty string required. |
| `--data-dir` | `~/.bolt` (identity), `~/.config/bolt-daemon` (trust) | Unified data directory. When set: identity at `<path>/identity.key`, trust at `<path>/pins/trust.json`. |

### Fail-Closed Rules (Rendezvous)

When `--signal rendezvous` is set, the following MUST be present or the
daemon MUST exit 1 before any network activity:

- `--room` REQUIRED
- `--session` REQUIRED
- `--to` REQUIRED (offerer only)
- `--expect-peer` REQUIRED (answerer only)

Unknown flags MUST cause exit 1. There is no `--help` flag.

Running with no arguments prints a usage line and exits 1:
```
Usage: bolt-daemon --role offerer|answerer [--signal file|rendezvous] [options]
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success. Payload exchange completed. |
| 1 | Fatal error. Includes: arg validation failure, server unreachable, timeout, scope/version/peer mismatch. |

The daemon MUST NOT exit 0 unless the full payload exchange succeeded.

## Log Tokens

Stable substrings that downstream tooling MAY match. These tokens appear on
stderr. The daemon MUST NOT change these strings without a version bump.

| Token | Context | Meaning |
|-------|---------|---------|
| `[bolt-daemon] exit 0` | Both modes | Clean exit after successful exchange |
| `[bolt-daemon] FATAL:` | Both modes | Fatal error, exit 1 follows |
| `SUCCESS` | Both modes | Payload verified (offerer: `received matching payload`, answerer: `echoed matching payload`) |
| `DataChannel open` | Both modes | WebRTC DataChannel established |
| `phase timeout expired` | Both modes | Deadline exceeded for a signaling/data phase |
| `[rendezvous] hello/ack complete` | Rendezvous | Hello/ack handshake succeeded |
| `[rendezvous] ignoring signal` | Rendezvous | Signal filtered (wrong session, room, peer, or msg_type) |
| `[rendezvous] hello retry:` | Rendezvous | Offerer retrying hello (target peer not yet registered) |
| `unsupported payload_version` | Rendezvous | Remote peer sent incompatible payload version (fatal) |
| `network_scope mismatch` | Rendezvous | Hello declared a scope that does not match local (fatal) |
| `ICE candidate accepted` | Both modes | Candidate passed scope filter |
| `ICE candidate REJECTED` | Both modes | Candidate blocked by scope filter |

## Data Plane vs Control Plane

bolt-daemon's architecture separates control plane from data plane:

- **Control plane (signaling):** bolt-rendezvous relays opaque signaling
  payloads (SDP, ICE candidates, hello/ack) between peers. It is coordination
  infrastructure only. No file payload bytes transit the rendezvous server.
- **Data plane (payload):** File payload bytes flow directly between peers
  over a WebRTC DataChannel (P2P). In the default architecture, no payload
  bytes traverse any server operated by us.

This separation is by design. The rendezvous server is untrusted and sees
only opaque signaling metadata. All encryption and payload integrity are
enforced at the peer level by the Bolt protocol layer.

## IPC Version Handshake Contract (B-DEP-N2-2)

The IPC Unix socket enforces a strict version handshake as the first
message exchange after client connection. No grace mode exists.

### Sequence

1. Client connects to Unix socket.
2. Client MUST send `version.handshake` (kind: `decision`) as its first message:
   ```json
   {"id":"...","kind":"decision","type":"version.handshake","ts_ms":<u64>,"payload":{"app_version":"<major.minor.patch>"}}
   ```
3. Daemon replies with `version.status` (kind: `event`):
   ```json
   {"id":"...","kind":"event","type":"version.status","ts_ms":<u64>,"payload":{"daemon_version":"<major.minor.patch>","compatible":<bool>}}
   ```
4. If `compatible: true`: daemon emits `daemon.status` event, then enters
   normal event/decision loop.
5. If `compatible: false`: daemon closes the connection immediately after
   sending `version.status`.

### Compatibility Rule

`major.minor` of app version MUST equal `major.minor` of daemon version.
Patch version MAY differ. Malformed versions are treated as incompatible.

### Fail-Closed Semantics

| Condition | Behavior |
|-----------|----------|
| First message is not `version.handshake` | `version.status` with `compatible: false`, then disconnect |
| First message is malformed JSON | `version.status` with `compatible: false`, then disconnect |
| `app_version` field missing from payload | `version.status` with `compatible: false`, then disconnect |
| Version incompatible (major.minor mismatch) | `version.status` with `compatible: false`, then disconnect |
| Handshake timeout (5 seconds) | Disconnect without response |

### Event Ordering Lock

- Before handshake completion: daemon MUST NOT emit any events except
  `version.status`.
- After compatible handshake: `daemon.status` is emitted immediately,
  followed by normal event flow.
- `ui_connected` flag is only set to `true` after successful handshake
  and `daemon.status` emission.

### Log Tokens

| Token | Meaning |
|-------|---------|
| `[IPC_VERSION_COMPATIBLE]` | Handshake succeeded, versions match |
| `[IPC_VERSION_INCOMPATIBLE]` | Handshake failed, version mismatch — closing |
| `[IPC_HANDSHAKE_FAIL]` | Handshake failed (malformed, missing, wrong type) — fail-closed |

## daemon.status Emission (B-DEP-N2-1)

The `daemon.status` event is emitted in **all daemon modes** (default,
smoke, simulate) immediately after a successful IPC version handshake.

Payload schema:
```json
{"connected_peers": <u32>, "ui_connected": <bool>, "version": "<string>"}
```

This event signals daemon readiness to the app. The app SHOULD NOT enable
transfer UI until `daemon.status` is received.

## Compatibility Contract

- **payload_version**: MUST be `1`. Any other value is fatal (exit 1).
- **session**: REQUIRED in rendezvous mode. Session mismatch between peers is
  non-fatal (signals silently ignored). Missing `--session` flag is fatal.
- **Peer targeting**: Deterministic. Offerer MUST specify `--to`, answerer MUST
  specify `--expect-peer`. Signals from unexpected peers are ignored.
- **Rendezvous server**: Untrusted relay. Does not inspect payloads. Version
  and session gating are enforced by the daemon, not the server.
- **Version pinning**: See [docs/COMPATIBILITY.md](COMPATIBILITY.md) for the
  daemon-to-rendezvous tag pairing matrix.

## Network Scope Policy

| Scope | Accepts |
|-------|---------|
| `lan` | Private (RFC 1918), link-local, loopback. Rejects public, CGNAT, mDNS. |
| `overlay` | Everything `lan` accepts, plus CGNAT `100.64.0.0/10`. Rejects public, mDNS. |
| `global` | All valid IPs (private + public + CGNAT). Rejects mDNS, malformed. |

Scope is enforced at two points:
1. Outbound: `on_candidate` callback filters local ICE candidates.
2. Inbound: `apply_remote_signal` filters remote ICE candidates.

Both peers MUST use the same `--network-scope`. Mismatch is detected during
hello/ack (rendezvous mode) and causes exit 1.
