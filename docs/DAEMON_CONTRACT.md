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
