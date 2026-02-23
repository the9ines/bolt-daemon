# Two-Machine Smoke Test (Rendezvous Signaling)

Operator guide for running bolt-daemon's smoke validation mode (`--mode smoke`)
between two physical machines using rendezvous signaling via bolt-rendezvous.

Smoke mode transfers a deterministic payload over the DataChannel, verifies
SHA-256 integrity on both sides, and reports latency/throughput with structured
exit codes. This replaces the default HELLO_PAYLOAD exchange with a configurable,
integrity-verified transfer.

## Prerequisites

**Software (both machines):**

- Rust stable toolchain (1.70+)
- CMake (for vendored libdatachannel build)
- Xcode Command Line Tools (macOS) or build-essential (Linux)

**Network:**

- Connectivity between machines (same LAN, Tailscale, or public)
- bolt-rendezvous server running and reachable from both machines

**Code:**

- bolt-daemon at `daemon-v0.1.3-smoke-rendezvous` or later (Phase 4L+ merged)
- bolt-rendezvous at `rendezvous-v0.0.3-ci` or later

Without Phase 4L+, `--mode smoke --signal rendezvous` exits 1 with
"not yet supported."

## Required Flags

Both peers must agree on all shared parameters. Mismatch causes a fatal
exit or silent ignore.

| Flag | Offerer | Answerer | Must Match |
|------|---------|----------|------------|
| `--role` | `offerer` | `answerer` | N/A |
| `--signal` | `rendezvous` | `rendezvous` | yes |
| `--mode` | `smoke` | `smoke` | yes |
| `--rendezvous-url` | `ws://IP:3001` | `ws://IP:3001` | yes |
| `--room` | same string | same string | yes |
| `--session` | same string | same string | yes |
| `--network-scope` | `lan\|overlay\|global` | same value | yes (fatal on mismatch) |
| `--bytes` | same value | same value | yes |
| `--peer-id` | unique ID | unique ID | distinct |
| `--to` | answerer's peer-id | N/A | N/A |
| `--expect-peer` | N/A | offerer's peer-id | N/A |
| `--phase-timeout-secs` | per-peer | per-peer | independent |
| `--repeat` | per-peer | per-peer | must match |
| `--json` | optional | optional | independent |

## Recommended Defaults

| Parameter | Default | Notes |
|-----------|---------|-------|
| `--bytes` | 1048576 (1 MiB) | Counter-based deterministic payload |
| `--repeat` | 1 | Number of send/verify cycles |
| `--phase-timeout-secs` | 30 | Use 300 for manual two-machine tests |
| `--room` | `test` | Any string, must match |
| `--json` | off | Add for machine-parseable output |

## Exit Codes

| Code | Meaning | Both peers must exit 0 for PASS |
|------|---------|---------------------------------|
| 0 | Success — SHA-256 verified, transfer complete | |
| 1 | Signaling failure (rendezvous unreachable, registration failed) | |
| 2 | DataChannel failure (open timeout, send error) | |
| 3 | Integrity mismatch (SHA-256 of received payload differs from expected) | |
| 4 | Timeout (transfer or ack timed out) | |

## Quick Start

### 1. Start the rendezvous server (Machine A)

```bash
cd ~/Desktop/the9ines.com/bolt-ecosystem/bolt-rendezvous
cargo run
```

Leave running. Open a second terminal.

### 2. Start answerer (Machine A, second terminal)

Replace `MACHINE_A_IP` with Machine A's actual IP (LAN: `192.168.x.x`,
overlay: `100.x.y.z`, global: public IP).

```bash
cd ~/Desktop/the9ines.com/bolt-ecosystem/bolt-daemon
cargo run -- --role answerer --signal rendezvous --mode smoke \
  --rendezvous-url ws://MACHINE_A_IP:3001 \
  --room test --session smoke-lan-001 \
  --peer-id bob --expect-peer alice \
  --network-scope lan --bytes 1048576 --phase-timeout-secs 300
```

### 3. Start offerer (Machine B)

```bash
cd bolt-daemon
cargo run -- --role offerer --signal rendezvous --mode smoke \
  --rendezvous-url ws://MACHINE_A_IP:3001 \
  --room test --session smoke-lan-001 \
  --peer-id alice --to bob \
  --network-scope lan --bytes 1048576 --phase-timeout-secs 300
```

### 4. Verify

Both peers should print a smoke report and exit 0:

```
[smoke] handshake .......... OK
[smoke] data channel ....... OK
[smoke] transferred ........ 1048576 bytes
[smoke] sha256 ............. OK (2c26b46b04e10182...)
[smoke] latency ............ 42 ms
[smoke] throughput ......... 23.8 MB/s
[smoke] result ............. PASS
```

With `--json`:

```json
{
  "mode": "smoke",
  "handshake": true,
  "data_channel": true,
  "bytes": 1048576,
  "sha256_expected": "2c26b46b04e10182...",
  "sha256_received": "2c26b46b04e10182...",
  "sha256_match": true,
  "latency_ms": 42,
  "throughput_mbps": 23.8,
  "repeat": 1,
  "result": "PASS",
  "error": null
}
```

## Command Generator

Use the helper script to generate copy/paste commands for any configuration:

```bash
bash scripts/print_two_machine_smoke_commands.sh \
  --network-scope lan \
  --session smoke-lan-001 \
  --rendezvous-url ws://192.168.1.100:3001 \
  --bytes 1048576
```

See `scripts/print_two_machine_smoke_commands.sh --help` for all options.

## Local Validation (Same Machine)

For same-machine testing before a two-machine run:

```bash
bash scripts/e2e_rendezvous_smoke_local.sh
```

This starts bolt-rendezvous + two daemon peers on localhost and verifies
both exit 0 with SHA-256 integrity.

## Network Scope Reference

| Scope | ICE candidates accepted | Use case |
|-------|------------------------|----------|
| `lan` | Private IPs only (192.168.x, 10.x, 172.16-31.x, link-local) | Same LAN |
| `overlay` | Private + CGNAT 100.64/10 (Tailscale, ZeroTier) | VPN mesh |
| `global` | All valid IPs including public | Direct public connectivity |

Global scope requires direct reachability (no STUN/TURN configured).

## Session Naming Convention

Use descriptive, unique session strings to prevent cross-talk:

```
smoke-<scope>-<NNN>
```

Examples: `smoke-lan-001`, `smoke-overlay-002`, `smoke-global-005`

Increment the suffix for each test run. Peers with different `--session`
values silently ignore each other's signals (non-fatal, continues waiting).

## Default Mode (Non-Smoke)

The daemon also supports default mode (`--mode default`, the default) which
exchanges a 13-byte `bolt-hello-v1` payload without SHA-256 verification.
For default mode two-machine testing, use:

- `scripts/print_two_machine_commands.sh` (command generator)
- `scripts/e2e_rendezvous_local.sh` (local E2E)

Default mode has a single exit code: 0 (success) or 1 (any failure).

## Troubleshooting

### macOS Firewall Blocks Rebuilt Binary

macOS asks "allow incoming connections?" each time you rebuild. If the dialog
was dismissed or denied, the binary is silently blocked.

```bash
cargo build
# macOS will prompt again — click Allow
```

Or temporarily disable the firewall in System Settings > Network > Firewall.

### "peer not found" During Hello

The offerer retries hello automatically (100ms backoff, up to 1s) if the
answerer hasn't registered yet. Start the answerer first. If it persists:

- Verify both peers use the same `--rendezvous-url`
- Verify `--peer-id` on one machine matches `--to` or `--expect-peer` on the other
- Check that the rendezvous server is running and reachable

### Signals Ignored (Session Mismatch)

Symptom: peers hang waiting for signals. Logs show:
```
[rendezvous] ignoring signal from 'X': session 'Y' != 'Z'
```

Fix: ensure both peers use the exact same `--session` value.

### Fatal Exit (Scope Mismatch)

Symptom: answerer exits 1 immediately after receiving hello:
```
network_scope mismatch: remote='overlay' local='lan'
```

Fix: both peers must use the same `--network-scope` value.

### Exit Code 3 (Integrity Mismatch)

Symptom: one peer reports `sha256_match: false` and exits 3.

This indicates data corruption during transfer. Check:
- Both peers use the same `--bytes` value
- No proxy or middlebox is modifying WebRTC traffic
- Try a smaller `--bytes` value to isolate

### Exit Code 4 (Timeout)

Symptom: peer exits 4 after receiving partial data.

- Increase `--phase-timeout-secs`
- Check network bandwidth between machines
- Try a smaller `--bytes` value

### Port 3001 Already in Use

```bash
lsof -i :3001    # macOS
ss -tlnp | grep 3001  # Linux

# Use a different port
cargo run -- --port 3002   # rendezvous server
# Update --rendezvous-url ws://...:3002 on both peers
```

### Tailscale Not Routing (Overlay Scope)

- Verify Tailscale is running: `tailscale status`
- Verify both machines can ping each other's Tailscale IP
- The rendezvous server must bind `0.0.0.0` (default) to accept Tailscale connections
- Verify `--network-scope overlay` is set on both peers
