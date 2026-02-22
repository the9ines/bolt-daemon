# Two-Machine Smoke Test (Rendezvous Signaling)

Reproduce the bolt-daemon WebRTC DataChannel exchange between two physical
machines using rendezvous signaling via bolt-rendezvous.

## Prerequisites

Both machines need:

- Rust stable toolchain (1.70+)
- CMake (for vendored libdatachannel build)
- Xcode Command Line Tools (macOS) or build-essential (Linux)
- Network connectivity between machines (same LAN, Tailscale, or public)

## Pinned Pairing

Use these exact tags for reproducibility:

| Component | Tag | Commit |
|-----------|-----|--------|
| bolt-daemon | `daemon-v0.0.10-ci-pin` | `f9c8f95` |
| bolt-rendezvous | `rendezvous-v0.0.3-ci` | `a9c496e` |

## Setup

### Machine A (runs rendezvous server + one daemon peer)

```bash
cd ~/Desktop/the9ines.com/bolt-ecosystem

# Ensure rendezvous is at the pinned tag
cd bolt-rendezvous
git fetch --tags
git checkout rendezvous-v0.0.3-ci
cargo build

# Start rendezvous server (foreground, port 3001)
cargo run
```

Leave the server running. Open a second terminal on Machine A.

### Machine B (runs the other daemon peer)

```bash
# Clone repos if not already present
git clone https://github.com/the9ines/bolt-daemon.git
git clone https://github.com/the9ines/bolt-rendezvous.git  # not needed for running, but for reference

cd bolt-daemon
git fetch --tags
git checkout daemon-v0.0.10-ci-pin
cargo build
```

## Test Commands

Replace `MACHINE_A_IP` with the actual IP of Machine A:
- LAN: use the private IP (e.g., `192.168.1.100`)
- Overlay: use the Tailscale IP (e.g., `100.x.y.z`)
- Global: use the public IP

### A) LAN Scope

Machine A (answerer):
```bash
cd ~/Desktop/the9ines.com/bolt-ecosystem/bolt-daemon
cargo run -- --role answerer --signal rendezvous \
  --rendezvous-url ws://MACHINE_A_IP:3001 \
  --room smoke --session smoke-lan-001 \
  --peer-id mac-studio --expect-peer macbook \
  --network-scope lan --phase-timeout-secs 300
```

Machine B (offerer):
```bash
cd bolt-daemon
cargo run -- --role offerer --signal rendezvous \
  --rendezvous-url ws://MACHINE_A_IP:3001 \
  --room smoke --session smoke-lan-001 \
  --peer-id macbook --to mac-studio \
  --network-scope lan --phase-timeout-secs 300
```

### B) Overlay Scope (Tailscale / CGNAT)

Both machines must have Tailscale running. Use the Tailscale IP of Machine A.

Machine A (answerer):
```bash
cd ~/Desktop/the9ines.com/bolt-ecosystem/bolt-daemon
cargo run -- --role answerer --signal rendezvous \
  --rendezvous-url ws://100.x.y.z:3001 \
  --room smoke --session smoke-overlay-001 \
  --peer-id mac-studio --expect-peer macbook \
  --network-scope overlay --phase-timeout-secs 300
```

Machine B (offerer):
```bash
cd bolt-daemon
cargo run -- --role offerer --signal rendezvous \
  --rendezvous-url ws://100.x.y.z:3001 \
  --room smoke --session smoke-overlay-001 \
  --peer-id macbook --to mac-studio \
  --network-scope overlay --phase-timeout-secs 300
```

### C) Global Scope

Accepts all valid IPs including public. Use Machine A's routable IP.

Machine A (answerer):
```bash
cd ~/Desktop/the9ines.com/bolt-ecosystem/bolt-daemon
cargo run -- --role answerer --signal rendezvous \
  --rendezvous-url ws://MACHINE_A_IP:3001 \
  --room smoke --session smoke-global-001 \
  --peer-id mac-studio --expect-peer macbook \
  --network-scope global --phase-timeout-secs 300
```

Machine B (offerer):
```bash
cd bolt-daemon
cargo run -- --role offerer --signal rendezvous \
  --rendezvous-url ws://MACHINE_A_IP:3001 \
  --room smoke --session smoke-global-001 \
  --peer-id macbook --to mac-studio \
  --network-scope global --phase-timeout-secs 300
```

**Note:** Global scope accepts public IPs. No STUN/TURN is configured by
default, so this only works when both machines can reach each other directly.
For NAT traversal, STUN/TURN integration is required (not yet implemented).

## Session Naming Convention

Use descriptive, unique session strings to prevent cross-talk:

```
<scope>-<purpose>-<NNN>
```

Examples: `smoke-lan-001`, `smoke-overlay-002`, `debug-global-005`

Increment the suffix for each test run. Two daemon instances with different
`--session` values silently ignore each other's signals.

## Success Criteria

Both peers must:

1. Print `hello/ack complete` with the matching session
2. Print `DataChannel open`
3. Print `SUCCESS` and exit 0

Example offerer output:
```
[offerer] rendezvous mode: room='smoke', session='smoke-lan-001', peer_id='macbook', to='mac-studio'
[rendezvous] received 'ack' signal from 'mac-studio'
[rendezvous] hello/ack complete — session 'smoke-lan-001'
[rendezvous] received 'answer' signal from 'mac-studio'
[offerer] DataChannel open
[offerer] SUCCESS — received matching payload
```

## Troubleshooting

### macOS Firewall Blocks Rebuilt Binary

macOS asks "allow incoming connections?" each time you rebuild. If the dialog
was dismissed or denied, the binary is silently blocked. Fix:

```bash
# Remove the firewall rule for the old binary, rebuild, and re-allow
cargo build
# macOS will prompt again — click Allow
```

Or temporarily disable the firewall in System Settings > Network > Firewall.

### "peer not found" During Hello

The offerer retries hello automatically (100ms backoff, up to 1s) if the
answerer hasn't registered yet. Start the answerer first. If it persists:

- Verify both peers use the same `--rendezvous-url`
- Verify the `--peer-id` on one machine matches `--to` or `--expect-peer` on the other
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

### Port 3001 Already in Use

```bash
# Find what's using port 3001
lsof -i :3001    # macOS
ss -tlnp | grep 3001  # Linux

# Kill it or use a different port
cargo run -- --port 3002   # rendezvous server
# Then update --rendezvous-url ws://...:3002 on both peers
```

### Tailscale Not Routing (Overlay Scope)

- Verify Tailscale is running: `tailscale status`
- Verify both machines can ping each other's Tailscale IP
- The rendezvous server must bind `0.0.0.0` (default) to accept Tailscale connections
- If ICE candidates are rejected, verify `--network-scope overlay` is set on both peers

### Phase Timeout Expired

Default timeout is 30 seconds. For manual two-machine tests where you need
time to start the second peer, use `--phase-timeout-secs 300` (5 minutes).
