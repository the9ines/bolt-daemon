# Two-Machine LAN E2E Test

End-to-end WebRTC DataChannel test between two physical machines on the same LAN.

## Machines

| Role | Machine | Arch | Notes |
|------|---------|------|-------|
| Machine A | Mac Studio | arm64 | Primary dev, macOS firewall enabled |
| Machine B | MacBook Pro | x86_64 | Secondary dev |

## Prerequisites

- Both machines on the same LAN (same Wi-Fi / wired network)
- Rust toolchain installed on both
- bolt-daemon repo cloned and at the same tag on both
- Tailscale or other VPN disabled during test (CGNAT IPs are rejected by LAN-only filter)

## Build

### Machine A (Mac Studio, arm64)

```bash
cd ~/Desktop/the9ines.com/bolt-ecosystem/bolt-daemon
cargo build --release
```

For E2E testing, always use the release binary at `target/release/bolt-daemon`.
Reserve `cargo run` for local single-machine dev only.

### Machine B (MacBook Pro, x86_64)

```bash
cd ~/Users/oberfelder/bolt-ecosystem/bolt-daemon
git fetch && git checkout <tag>
cargo build --release
```

## Firewall

macOS application firewall rules are tied to binary identity. Rules go stale
when the binary is rebuilt (the hash changes). This causes silent inbound UDP
blocking with no log or prompt.

**After every rebuild**, re-add the firewall rule:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --remove <path-to-bolt-daemon>
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add <path-to-bolt-daemon>
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp <path-to-bolt-daemon>
```

Verify:

```bash
/usr/libexec/ApplicationFirewall/socketfilterfw --listapps | grep bolt-daemon
```

Must show `(Allow incoming connections)`.

**Codesigning** (optional, avoids re-adding after each rebuild):

```bash
codesign -s - target/release/bolt-daemon
```

Ad-hoc signing (`-s -`) is sufficient for the application firewall.

## Option A: File-Based Signaling (manual scp)

File-based signaling via `/tmp/bolt-spike/`. The offerer writes `offer.json`,
the answerer reads it, writes `answer.json`, and the offerer reads the answer
to complete the WebRTC handshake.

### Step 1: Clean signal directory (both machines)

```bash
rm -rf /tmp/bolt-spike && mkdir -p /tmp/bolt-spike
```

### Step 2: Start the offerer

```bash
# On the offerer machine (use extended timeout for manual scp):
./target/release/bolt-daemon --role offerer --phase-timeout-secs 300
```

### Step 3: Copy offer to the answerer machine

```bash
# From offerer machine to answerer machine:
scp /tmp/bolt-spike/offer.json <user>@<answerer-ip>:/tmp/bolt-spike/offer.json
```

### Step 4: Start the answerer

```bash
# On the answerer machine:
./target/release/bolt-daemon --role answerer --phase-timeout-secs 300
```

Reads `offer.json`, writes `answer.json`.

### Step 5: Copy answer back to the offerer machine

```bash
# From answerer machine to offerer machine:
scp /tmp/bolt-spike/answer.json <user>@<offerer-ip>:/tmp/bolt-spike/answer.json
```

### Step 6: Verify

Both sides should print:

```
[pc] connection state: Connected
[dc] open
[offerer] SUCCESS — received matching payload
[bolt-daemon] exit 0
```

```
[pc] connection state: Connected
[dc] open
[answerer] SUCCESS — echoed matching payload
[bolt-daemon] exit 0
```

## Option B: Rendezvous Signaling (no scp needed)

Uses bolt-rendezvous WebSocket server to relay signaling. No manual file
copying between machines. Requires the rendezvous server to be reachable
from both machines.

### Step 1: Start rendezvous server

On one of the machines (or a shared server):

```bash
cd ~/Desktop/the9ines.com/bolt-ecosystem/bolt-rendezvous
cargo run
```

Default listen address: `ws://0.0.0.0:3001`

### Step 2: Start the offerer

```bash
# On Machine A:
./target/release/bolt-daemon --role offerer --signal rendezvous \
  --rendezvous-url ws://<rendezvous-ip>:3001 \
  --room lan-test --session e2e-1 --peer-id alice --to bob
```

### Step 3: Start the answerer

```bash
# On Machine B:
./target/release/bolt-daemon --role answerer --signal rendezvous \
  --rendezvous-url ws://<rendezvous-ip>:3001 \
  --room lan-test --session e2e-1 --peer-id bob --expect-peer alice
```

### Step 4: Verify

Same success output as file mode. Both exit 0.

**Note:** Default timeout is 30 seconds. For manual multi-terminal setup,
add `--phase-timeout-secs 300` if needed.

## Automated Script (via SSH, file mode)

If Machine A has SSH access to Machine B, the entire exchange can be scripted.
This example uses Machine B as offerer, Machine A as answerer:

```bash
MACHINE_B="oberfelder@192.168.4.249"
MACHINE_B_DAEMON="/Users/oberfelder/Users/oberfelder/bolt-ecosystem/bolt-daemon/target/release/bolt-daemon"
MACHINE_A_DAEMON="./target/release/bolt-daemon"

# Clean both sides
rm -rf /tmp/bolt-spike && mkdir -p /tmp/bolt-spike
ssh $MACHINE_B "rm -rf /tmp/bolt-spike && mkdir -p /tmp/bolt-spike"

# Start offerer on B (detached)
ssh $MACHINE_B "nohup $MACHINE_B_DAEMON --role offerer --phase-timeout-secs 300 </dev/null >/dev/null 2>/tmp/bolt-spike/offerer.log &
for i in \$(seq 1 15); do
  [ -f /tmp/bolt-spike/offer.json ] && [ -s /tmp/bolt-spike/offer.json ] && exit 0
  sleep 1
done
exit 1"

# Copy offer to A
scp -q $MACHINE_B:/tmp/bolt-spike/offer.json /tmp/bolt-spike/offer.json

# Start answerer on A
$MACHINE_A_DAEMON --role answerer --phase-timeout-secs 300 2>/tmp/bolt-spike/answerer.log &
for i in $(seq 1 15); do
  [ -f /tmp/bolt-spike/answer.json ] && [ -s /tmp/bolt-spike/answer.json ] && break
  sleep 1
done

# Copy answer to B
scp -q /tmp/bolt-spike/answer.json $MACHINE_B:/tmp/bolt-spike/answer.json

# Check results
sleep 15
echo "=== Machine A ===" && tail -5 /tmp/bolt-spike/answerer.log
echo "=== Machine B ===" && ssh $MACHINE_B "tail -5 /tmp/bolt-spike/offerer.log"
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `connection state: Failed` after ~40s | Firewall blocking STUN UDP | Re-add firewall rule (see above) |
| `FATAL: timed out waiting for answer.json` | Signaling file not delivered in time | Use `--phase-timeout-secs 300` or rendezvous mode |
| `ICE candidate REJECTED (Lan)` | Tailscale/VPN active | Disable VPN during test |
| `bad CPU type in executable` | Wrong architecture binary | Build locally on each machine, do not scp binaries |
| `rendezvous server unreachable` | bolt-rendezvous not running | Start it, or use file mode |
| `FATAL: --signal rendezvous requires --room` | Missing required flag | Add `--room`, `--session`, `--to`/`--expect-peer` |
| `FATAL: --signal rendezvous requires --session` | Missing required flag | Add `--session` (must match on both sides) |
| `network_scope mismatch` | Peers disagree on scope | Use same `--network-scope` on both sides |

## Local Regression (Single Machine)

For quick single-machine regression testing (no manual scp, no SSH), use the
automated E2E script:

```bash
bash scripts/e2e_rendezvous_local.sh
```

This starts bolt-rendezvous + offerer + answerer locally with rendezvous signaling,
hello/ack handshake, and session matching. See `README.md` for details.

## Known Limitations

- macOS firewall rules go stale on binary rebuild (silent block, no prompt)
- libjuice ICE connectivity timer is ~40 seconds (not configurable via RtcConfig)
- mDNS `.local` candidates are rejected (cannot verify they resolve to LAN)
- Default timeout is 30 seconds; use `--phase-timeout-secs 300` for manual two-machine tests
