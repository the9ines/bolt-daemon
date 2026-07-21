#!/usr/bin/env bash
# Contract smoke test — validates DAEMON_CONTRACT.md matches actual behavior.
#
# Covers the current CLI surface: ws-endpoint (default) and simulate modes,
# legacy-flag rejection, fail-closed arg validation, startup log tokens.
# Runs isolated (scratch --data-dir / --socket-path); no network peers needed.
# Exits 0 only if all checks pass.
#
# Usage:
#   bash scripts/contract_smoke.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DAEMON_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Building bolt-daemon ==="
cargo build --manifest-path "$DAEMON_DIR/Cargo.toml" 2>&1 | tail -2

BIN="$DAEMON_DIR/target/debug/bolt-daemon"

if [ ! -x "$BIN" ]; then
    echo "FATAL: bolt-daemon binary not found at $BIN"
    exit 1
fi

SCRATCH="$(mktemp -d /tmp/bolt-contract-smoke.XXXXXX)"
SOCK="$SCRATCH/ipc.sock"
DAEMON_PID=""
cleanup() {
    [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null || true
    rm -rf "$SCRATCH"
}
trap cleanup EXIT

ISOLATE=(--data-dir "$SCRATCH" --socket-path "$SOCK")

PASS=0
FAIL=0

check() {
    local desc="$1"
    local result="$2"  # 0 = pass, nonzero = fail
    if [ "$result" -eq 0 ]; then
        echo "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $desc"
        FAIL=$((FAIL + 1))
    fi
}

echo ""
echo "=== Contract Smoke Checks ==="

# ── 1. Invalid --mode → exit 1 ─────────────────────────────
RC=0; "$BIN" --mode banana 2>/dev/null || RC=$?
[ "$RC" -ne 0 ] && R=0 || R=1
check "--mode banana exits nonzero" "$R"

# ── 2. Legacy WebRTC flags → exit 1 + message ──────────────
for flag in --role --signal --offer --answer --interop-check; do
    RC=0; "$BIN" "$flag" x 2>/dev/null || RC=$?
    [ "$RC" -ne 0 ] && R=0 || R=1
    check "Legacy flag $flag exits nonzero" "$R"
done
OUTPUT=$("$BIN" --role offerer 2>&1 || true)
echo "$OUTPUT" | grep -q "Legacy flag" && R=0 || R=1
check "Legacy flag rejection mentions 'Legacy flag'" "$R"

# ── 3. ws-endpoint (default) without --ws-listen → exit 1 ──
RC=0; "$BIN" "${ISOLATE[@]}" 2>/dev/null || RC=$?
[ "$RC" -ne 0 ] && R=0 || R=1
check "Default mode without --ws-listen exits nonzero" "$R"

OUTPUT=$("$BIN" "${ISOLATE[@]}" 2>&1 || true)
echo "$OUTPUT" | grep -q -- "--ws-listen required" && R=0 || R=1
check "Missing --ws-listen mentions '--ws-listen required'" "$R"

# ── 4. Invalid --ws-listen address → exit 1 ────────────────
RC=0; "$BIN" "${ISOLATE[@]}" --ws-listen not-an-addr 2>/dev/null || RC=$?
[ "$RC" -ne 0 ] && R=0 || R=1
check "Invalid --ws-listen address exits nonzero" "$R"

OUTPUT=$("$BIN" "${ISOLATE[@]}" --ws-listen not-an-addr 2>&1 || true)
echo "$OUTPUT" | grep -q "invalid --ws-listen" && R=0 || R=1
check "Invalid --ws-listen mentions 'invalid --ws-listen'" "$R"

# ── 5. simulate mode without --simulate-event → exit 1 ─────
RC=0; "$BIN" --mode simulate "${ISOLATE[@]}" 2>/dev/null || RC=$?
[ "$RC" -ne 0 ] && R=0 || R=1
check "Simulate without --simulate-event exits nonzero" "$R"

OUTPUT=$("$BIN" --mode simulate "${ISOLATE[@]}" 2>&1 || true)
echo "$OUTPUT" | grep -q -- "--simulate-event required" && R=0 || R=1
check "Simulate without event mentions '--simulate-event required'" "$R"

# ── 6. Invalid --simulate-event → exit 1 ───────────────────
RC=0; "$BIN" --mode simulate --simulate-event banana "${ISOLATE[@]}" 2>/dev/null || RC=$?
[ "$RC" -ne 0 ] && R=0 || R=1
check "--simulate-event banana exits nonzero" "$R"

# ── 7. Invalid --pairing-policy → exit 1 ───────────────────
RC=0; "$BIN" --pairing-policy banana 2>/dev/null || RC=$?
[ "$RC" -ne 0 ] && R=0 || R=1
check "--pairing-policy banana exits nonzero" "$R"

# ── 8. Startup banner + tokens; unknown flags tolerated ────
# Valid ws-endpoint run on an ephemeral port, with a bogus flag mixed in
# (contract: unknown non-legacy flags are ignored). Capture startup stderr,
# verify tokens and that the daemon stays alive, then kill it.
LOG="$SCRATCH/startup.log"
"$BIN" --mode ws-endpoint --ws-listen 127.0.0.1:0 --bogus-flag whatever \
    "${ISOLATE[@]}" 2>"$LOG" &
DAEMON_PID=$!
sleep 2

kill -0 "$DAEMON_PID" 2>/dev/null && R=0 || R=1
check "Daemon stays alive with unknown flag (tolerant parser)" "$R"

grep -q "\[bolt-daemon\] mode=WsEndpoint" "$LOG" && R=0 || R=1
check "Startup banner shows mode=WsEndpoint" "$R"

grep -q "\[IPC\] listening on $SOCK" "$LOG" && R=0 || R=1
check "IPC server binds --socket-path" "$R"

grep -q "\[WS_ENDPOINT\] starting on" "$LOG" && R=0 || R=1
check "WS endpoint startup token present" "$R"

kill "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true
DAEMON_PID=""

[ -f "$SCRATCH/identity.key" ] && R=0 || R=1
check "Identity created in --data-dir" "$R"

# ── Summary ───────────────────────────────────────────────
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -ne 0 ]; then
    echo "FAIL"
    exit 1
fi

echo "PASS — all contract checks verified"
exit 0
