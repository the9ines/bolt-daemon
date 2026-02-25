#!/usr/bin/env bash
# E2E test for INTEROP-4: post-HELLO message set (ping/pong/app_message).
#
# Prerequisites:
#   - bolt-rendezvous at ../bolt-rendezvous (sibling repo)
#   - Rust toolchain installed
#
# Usage:
#   bash scripts/e2e_interop_4_local.sh
#
# Runs bolt-rendezvous + two bolt-daemon peers in full web interop mode
# (web_v1 + web_hello_v1 + web_dc_v1). Validates:
#   - HELLO completes on both sides
#   - Envelope negotiated
#   - Ping/pong roundtrip
#   - app_message received and echoed
# Exits 0 on success, 1 on any failure.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DAEMON_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RENDEZVOUS_DIR="$(cd "$DAEMON_DIR/../bolt-rendezvous" && pwd 2>/dev/null)" || {
    echo "FATAL: bolt-rendezvous not found at $DAEMON_DIR/../bolt-rendezvous"
    exit 1
}

echo "=== Building bolt-rendezvous ==="
cargo build --manifest-path "$RENDEZVOUS_DIR/Cargo.toml" 2>&1

echo "=== Building bolt-daemon ==="
cargo build --manifest-path "$DAEMON_DIR/Cargo.toml" 2>&1

# Discover rendezvous binary
if [ -x "$RENDEZVOUS_DIR/target/debug/bolt-rendezvous" ]; then
    RENDEZVOUS_BIN="$RENDEZVOUS_DIR/target/debug/bolt-rendezvous"
elif [ -x "$RENDEZVOUS_DIR/target/debug/localbolt-signal" ]; then
    RENDEZVOUS_BIN="$RENDEZVOUS_DIR/target/debug/localbolt-signal"
else
    echo "FATAL: no rendezvous binary found in $RENDEZVOUS_DIR/target/debug/"
    exit 1
fi
DAEMON_BIN="$DAEMON_DIR/target/debug/bolt-daemon"

LOG_DIR="/tmp/bolt-e2e-interop4-$$"
mkdir -p "$LOG_DIR"

RV_PID=""
OFF_PID=""
ANS_PID=""

cleanup() {
    [ -n "$OFF_PID" ] && kill "$OFF_PID" 2>/dev/null || true
    [ -n "$ANS_PID" ] && kill "$ANS_PID" 2>/dev/null || true
    [ -n "$RV_PID" ] && kill "$RV_PID" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

ROOM="interop4-test"
SESSION="s1"
RV_URL="ws://127.0.0.1:3001"
TIMEOUT_SECS=15

# ── Start rendezvous server ──────────────────────────────────
echo "=== Starting bolt-rendezvous ==="
"$RENDEZVOUS_BIN" &>"$LOG_DIR/rendezvous.log" &
RV_PID=$!
sleep 1

if ! kill -0 "$RV_PID" 2>/dev/null; then
    echo "FAIL: rendezvous server did not start"
    cat "$LOG_DIR/rendezvous.log"
    exit 1
fi
echo "  rendezvous PID=$RV_PID"

# ── Start answerer ───────────────────────────────────────────
echo "=== Starting answerer (web_dc_v1) ==="
"$DAEMON_BIN" \
    --role answerer \
    --signal rendezvous \
    --interop-signal web_v1 \
    --interop-hello web_hello_v1 \
    --interop-dc web_dc_v1 \
    --pairing-policy allow \
    --room "$ROOM" \
    --session "$SESSION" \
    --expect-peer offerer1 \
    --peer-id answerer1 \
    --rendezvous-url "$RV_URL" \
    --phase-timeout-secs "$TIMEOUT_SECS" \
    &>"$LOG_DIR/answerer.log" &
ANS_PID=$!
echo "  answerer PID=$ANS_PID"
sleep 2

# ── Start offerer ────────────────────────────────────────────
echo "=== Starting offerer (web_dc_v1) ==="
"$DAEMON_BIN" \
    --role offerer \
    --signal rendezvous \
    --interop-signal web_v1 \
    --interop-hello web_hello_v1 \
    --interop-dc web_dc_v1 \
    --room "$ROOM" \
    --session "$SESSION" \
    --to answerer1 \
    --peer-id offerer1 \
    --rendezvous-url "$RV_URL" \
    --phase-timeout-secs "$TIMEOUT_SECS" \
    &>"$LOG_DIR/offerer.log" &
OFF_PID=$!
echo "  offerer PID=$OFF_PID"

# ── Wait for both daemons to exit ────────────────────────────
echo "=== Waiting for daemons (timeout ${TIMEOUT_SECS}s + buffer) ==="
WAIT_LIMIT=$((TIMEOUT_SECS + 10))
for i in $(seq 1 "$WAIT_LIMIT"); do
    OFF_ALIVE=0
    ANS_ALIVE=0
    kill -0 "$OFF_PID" 2>/dev/null && OFF_ALIVE=1
    kill -0 "$ANS_PID" 2>/dev/null && ANS_ALIVE=1
    if [ "$OFF_ALIVE" -eq 0 ] && [ "$ANS_ALIVE" -eq 0 ]; then
        echo "  both daemons exited after ${i}s"
        break
    fi
    sleep 1
done

# ── Validate logs ────────────────────────────────────────────
echo ""
echo "=== Validation ==="
FAILURES=0

check() {
    local label="$1"
    local file="$2"
    local pattern="$3"
    if grep -q "$pattern" "$file"; then
        echo "  PASS: $label"
    else
        echo "  FAIL: $label (pattern: $pattern)"
        FAILURES=$((FAILURES + 1))
    fi
}

# Offerer checks
check "offerer: HELLO complete" "$LOG_DIR/offerer.log" "HELLO exchange complete"
check "offerer: envelope negotiated" "$LOG_DIR/offerer.log" "bolt.profile-envelope-v1"
check "offerer: sent initial ping" "$LOG_DIR/offerer.log" "\\[INTEROP-4\\] sent initial ping"
check "offerer: sent app_message" "$LOG_DIR/offerer.log" "\\[INTEROP-4\\] sent app_message"
check "offerer: recv pong" "$LOG_DIR/offerer.log" "\\[INTEROP-4\\] recv pong"
check "offerer: recv app echo" "$LOG_DIR/offerer.log" "\\[INTEROP-4\\] app_message recv"

# Answerer checks
check "answerer: HELLO complete" "$LOG_DIR/answerer.log" "HELLO exchange complete"
check "answerer: envelope negotiated" "$LOG_DIR/answerer.log" "bolt.profile-envelope-v1"
check "answerer: recv ping, sent pong" "$LOG_DIR/answerer.log" "\\[INTEROP-4\\] recv ping"
check "answerer: recv app_message" "$LOG_DIR/answerer.log" "\\[INTEROP-4\\] app_message recv"

echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo "=== ALL CHECKS PASSED ==="
    echo "  Logs: $LOG_DIR/"
    exit 0
else
    echo "=== $FAILURES CHECK(S) FAILED ==="
    echo ""
    echo "--- offerer log ---"
    cat "$LOG_DIR/offerer.log"
    echo ""
    echo "--- answerer log ---"
    cat "$LOG_DIR/answerer.log"
    echo ""
    echo "  Logs: $LOG_DIR/"
    exit 1
fi
