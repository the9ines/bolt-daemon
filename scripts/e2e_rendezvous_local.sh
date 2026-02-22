#!/usr/bin/env bash
# Deterministic local E2E test for bolt-daemon rendezvous signaling.
#
# Prerequisites:
#   - bolt-rendezvous at ../bolt-rendezvous (sibling repo)
#   - Rust toolchain installed
#
# Usage:
#   bash scripts/e2e_rendezvous_local.sh
#
# Runs bolt-rendezvous + two bolt-daemon peers (offerer/answerer) with
# rendezvous signaling, hello/ack handshake, session matching.
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

RENDEZVOUS_BIN="$RENDEZVOUS_DIR/target/debug/bolt-rendezvous"
DAEMON_BIN="$DAEMON_DIR/target/debug/bolt-daemon"

LOG_DIR="/tmp/bolt-e2e-$$"
mkdir -p "$LOG_DIR"

# PIDs for cleanup
RV_PID=""
OFF_PID=""
ANS_PID=""

cleanup() {
    [ -n "$RV_PID" ] && kill "$RV_PID" 2>/dev/null || true
    [ -n "$OFF_PID" ] && kill "$OFF_PID" 2>/dev/null || true
    [ -n "$ANS_PID" ] && kill "$ANS_PID" 2>/dev/null || true
    # Keep logs on failure for debugging
    if [ "${E2E_PASSED:-0}" -eq 1 ]; then
        rm -rf "$LOG_DIR"
    else
        echo "Logs preserved at: $LOG_DIR"
    fi
}
trap cleanup EXIT

# ── Start rendezvous server ──────────────────────────────────
echo "=== Starting rendezvous server ==="
"$RENDEZVOUS_BIN" &>"$LOG_DIR/rendezvous.log" &
RV_PID=$!

# Wait for server to be ready (listen on port 3001)
for i in $(seq 1 10); do
    if lsof -i :3001 -sTCP:LISTEN >/dev/null 2>&1; then
        echo "Rendezvous server ready (PID $RV_PID)"
        break
    fi
    if [ "$i" -eq 10 ]; then
        echo "FATAL: rendezvous server did not start within 10 seconds"
        cat "$LOG_DIR/rendezvous.log"
        exit 1
    fi
    sleep 1
done

# ── Start answerer first (registers and waits for hello) ─────
echo "=== Starting answerer (bob) ==="
"$DAEMON_BIN" --role answerer --signal rendezvous \
    --rendezvous-url ws://127.0.0.1:3001 \
    --room test --session test-session-1 \
    --peer-id bob --expect-peer alice \
    --network-scope lan --phase-timeout-secs 30 \
    2>"$LOG_DIR/answerer.log" &
ANS_PID=$!

# Brief pause to let answerer register before offerer sends hello
sleep 1

# ── Start offerer (sends hello, retries if peer not yet registered) ──
echo "=== Starting offerer (alice) ==="
"$DAEMON_BIN" --role offerer --signal rendezvous \
    --rendezvous-url ws://127.0.0.1:3001 \
    --room test --session test-session-1 \
    --peer-id alice --to bob \
    --network-scope lan --phase-timeout-secs 30 \
    2>"$LOG_DIR/offerer.log" &
OFF_PID=$!

# ── Wait for both peers ──────────────────────────────────────
echo "=== Waiting for peers to complete ==="

OFF_RC=0
wait "$OFF_PID" || OFF_RC=$?
OFF_PID=""

ANS_RC=0
wait "$ANS_PID" || ANS_RC=$?
ANS_PID=""

# ── Report results ───────────────────────────────────────────
echo ""
echo "=== Offerer (exit $OFF_RC) ==="
grep -E 'session=|hello/ack|sending|received|DataChannel open|SUCCESS|FATAL' \
    "$LOG_DIR/offerer.log" 2>/dev/null || true

echo ""
echo "=== Answerer (exit $ANS_RC) ==="
grep -E 'session=|hello/ack|sending|received|DataChannel open|SUCCESS|FATAL' \
    "$LOG_DIR/answerer.log" 2>/dev/null || true

echo ""
if [ "$OFF_RC" -eq 0 ] && [ "$ANS_RC" -eq 0 ]; then
    E2E_PASSED=1
    echo "PASS — both peers exited 0"
    exit 0
else
    echo "FAIL (offerer=$OFF_RC, answerer=$ANS_RC)"
    echo ""
    echo "--- Full offerer log ---"
    cat "$LOG_DIR/offerer.log" 2>/dev/null || true
    echo ""
    echo "--- Full answerer log ---"
    cat "$LOG_DIR/answerer.log" 2>/dev/null || true
    exit 1
fi
