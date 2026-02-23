#!/usr/bin/env bash
# Local E2E test for bolt-daemon rendezvous smoke mode.
#
# Runs bolt-rendezvous + two bolt-daemon peers (answerer/offerer) with
# --mode smoke on localhost. Verifies both exit 0 with SHA-256 integrity.
#
# Prerequisites:
#   - bolt-rendezvous at ../bolt-rendezvous (sibling repo)
#   - Rust toolchain installed
#
# Usage:
#   bash scripts/e2e_rendezvous_smoke_local.sh [--bytes N] [--repeat N] [--json]
#
# Exits 0 on success (both peers PASS), 1 on any failure.
# NOT intended for CI — local validation only.

set -euo pipefail

# ── Parse optional args ─────────────────────────────────────
BYTES="1048576"
REPEAT="1"
JSON_FLAG=""

while [ $# -gt 0 ]; do
    case "$1" in
        --bytes)  BYTES="$2"; shift 2 ;;
        --repeat) REPEAT="$2"; shift 2 ;;
        --json)   JSON_FLAG="--json"; shift ;;
        *)
            echo "Unknown option: $1 (usage: $0 [--bytes N] [--repeat N] [--json])" >&2
            exit 1
            ;;
    esac
done

# ── Locate repos ────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DAEMON_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RENDEZVOUS_DIR="$(cd "$DAEMON_DIR/../bolt-rendezvous" && pwd 2>/dev/null)" || {
    echo "FATAL: bolt-rendezvous not found at $DAEMON_DIR/../bolt-rendezvous"
    echo "This script requires bolt-rendezvous as a sibling repo."
    exit 1
}

# ── Build ───────────────────────────────────────────────────
echo "=== Building bolt-rendezvous ==="
cargo build --manifest-path "$RENDEZVOUS_DIR/Cargo.toml" 2>&1

echo "=== Building bolt-daemon ==="
cargo build --manifest-path "$DAEMON_DIR/Cargo.toml" 2>&1

# Discover rendezvous binary (handles crate rename history)
if [ -x "$RENDEZVOUS_DIR/target/debug/bolt-rendezvous" ]; then
    RENDEZVOUS_BIN="$RENDEZVOUS_DIR/target/debug/bolt-rendezvous"
elif [ -x "$RENDEZVOUS_DIR/target/debug/localbolt-signal" ]; then
    RENDEZVOUS_BIN="$RENDEZVOUS_DIR/target/debug/localbolt-signal"
else
    echo "FATAL: no rendezvous binary found in $RENDEZVOUS_DIR/target/debug/"
    echo "Expected bolt-rendezvous or localbolt-signal"
    exit 1
fi
DAEMON_BIN="$DAEMON_DIR/target/debug/bolt-daemon"

LOG_DIR="/tmp/bolt-smoke-e2e-$$"
mkdir -p "$LOG_DIR"

# PIDs for cleanup
RV_PID=""
OFF_PID=""
ANS_PID=""

cleanup() {
    [ -n "$RV_PID" ] && kill "$RV_PID" 2>/dev/null || true
    [ -n "$OFF_PID" ] && kill "$OFF_PID" 2>/dev/null || true
    [ -n "$ANS_PID" ] && kill "$ANS_PID" 2>/dev/null || true
    if [ "${E2E_PASSED:-0}" -eq 1 ]; then
        rm -rf "$LOG_DIR"
    else
        echo "Logs preserved at: $LOG_DIR"
    fi
}
trap cleanup EXIT

# ── Start rendezvous server ─────────────────────────────────
echo "=== Starting rendezvous server ==="
"$RENDEZVOUS_BIN" &>"$LOG_DIR/rendezvous.log" &
RV_PID=$!

# Wait for server to be ready (listen on port 3001)
for i in $(seq 1 10); do
    if (echo >/dev/tcp/127.0.0.1/3001) 2>/dev/null; then
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

# ── Start answerer first ────────────────────────────────────
echo "=== Starting smoke answerer (bob) ==="
echo "    bytes=$BYTES repeat=$REPEAT"
"$DAEMON_BIN" --role answerer --signal rendezvous --mode smoke \
    --rendezvous-url ws://127.0.0.1:3001 \
    --room test --session smoke-local-$$ \
    --peer-id bob --expect-peer alice \
    --network-scope lan --bytes "$BYTES" --repeat "$REPEAT" \
    --phase-timeout-secs 30 $JSON_FLAG \
    2>"$LOG_DIR/answerer.log" &
ANS_PID=$!

# Brief pause to let answerer register
sleep 1

# ── Start offerer ───────────────────────────────────────────
echo "=== Starting smoke offerer (alice) ==="
"$DAEMON_BIN" --role offerer --signal rendezvous --mode smoke \
    --rendezvous-url ws://127.0.0.1:3001 \
    --room test --session smoke-local-$$ \
    --peer-id alice --to bob \
    --network-scope lan --bytes "$BYTES" --repeat "$REPEAT" \
    --phase-timeout-secs 30 $JSON_FLAG \
    2>"$LOG_DIR/offerer.log" &
OFF_PID=$!

# ── Wait for both peers ─────────────────────────────────────
echo "=== Waiting for peers to complete ==="

OFF_RC=0
wait "$OFF_PID" || OFF_RC=$?
OFF_PID=""

ANS_RC=0
wait "$ANS_PID" || ANS_RC=$?
ANS_PID=""

# ── Report results ──────────────────────────────────────────
echo ""
echo "=== Offerer (exit $OFF_RC) ==="
grep -E 'hello/ack|DataChannel open|smoke|PASS|FAIL|FATAL' \
    "$LOG_DIR/offerer.log" 2>/dev/null || true

echo ""
echo "=== Answerer (exit $ANS_RC) ==="
grep -E 'hello/ack|DataChannel open|smoke|PASS|FAIL|FATAL' \
    "$LOG_DIR/answerer.log" 2>/dev/null || true

echo ""
if [ "$OFF_RC" -eq 0 ] && [ "$ANS_RC" -eq 0 ]; then
    E2E_PASSED=1
    echo "PASS — both peers exited 0 (smoke mode, ${BYTES} bytes, repeat=${REPEAT})"
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
