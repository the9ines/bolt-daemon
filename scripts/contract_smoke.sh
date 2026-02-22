#!/usr/bin/env bash
# Contract smoke test — validates DAEMON_CONTRACT.md matches actual behavior.
#
# Does NOT require bolt-rendezvous running.
# Does NOT run a full E2E exchange.
# Exits 0 only if all checks pass.
#
# Usage:
#   bash scripts/contract_smoke.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DAEMON_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Building bolt-daemon ==="
cargo build --manifest-path "$DAEMON_DIR/Cargo.toml" 2>&1

BIN="$DAEMON_DIR/target/debug/bolt-daemon"

if [ ! -x "$BIN" ]; then
    echo "FATAL: bolt-daemon binary not found at $BIN"
    exit 1
fi

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

# ── 1. No args → usage line + exit 1 ───────────────────────
OUTPUT=$("$BIN" 2>&1 || true)
RC=0; "$BIN" 2>/dev/null || RC=$?
echo "$OUTPUT" | grep -q "Usage:" && R=0 || R=1
check "No args prints usage line" "$R"
[ "$RC" -ne 0 ] && R=0 || R=1
check "No args exits nonzero" "$R"

# ── 2. Unknown flag → exit 1 ───────────────────────────────
RC=0; "$BIN" --bogus-flag 2>/dev/null || RC=$?
[ "$RC" -ne 0 ] && R=0 || R=1
check "Unknown flag --bogus-flag exits nonzero" "$R"

OUTPUT=$("$BIN" --help 2>&1 || true)
RC=0; "$BIN" --help 2>/dev/null || RC=$?
[ "$RC" -ne 0 ] && R=0 || R=1
check "--help exits nonzero (no help flag)" "$R"
echo "$OUTPUT" | grep -q "Unknown argument" && R=0 || R=1
check "--help prints 'Unknown argument'" "$R"

# ── 3. --role validation ───────────────────────────────────
RC=0; "$BIN" --role banana 2>/dev/null || RC=$?
[ "$RC" -ne 0 ] && R=0 || R=1
check "--role banana exits nonzero" "$R"

# ── 4. Rendezvous fail-closed: missing --room ─────────────
RC=0; "$BIN" --role offerer --signal rendezvous --session s1 --to bob 2>/dev/null || RC=$?
[ "$RC" -ne 0 ] && R=0 || R=1
check "Rendezvous without --room exits nonzero" "$R"

OUTPUT=$("$BIN" --role offerer --signal rendezvous --session s1 --to bob 2>&1 || true)
echo "$OUTPUT" | grep -q "requires --room" && R=0 || R=1
check "Rendezvous without --room mentions --room" "$R"

# ── 5. Rendezvous fail-closed: missing --session ─────────
RC=0; "$BIN" --role offerer --signal rendezvous --room r1 --to bob 2>/dev/null || RC=$?
[ "$RC" -ne 0 ] && R=0 || R=1
check "Rendezvous without --session exits nonzero" "$R"

OUTPUT=$("$BIN" --role offerer --signal rendezvous --room r1 --to bob 2>&1 || true)
echo "$OUTPUT" | grep -q "requires --session" && R=0 || R=1
check "Rendezvous without --session mentions --session" "$R"

# ── 6. Rendezvous fail-closed: offerer missing --to ──────
RC=0; "$BIN" --role offerer --signal rendezvous --room r1 --session s1 2>/dev/null || RC=$?
[ "$RC" -ne 0 ] && R=0 || R=1
check "Rendezvous offerer without --to exits nonzero" "$R"

OUTPUT=$("$BIN" --role offerer --signal rendezvous --room r1 --session s1 2>&1 || true)
echo "$OUTPUT" | grep -q "requires --to" && R=0 || R=1
check "Rendezvous offerer without --to mentions --to" "$R"

# ── 7. Rendezvous fail-closed: answerer missing --expect-peer
RC=0; "$BIN" --role answerer --signal rendezvous --room r1 --session s1 2>/dev/null || RC=$?
[ "$RC" -ne 0 ] && R=0 || R=1
check "Rendezvous answerer without --expect-peer exits nonzero" "$R"

OUTPUT=$("$BIN" --role answerer --signal rendezvous --room r1 --session s1 2>&1 || true)
echo "$OUTPUT" | grep -q "requires --expect-peer" && R=0 || R=1
check "Rendezvous answerer without --expect-peer mentions --expect-peer" "$R"

# ── 8. --network-scope validation ─────────────────────────
RC=0; "$BIN" --role offerer --network-scope banana 2>/dev/null || RC=$?
[ "$RC" -ne 0 ] && R=0 || R=1
check "--network-scope banana exits nonzero" "$R"

# ── 9. --phase-timeout-secs validation ────────────────────
RC=0; "$BIN" --role offerer --phase-timeout-secs 0 2>/dev/null || RC=$?
[ "$RC" -ne 0 ] && R=0 || R=1
check "--phase-timeout-secs 0 exits nonzero" "$R"

RC=0; "$BIN" --role offerer --phase-timeout-secs abc 2>/dev/null || RC=$?
[ "$RC" -ne 0 ] && R=0 || R=1
check "--phase-timeout-secs abc exits nonzero" "$R"

# ── 10. --signal validation ───────────────────────────────
RC=0; "$BIN" --role offerer --signal banana 2>/dev/null || RC=$?
[ "$RC" -ne 0 ] && R=0 || R=1
check "--signal banana exits nonzero" "$R"

# ── 11. Startup banner format ─────────────────────────────
# File mode offerer with nonexistent signal dir — will eventually time out,
# but the startup banner should appear immediately. We capture stderr, kill
# the process after 1 second, and check the banner.
OUTPUT=$( ("$BIN" --role offerer --offer /dev/null --answer /dev/null \
    --phase-timeout-secs 2 2>&1 || true) | head -5 )
echo "$OUTPUT" | grep -q "\[bolt-daemon\]" && R=0 || R=1
check "Startup banner contains [bolt-daemon]" "$R"
echo "$OUTPUT" | grep -q "signal=File" && R=0 || R=1
check "Startup banner shows signal=File" "$R"
echo "$OUTPUT" | grep -q "scope=Lan" && R=0 || R=1
check "Startup banner shows scope=Lan (default)" "$R"

# ── Summary ───────────────────────────────────────────────
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -ne 0 ]; then
    echo "FAIL"
    exit 1
fi

echo "PASS — all contract checks verified"
exit 0
