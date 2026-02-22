#!/usr/bin/env bash
# Start bolt-rendezvous server at the pinned tag.
#
# Verifies the sibling bolt-rendezvous repo exists and is checked out at the
# expected tag commit. Builds and runs the server in the foreground.
#
# Usage:
#   bash scripts/run_rendezvous_pinned.sh
#
# Exit codes:
#   0 — server exited cleanly (Ctrl-C)
#   1 — pre-flight check failed

set -euo pipefail

EXPECTED_TAG="rendezvous-v0.0.3-ci"
EXPECTED_COMMIT="a9c496e174adae9c6a1cc3951e15642c08f22fd1"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DAEMON_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RENDEZVOUS_DIR="$DAEMON_DIR/../bolt-rendezvous"

# ── Pre-flight: sibling repo exists ─────────────────────────
if [ ! -d "$RENDEZVOUS_DIR/.git" ]; then
    echo "FATAL: bolt-rendezvous not found at $RENDEZVOUS_DIR"
    echo ""
    echo "Clone it as a sibling:"
    echo "  cd $(dirname "$DAEMON_DIR")"
    echo "  git clone https://github.com/the9ines/bolt-rendezvous.git"
    exit 1
fi

RENDEZVOUS_DIR="$(cd "$RENDEZVOUS_DIR" && pwd)"

# ── Pre-flight: correct tag commit ──────────────────────────
ACTUAL_COMMIT="$(git -C "$RENDEZVOUS_DIR" rev-parse HEAD)"

if [ "$ACTUAL_COMMIT" != "$EXPECTED_COMMIT" ]; then
    echo "FATAL: bolt-rendezvous is not at $EXPECTED_TAG"
    echo ""
    echo "  Expected commit: $EXPECTED_COMMIT"
    echo "  Actual commit:   $ACTUAL_COMMIT"
    echo ""
    echo "To fix, run:"
    echo "  cd $RENDEZVOUS_DIR"
    echo "  git fetch --tags"
    echo "  git checkout $EXPECTED_TAG"
    exit 1
fi

echo "bolt-rendezvous verified at $EXPECTED_TAG ($EXPECTED_COMMIT)"

# ── Build and run ───────────────────────────────────────────
echo "Building bolt-rendezvous..."
cargo build --manifest-path "$RENDEZVOUS_DIR/Cargo.toml" 2>&1

# Discover binary
if [ -x "$RENDEZVOUS_DIR/target/debug/bolt-rendezvous" ]; then
    BIN="$RENDEZVOUS_DIR/target/debug/bolt-rendezvous"
elif [ -x "$RENDEZVOUS_DIR/target/debug/localbolt-signal" ]; then
    BIN="$RENDEZVOUS_DIR/target/debug/localbolt-signal"
else
    echo "FATAL: no rendezvous binary found in $RENDEZVOUS_DIR/target/debug/"
    exit 1
fi

echo ""
echo "Starting rendezvous server:"
echo "  Binary: $BIN"
echo "  URL:    ws://0.0.0.0:3001"
echo "  Ctrl-C to stop"
echo ""

exec "$BIN"
