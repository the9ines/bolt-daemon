#!/usr/bin/env bash
# Print copy/paste commands for a two-machine rendezvous smoke test.
#
# Usage:
#   bash scripts/print_two_machine_commands.sh [OPTIONS]
#
# Options:
#   --scope <lan|overlay|global>      Network scope (default: lan)
#   --session <string>                Session discriminator (default: smoke-001)
#   --room <string>                   Room name (default: smoke)
#   --rendezvous-url <url>            Rendezvous server URL (default: ws://MACHINE_A_IP:3001)
#   --offerer-id <string>             Offerer peer ID (default: macbook)
#   --answerer-id <string>            Answerer peer ID (default: mac-studio)
#   --phase-timeout-secs <int>        Timeout per phase (default: 300)
#
# This script does NOT run the daemon. It only prints commands.

set -euo pipefail

# ── Defaults ────────────────────────────────────────────────
SCOPE="lan"
SESSION="smoke-001"
ROOM="smoke"
RENDEZVOUS_URL="ws://MACHINE_A_IP:3001"
OFFERER_ID="macbook"
ANSWERER_ID="mac-studio"
TIMEOUT="300"

# ── Parse args ──────────────────────────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        --scope)          SCOPE="$2"; shift 2 ;;
        --session)        SESSION="$2"; shift 2 ;;
        --room)           ROOM="$2"; shift 2 ;;
        --rendezvous-url) RENDEZVOUS_URL="$2"; shift 2 ;;
        --offerer-id)     OFFERER_ID="$2"; shift 2 ;;
        --answerer-id)    ANSWERER_ID="$2"; shift 2 ;;
        --phase-timeout-secs) TIMEOUT="$2"; shift 2 ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# ── Validate scope ──────────────────────────────────────────
case "$SCOPE" in
    lan|overlay|global) ;;
    *)
        echo "FATAL: --scope must be lan, overlay, or global (got: $SCOPE)" >&2
        exit 1
        ;;
esac

# ── Print ───────────────────────────────────────────────────
DAEMON_PATH="~/Desktop/the9ines.com/bolt-ecosystem/bolt-daemon"

cat <<EOF
=== Two-Machine Smoke Test Commands ===

Scope:    $SCOPE
Session:  $SESSION
Room:     $ROOM
Server:   $RENDEZVOUS_URL
Offerer:  $OFFERER_ID
Answerer: $ANSWERER_ID
Timeout:  ${TIMEOUT}s

────────────────────────────────────────
Machine A (answerer: $ANSWERER_ID)
────────────────────────────────────────

cd $DAEMON_PATH
cargo run -- --role answerer --signal rendezvous \\
  --rendezvous-url $RENDEZVOUS_URL \\
  --room $ROOM --session $SESSION \\
  --peer-id $ANSWERER_ID --expect-peer $OFFERER_ID \\
  --network-scope $SCOPE --phase-timeout-secs $TIMEOUT

────────────────────────────────────────
Machine B (offerer: $OFFERER_ID)
────────────────────────────────────────

cd $DAEMON_PATH
cargo run -- --role offerer --signal rendezvous \\
  --rendezvous-url $RENDEZVOUS_URL \\
  --room $ROOM --session $SESSION \\
  --peer-id $OFFERER_ID --to $ANSWERER_ID \\
  --network-scope $SCOPE --phase-timeout-secs $TIMEOUT

EOF
