#!/usr/bin/env bash
# Print copy/paste commands for a two-machine rendezvous smoke test.
#
# Generates commands for --mode smoke with SHA-256 integrity verification.
# For default mode (HELLO_PAYLOAD), use print_two_machine_commands.sh instead.
#
# Usage:
#   bash scripts/print_two_machine_smoke_commands.sh [OPTIONS]
#
# Required:
#   --network-scope <lan|overlay|global>   Network scope
#   --session <string>                     Session discriminator
#   --rendezvous-url <ws://ip:port>        Rendezvous server URL
#
# Optional:
#   --room <string>                Room name (default: test)
#   --bytes <N>                    Payload size in bytes (default: 1048576)
#   --repeat <N>                   Transfer cycles (default: 1)
#   --phase-timeout-secs <secs>    Timeout per phase (default: 30)
#   --peer-a <id>                  Answerer peer ID (default: bob)
#   --peer-b <id>                  Offerer peer ID (default: alice)
#   --json                         Add --json to daemon commands
#   --help                         Show this help
#
# This script does NOT run the daemon. It only prints commands.

set -euo pipefail

# ── Defaults ────────────────────────────────────────────────
NETWORK_SCOPE=""
SESSION=""
ROOM="test"
RENDEZVOUS_URL=""
BYTES="1048576"
REPEAT="1"
TIMEOUT="30"
PEER_A="bob"
PEER_B="alice"
JSON_FLAG=""

# ── Parse args ──────────────────────────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        --network-scope)      NETWORK_SCOPE="$2"; shift 2 ;;
        --session)            SESSION="$2"; shift 2 ;;
        --room)               ROOM="$2"; shift 2 ;;
        --rendezvous-url)     RENDEZVOUS_URL="$2"; shift 2 ;;
        --bytes)              BYTES="$2"; shift 2 ;;
        --repeat)             REPEAT="$2"; shift 2 ;;
        --phase-timeout-secs) TIMEOUT="$2"; shift 2 ;;
        --peer-a)             PEER_A="$2"; shift 2 ;;
        --peer-b)             PEER_B="$2"; shift 2 ;;
        --json)               JSON_FLAG=" --json"; shift ;;
        --help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            echo "Run with --help for usage." >&2
            exit 1
            ;;
    esac
done

# ── Validate required args ──────────────────────────────────
ERRORS=0

if [ -z "$NETWORK_SCOPE" ]; then
    echo "FATAL: --network-scope is required (lan|overlay|global)" >&2
    ERRORS=1
fi

if [ -z "$SESSION" ]; then
    echo "FATAL: --session is required" >&2
    ERRORS=1
fi

if [ -z "$RENDEZVOUS_URL" ]; then
    echo "FATAL: --rendezvous-url is required (e.g., ws://192.168.1.100:3001)" >&2
    ERRORS=1
fi

if [ "$ERRORS" -ne 0 ]; then
    echo "" >&2
    echo "Run with --help for usage." >&2
    exit 1
fi

# ── Validate scope ──────────────────────────────────────────
case "$NETWORK_SCOPE" in
    lan|overlay|global) ;;
    *)
        echo "FATAL: --network-scope must be lan, overlay, or global (got: $NETWORK_SCOPE)" >&2
        exit 1
        ;;
esac

# ── Print ───────────────────────────────────────────────────
cat <<EOF
=== Two-Machine Rendezvous Smoke Commands ===

Mode:     smoke (SHA-256 integrity)
Scope:    $NETWORK_SCOPE
Session:  $SESSION
Room:     $ROOM
Server:   $RENDEZVOUS_URL
Bytes:    $BYTES
Repeat:   $REPEAT
Timeout:  ${TIMEOUT}s
Peer A:   $PEER_A (answerer)
Peer B:   $PEER_B (offerer)

────────────────────────────────────────
Machine A (answerer: $PEER_A)
────────────────────────────────────────

cargo run -- --role answerer --signal rendezvous --mode smoke \\
  --rendezvous-url $RENDEZVOUS_URL \\
  --room $ROOM --session $SESSION \\
  --peer-id $PEER_A --expect-peer $PEER_B \\
  --network-scope $NETWORK_SCOPE --bytes $BYTES --repeat $REPEAT \\
  --phase-timeout-secs $TIMEOUT$JSON_FLAG

────────────────────────────────────────
Machine B (offerer: $PEER_B)
────────────────────────────────────────

cargo run -- --role offerer --signal rendezvous --mode smoke \\
  --rendezvous-url $RENDEZVOUS_URL \\
  --room $ROOM --session $SESSION \\
  --peer-id $PEER_B --to $PEER_A \\
  --network-scope $NETWORK_SCOPE --bytes $BYTES --repeat $REPEAT \\
  --phase-timeout-secs $TIMEOUT$JSON_FLAG

────────────────────────────────────────
Expected: both peers exit 0 with [smoke] result ............. PASS
Exit codes: 0=success, 1=signaling, 2=datachannel, 3=integrity, 4=timeout
EOF
