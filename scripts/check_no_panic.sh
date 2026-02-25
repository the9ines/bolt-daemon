#!/usr/bin/env bash
# CI durability guard: reject unwrap()/expect() in production code.
#
# Scans src/ for .unwrap() and .expect( outside of #[cfg(test)] modules.
# Exits non-zero if any are found.
#
# Usage:
#   scripts/check_no_panic.sh
#
# This script requires no network, no extra dependencies, and is deterministic.

VIOLATIONS=""

for f in $(find src -name '*.rs' -type f | sort); do
    # Find the first #[cfg(test)] line number (0 if none)
    test_line=$(grep -n '#\[cfg(test)\]' "$f" 2>/dev/null | head -1 | cut -d: -f1)
    test_line="${test_line:-0}"

    # Check each unwrap()/expect() occurrence
    while IFS=: read -r line content; do
        if [ "$test_line" -eq 0 ] || [ "$line" -lt "$test_line" ]; then
            echo "FAIL: $f:$line:$content"
            VIOLATIONS="yes"
        fi
    done < <(grep -n '\.unwrap()\|\.expect(' "$f" 2>/dev/null || true)
done

if [ -n "$VIOLATIONS" ]; then
    echo ""
    echo "ERROR: unwrap()/expect() found in production code paths."
    echo "Production code must use explicit error handling (?, match, ok_or)."
    echo "unwrap/expect are only permitted inside #[cfg(test)] modules and tests/."
    exit 1
fi

echo "OK: no unwrap()/expect() in production code paths."
exit 0
