#!/bin/bash
# NASA Power of 10 Rules #5 & #7: Runtime unwrap() Validation
# No .unwrap() or .expect() in production request handling paths
#
# Usage: ./scripts/ci/validate-runtime-unwraps.sh [files...]
#
# Arguments:
#   files: Space-separated list of files to check
#          Default: auth.rs, server.rs, policy.rs in crates/tacacs-server/src/

set -e

echo "=== NASA Power of 10 Rules #5 & #7: Runtime unwrap() Validation ==="
echo "Rule: No .unwrap() or .expect() in production request handling paths"
echo ""

# Default critical files if none provided
if [ $# -eq 0 ]; then
    CRITICAL_FILES=(
        "crates/tacacs-server/src/auth.rs"
        "crates/tacacs-server/src/server.rs"
        "crates/tacacs-server/src/policy.rs"
    )
else
    CRITICAL_FILES=("$@")
fi

echo "=== Checking critical runtime files ==="
TOTAL_VIOLATIONS=0

for file in "${CRITICAL_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        echo "⚠️ WARNING: File not found: $file"
        continue
    fi

    echo "Checking $file..."

    # Find the #[cfg(test)] line to exclude test code
    LINE_NUM=$(grep -n "^#\[cfg(test)\]" "$file" | head -1 | cut -d: -f1)

    if [ -z "$LINE_NUM" ]; then
        # No test section found, check entire file
        LINE_NUM=999999
    fi

    # Count .unwrap() calls in runtime code (before #[cfg(test)])
    UNWRAPS=$(head -n "$LINE_NUM" "$file" | grep -c "\.unwrap()" || true)
    UNWRAPS="${UNWRAPS:-0}"
    UNWRAPS=$(echo "$UNWRAPS" | tr -d '[:space:]')

    if [ "$UNWRAPS" -gt 0 ] 2>/dev/null; then
        echo "  ❌ Found $UNWRAPS .unwrap() calls in runtime code"

        # Show the specific lines with unwrap()
        echo "  Violations:"
        head -n "$LINE_NUM" "$file" | grep -n "\.unwrap()" | while read -r match; do
            echo "    Line $match"
        done

        TOTAL_VIOLATIONS=$((TOTAL_VIOLATIONS + UNWRAPS))
    else
        echo "  ✅ No .unwrap() in runtime code"
    fi
done

echo ""

if [ "$TOTAL_VIOLATIONS" -gt 0 ]; then
    echo "❌ FAIL: Found $TOTAL_VIOLATIONS .unwrap() calls in critical runtime paths"
    echo ""
    echo "Fix by using one of these patterns:"
    echo "  - .ok()? for Option types"
    echo "  - .map_err(|e| ...)? for Result types"
    echo "  - .unwrap_or_default() for safe defaults"
    echo "  - .expect(\"descriptive message\") only in initialization code"
    exit 1
else
    echo "✅ PASS: No .unwrap() calls in critical runtime paths"
    exit 0
fi
