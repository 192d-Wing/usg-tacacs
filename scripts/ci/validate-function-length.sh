#!/bin/bash
# NASA Power of 10 Rule #4: Function Length Validation
# All functions must be ≤60 lines
#
# Usage: ./scripts/ci/validate-function-length.sh [--all] [function_name] [file_path] [max_lines]
#
# Modes:
#   --all           Scan all .rs files in crates/ directory for violations
#   [function_name] Check a specific function (default: handle_connection)
#
# Arguments (single function mode):
#   function_name: Name of the function to validate (default: handle_connection)
#   file_path:     Path to the source file (default: crates/tacacs-server/src/server.rs)
#   max_lines:     Maximum allowed lines (default: 60)

set -e

MAX_LINES="${MAX_LINES:-60}"

# Temp file for accumulating violations (avoids subshell variable issues)
VIOLATIONS_FILE=$(mktemp)
trap "rm -f $VIOLATIONS_FILE" EXIT

# Function to measure a single function's length using brace matching
measure_function_length() {
    local file="$1"
    local start_line="$2"

    local line_count=0
    local brace_count=0
    local found_open=false

    while IFS= read -r line; do
        line_count=$((line_count + 1))

        # Count opening braces
        local open=$(echo "$line" | grep -o '{' | wc -l | tr -d ' ')
        brace_count=$((brace_count + open))

        if [ "$brace_count" -gt 0 ]; then
            found_open=true
        fi

        # Count closing braces
        local close=$(echo "$line" | grep -o '}' | wc -l | tr -d ' ')
        brace_count=$((brace_count - close))

        # Function ends when braces balance
        if [ "$found_open" = true ] && [ "$brace_count" -eq 0 ]; then
            echo "$line_count"
            return 0
        fi
    done < <(tail -n +"$start_line" "$file")

    echo "0"
    return 1
}

# Function to check a single specific function
check_single_function() {
    local function_name="$1"
    local file_path="$2"
    local max_lines="$3"

    echo "=== NASA Power of 10 Rule #4: Function Length Validation ==="
    echo "Rule: All functions must be ≤${max_lines} lines"
    echo ""
    echo "=== Checking ${function_name} function in ${file_path} ==="

    # Find the function start line
    local start_line=$(grep -n "^async fn ${function_name}\|^fn ${function_name}\|^pub async fn ${function_name}\|^pub fn ${function_name}\|^    pub async fn ${function_name}\|^    pub fn ${function_name}\|^    async fn ${function_name}\|^    fn ${function_name}" "$file_path" | head -1 | cut -d: -f1)

    if [ -z "$start_line" ]; then
        echo "❌ ERROR: Could not find ${function_name} function in ${file_path}"
        exit 1
    fi

    echo "Found function at line ${start_line}"

    local line_count=$(measure_function_length "$file_path" "$start_line")

    if [ "$line_count" -eq 0 ]; then
        echo "⚠️ WARNING: Could not determine function end (brace matching failed)"
        exit 1
    fi

    echo "${function_name} function length: ${line_count} lines"

    if [ "$line_count" -le "$max_lines" ]; then
        echo "✅ PASS: ${function_name} is ${line_count} lines (≤${max_lines} line target)"
        exit 0
    else
        echo "❌ FAIL: ${function_name} is ${line_count} lines (exceeds ${max_lines} line limit)"
        exit 1
    fi
}

# Function to scan all files for violations
scan_all_functions() {
    local max_lines="${1:-60}"
    local search_path="${2:-crates}"

    echo "=== NASA Power of 10 Rule #4: Comprehensive Function Length Validation ==="
    echo "Rule: All functions must be ≤${max_lines} lines"
    echo "Scanning: ${search_path}/**/*.rs"
    echo ""

    local total_functions=0

    # Clear violations file
    > "$VIOLATIONS_FILE"

    # Find all .rs files, excluding test files and build artifacts
    for file in $(find "$search_path" -name "*.rs" -type f 2>/dev/null | sort); do
        # Skip test files and generated code
        if [[ "$file" == *"/tests/"* ]] || [[ "$file" == *"/target/"* ]] || [[ "$file" == *"_test.rs" ]]; then
            continue
        fi

        # Find the #[cfg(test)] line to exclude test code within files
        local test_line=$(grep -n "^#\[cfg(test)\]" "$file" 2>/dev/null | head -1 | cut -d: -f1)
        if [ -z "$test_line" ]; then
            test_line=999999
        fi

        # Find all function definitions in the file (before test section)
        # Match: fn name, pub fn name, async fn name, pub async fn name, pub(crate) fn name, etc.
        while IFS=: read -r line_num line_content; do
            # Skip empty lines
            [ -z "$line_num" ] && continue

            # Skip if this function is in the test section
            if [ "$line_num" -ge "$test_line" ]; then
                continue
            fi

            # Extract function name
            local func_name=$(echo "$line_content" | sed -E 's/.*fn ([a-zA-Z_][a-zA-Z0-9_]*).*/\1/')

            if [ -z "$func_name" ] || [ "$func_name" = "$line_content" ]; then
                continue
            fi

            total_functions=$((total_functions + 1))

            # Measure function length
            local length=$(measure_function_length "$file" "$line_num")

            if [ "$length" -gt "$max_lines" ]; then
                local relative_path="${file#./}"
                echo "  ❌ ${relative_path}:${line_num} - ${func_name}() is ${length} lines" >> "$VIOLATIONS_FILE"
            fi
        done < <(head -n "$test_line" "$file" | grep -n "^\s*\(pub\s\+\)\?\(pub(\w\+)\s\+\)\?\(async\s\+\)\?fn\s\+[a-zA-Z_]" 2>/dev/null || true)

    done

    local total_violations=$(wc -l < "$VIOLATIONS_FILE" | tr -d ' ')

    echo "Scanned ${total_functions} functions"
    echo ""

    if [ "$total_violations" -gt 0 ]; then
        echo "Found ${total_violations} function(s) exceeding ${max_lines} lines:"
        echo ""
        cat "$VIOLATIONS_FILE"
        echo ""
        echo "❌ FAIL: ${total_violations} functions exceed the ${max_lines} line limit"
        echo ""
        echo "To fix violations:"
        echo "  1. Extract helper functions for logical sub-tasks"
        echo "  2. Use early returns to reduce nesting"
        echo "  3. Move complex conditionals to separate functions"
        exit 1
    else
        echo "✅ PASS: All ${total_functions} functions are ≤${max_lines} lines"
        exit 0
    fi
}

# Main entry point
if [ "$1" = "--all" ]; then
    max_lines="${2:-60}"
    search_path="${3:-crates}"
    scan_all_functions "$max_lines" "$search_path"
else
    FUNCTION_NAME="${1:-handle_connection}"
    FILE_PATH="${2:-crates/tacacs-server/src/server.rs}"
    MAX_LINES="${3:-60}"
    check_single_function "$FUNCTION_NAME" "$FILE_PATH" "$MAX_LINES"
fi
