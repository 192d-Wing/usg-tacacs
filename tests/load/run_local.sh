#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# NIST SP 800-53 Rev5: SA-11 (Developer Testing), SC-5 (DoS Protection Assessment)
#
# Build the tacacs-server binary, start it with load-test-friendly settings on
# a high port (no root needed), run the Python ASCII auth load test, then
# clean up.
#
# Usage:
#   ./run_local.sh [--workers N] [--duration S] [--warmup S] [extra load_test.py args...]
#
# Requires:
#   cargo (Rust toolchain)
#   pip install tacacs_plus psutil
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Load-test server settings (high port avoids root requirement)
TACACS_PORT="${TACACS_PORT:-4949}"
TACACS_SECRET="${TACACS_SECRET:-loadtest-secret}"
METRICS_PORT="${METRICS_PORT:-9090}"
PID_FILE="/tmp/tacacs-load.pid"
LOG_FILE="/tmp/tacacs-load.log"

# Use Homebrew python3.14 where psutil/tacacs_plus are installed.
# The Xcode python3 (3.9) has a separate site-packages and lacks both.
PYTHON="${PYTHON:-python3.14}"

BINARY="${REPO_ROOT}/target/release/usg-tacacs-server"
POLICY="${SCRIPT_DIR}/../../tests/e2e/config/usg-tacacs/policy.json"
SCHEMA="${SCRIPT_DIR}/../../tests/e2e/config/usg-tacacs/policy.schema.json"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

die() { echo "ERROR: $*" >&2; exit 1; }

wait_port() {
    local host="$1" port="$2" label="$3"
    local max=30 i=0
    while ! nc -z "${host}" "${port}" 2>/dev/null; do
        i=$(( i + 1 ))
        [ "${i}" -ge "${max}" ] && die "${label} not ready after ${max}s"
        sleep 1
    done
    echo "  ${label} ready on port ${port}"
}

cleanup() {
    if [ -f "${PID_FILE}" ]; then
        local pid
        pid="$(cat "${PID_FILE}")"
        kill "${pid}" 2>/dev/null || true
        rm -f "${PID_FILE}"
        echo "  server (PID ${pid}) stopped"
    fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

echo "=== Building usg-tacacs-server ==="
cargo build --release -p usg-tacacs-server \
    --manifest-path "${REPO_ROOT}/Cargo.toml"

[ -x "${BINARY}" ] || die "binary not found at ${BINARY}"
echo "  binary: ${BINARY}"

# ---------------------------------------------------------------------------
# Start server
# ---------------------------------------------------------------------------

echo ""
echo "=== Starting tacacs-server on port ${TACACS_PORT} ==="

"${BINARY}" \
    --listen-legacy "127.0.0.1:${TACACS_PORT}" \
    --listen-http   "127.0.0.1:${METRICS_PORT}" \
    --secret        "${TACACS_SECRET}" \
    --policy        "${POLICY}" \
    --schema        "${SCHEMA}" \
    --allow-static-credentials \
    --user-password "alice:alice-secret" \
    --user-password "bob:bob-secret" \
    --ascii-lockout-limit    0 \
    --ascii-backoff-ms       0 \
    --ascii-attempt-limit    255 \
    --max-connections-per-ip 1000 \
    --packet-read-timeout-secs 30 \
    --log-format json \
    >"${LOG_FILE}" 2>&1 &

SERVER_PID=$!
echo "${SERVER_PID}" > "${PID_FILE}"
echo "  PID ${SERVER_PID}  log → ${LOG_FILE}"

wait_port 127.0.0.1 "${TACACS_PORT}"   "tacacs"
wait_port 127.0.0.1 "${METRICS_PORT}"  "metrics"

# ---------------------------------------------------------------------------
# Run load test
# ---------------------------------------------------------------------------

echo ""
echo "=== Running load test ==="

"${PYTHON}" "${SCRIPT_DIR}/load_test.py" \
    --host        127.0.0.1 \
    --port        "${TACACS_PORT}" \
    --secret      "${TACACS_SECRET}" \
    --pid         "${SERVER_PID}" \
    --metrics-url "http://127.0.0.1:${METRICS_PORT}/metrics" \
    "$@"
