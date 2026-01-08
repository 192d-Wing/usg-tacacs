#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Install TACACS+ server binary

set -euo pipefail

echo "=== Installing TACACS+ Server ==="

TACACS_VERSION="${TACACS_VERSION:-latest}"
TACACS_BINARY_URL="${TACACS_BINARY_URL:-}"
INSTALL_DIR="/usr/local/bin"

# Create temporary directory
TEMP_DIR=$(mktemp -d)
trap "rm -rf ${TEMP_DIR}" EXIT

if [ -n "${TACACS_BINARY_URL}" ]; then
    echo "Downloading TACACS+ server from ${TACACS_BINARY_URL}"
    curl -fsSL -o "${TEMP_DIR}/tacacs-server" "${TACACS_BINARY_URL}"
elif [ -f "/tmp/tacacs-server" ]; then
    echo "Using pre-uploaded binary"
    cp /tmp/tacacs-server "${TEMP_DIR}/tacacs-server"
else
    echo "ERROR: No binary URL provided and no pre-uploaded binary found"
    echo "Please provide TACACS_BINARY_URL or upload the binary to /tmp/tacacs-server"
    exit 1
fi

# Verify it's an executable
if ! file "${TEMP_DIR}/tacacs-server" | grep -q "executable"; then
    echo "ERROR: Downloaded file is not an executable"
    exit 1
fi

# Install binary
sudo install -m 0755 -o root -g root "${TEMP_DIR}/tacacs-server" "${INSTALL_DIR}/tacacs-server"

# Verify installation
if ! "${INSTALL_DIR}/tacacs-server" --version; then
    echo "ERROR: Failed to verify installation"
    exit 1
fi

# Create default configuration
sudo tee /etc/tacacs/config.json > /dev/null << 'EOF'
{
  "shared_secret": "CHANGE_ME_IN_PRODUCTION",
  "listen_legacy": "0.0.0.0:49",
  "listen_http": "0.0.0.0:8080",
  "policy_file": "/etc/tacacs/policy.json",
  "ascii": {
    "attempt_limit": 5,
    "user_attempt_limit": 3,
    "pass_attempt_limit": 5,
    "backoff_ms": 100,
    "backoff_max_ms": 5000,
    "lockout_limit": 10
  }
}
EOF

# Create default policy
sudo tee /etc/tacacs/policy.json > /dev/null << 'EOF'
{
  "default_allow": false,
  "rules": [],
  "shell_start": {},
  "allow_raw_server_msg": true,
  "raw_server_msg_allow_prefixes": [],
  "raw_server_msg_deny_prefixes": []
}
EOF

# Set permissions
sudo chown tacacs:tacacs /etc/tacacs/config.json /etc/tacacs/policy.json
sudo chmod 640 /etc/tacacs/config.json /etc/tacacs/policy.json

echo "TACACS+ server ${TACACS_VERSION} installed successfully"
echo "=== Installation Complete ==="
