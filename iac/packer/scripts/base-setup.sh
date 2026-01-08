#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Base system setup for TACACS+ server golden image

set -euo pipefail

echo "=== Base System Setup ==="

# Detect OS family
if [ -f /etc/redhat-release ]; then
    OS_FAMILY="redhat"
elif [ -f /etc/debian_version ]; then
    OS_FAMILY="debian"
else
    echo "Unsupported OS"
    exit 1
fi

echo "Detected OS family: ${OS_FAMILY}"

# Update system packages
if [ "${OS_FAMILY}" = "redhat" ]; then
    sudo dnf update -y
    sudo dnf install -y \
        curl \
        openssl \
        ca-certificates \
        chrony \
        audit \
        policycoreutils-python-utils
else
    sudo apt-get update
    sudo apt-get upgrade -y
    sudo apt-get install -y \
        curl \
        openssl \
        ca-certificates \
        chrony \
        auditd
fi

# Configure time synchronization
sudo systemctl enable chronyd
sudo systemctl start chronyd

# Configure audit logging
if [ "${OS_FAMILY}" = "redhat" ]; then
    sudo systemctl enable auditd
fi

# Create tacacs user and group
if ! getent group tacacs > /dev/null 2>&1; then
    sudo groupadd --system tacacs
fi

if ! getent passwd tacacs > /dev/null 2>&1; then
    sudo useradd --system \
        --gid tacacs \
        --home-dir /var/lib/tacacs \
        --shell /usr/sbin/nologin \
        --comment "TACACS+ Server" \
        tacacs
fi

# Create required directories
sudo mkdir -p /etc/tacacs/certs
sudo mkdir -p /var/lib/tacacs
sudo mkdir -p /var/log/tacacs

# Set ownership
sudo chown -R tacacs:tacacs /etc/tacacs
sudo chown -R tacacs:tacacs /var/lib/tacacs
sudo chown -R tacacs:tacacs /var/log/tacacs

# Set permissions
sudo chmod 750 /etc/tacacs
sudo chmod 750 /etc/tacacs/certs
sudo chmod 750 /var/lib/tacacs
sudo chmod 750 /var/log/tacacs

echo "=== Base Setup Complete ==="
