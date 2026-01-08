#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Security hardening for TACACS+ server golden image

set -euo pipefail

echo "=== Security Hardening ==="

# Detect OS family
if [ -f /etc/redhat-release ]; then
    OS_FAMILY="redhat"
else
    OS_FAMILY="debian"
fi

# ============================================================================
# SSH Hardening
# ============================================================================

echo "Hardening SSH..."

SSH_CONFIG="/etc/ssh/sshd_config"

# Backup original config
sudo cp "${SSH_CONFIG}" "${SSH_CONFIG}.bak"

# Apply SSH hardening
sudo tee -a "${SSH_CONFIG}" > /dev/null << 'EOF'

# Security hardening (added by Packer)
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 2
AllowAgentForwarding no
AllowTcpForwarding no
EOF

# ============================================================================
# Kernel Parameters
# ============================================================================

echo "Configuring kernel parameters..."

sudo tee /etc/sysctl.d/99-tacacs-security.conf > /dev/null << 'EOF'
# Network security
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1

# IPv6 (disable if not needed)
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Memory protection
kernel.randomize_va_space = 2
kernel.exec-shield = 1
kernel.dmesg_restrict = 1

# Core dumps
fs.suid_dumpable = 0
EOF

sudo sysctl -p /etc/sysctl.d/99-tacacs-security.conf || true

# ============================================================================
# Firewall Configuration
# ============================================================================

echo "Configuring firewall..."

if [ "${OS_FAMILY}" = "redhat" ]; then
    # Enable firewalld
    sudo systemctl enable firewalld
    sudo systemctl start firewalld

    # Add TACACS+ rules
    sudo firewall-cmd --permanent --add-port=49/tcp
    sudo firewall-cmd --permanent --add-port=300/tcp
    sudo firewall-cmd --permanent --add-port=8080/tcp

    # Reload
    sudo firewall-cmd --reload
else
    # Enable UFW
    sudo ufw --force enable

    # Add TACACS+ rules
    sudo ufw allow 49/tcp
    sudo ufw allow 300/tcp
    sudo ufw allow 8080/tcp
    sudo ufw allow 22/tcp
fi

# ============================================================================
# Audit Rules
# ============================================================================

echo "Configuring audit rules..."

sudo tee /etc/audit/rules.d/tacacs.rules > /dev/null << 'EOF'
# TACACS+ specific audit rules
-w /etc/tacacs/ -p wa -k tacacs_config
-w /usr/local/bin/tacacs-server -p x -k tacacs_exec
-a always,exit -F arch=b64 -S connect -F a0!=10 -k tacacs_network

# Login monitoring
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
EOF

# ============================================================================
# File Permissions
# ============================================================================

echo "Setting file permissions..."

# Restrict cron
sudo chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly

# Restrict at
if [ -f /etc/at.deny ]; then
    sudo chmod 600 /etc/at.deny
fi

# ============================================================================
# Remove Unnecessary Packages
# ============================================================================

echo "Removing unnecessary packages..."

if [ "${OS_FAMILY}" = "redhat" ]; then
    sudo dnf remove -y \
        telnet \
        rsh \
        rsh-server \
        tftp \
        tftp-server \
        vsftpd \
        2>/dev/null || true
else
    sudo apt-get remove -y \
        telnet \
        rsh-client \
        rsh-server \
        tftp \
        tftpd \
        vsftpd \
        2>/dev/null || true
fi

# ============================================================================
# Banner Configuration
# ============================================================================

echo "Configuring login banner..."

sudo tee /etc/issue > /dev/null << 'EOF'
***************************************************************************
                     AUTHORIZED ACCESS ONLY
***************************************************************************
This system is for authorized use only. All activities are monitored and
logged. Unauthorized access attempts will be reported to authorities.
***************************************************************************
EOF

sudo tee /etc/issue.net > /dev/null << 'EOF'
***************************************************************************
                     AUTHORIZED ACCESS ONLY
***************************************************************************
EOF

echo "=== Hardening Complete ==="
