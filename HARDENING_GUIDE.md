# Production Hardening Guide

**Project:** usg-tacacs TACACS+ Server
**Date:** 2026-01-11
**Audience:** Security Engineers, System Administrators

## Table of Contents

1. [Hardening Overview](#hardening-overview)
2. [Defense in Depth Configuration](#defense-in-depth-configuration)
3. [Network Layer Security](#network-layer-security)
4. [Operating System Hardening](#operating-system-hardening)
5. [Application Security](#application-security)
6. [Cryptographic Hardening](#cryptographic-hardening)
7. [Monitoring and Detection](#monitoring-and-detection)
8. [High-Security Deployment](#high-security-deployment)
9. [Security Validation](#security-validation)

---

## Hardening Overview

This guide provides configuration recommendations to elevate the usg-tacacs server from STRONG to EXCELLENT security posture, suitable for high-security environments requiring defense in depth.

### Security Baselines

| Environment | TLS Mode | Authentication | Monitoring | OS Hardening |
|-------------|----------|----------------|------------|--------------|
| **Development** | TLS 1.3 | Local users | Basic logs | Standard |
| **Staging** | TLS 1.3 + mTLS | LDAPS | Prometheus | Enhanced |
| **Production** | TLS 1.3 + mTLS | LDAPS + MFA | Full SIEM | Maximum |
| **High-Security** | TLS 1.3 + mTLS + Allowlist | LDAPS + Hardware MFA | SIEM + Anomaly Detection | Maximum + Audit |

---

## Defense in Depth Configuration

### Layer 1: Network Perimeter

**Objective:** Prevent unauthorized network access

```bash
#!/bin/bash
# /usr/local/bin/tacacs-network-hardening.sh

# 1. Firewall - Only allow specific NAD networks
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# TACACS+ port - NAD network only
iptables -A INPUT -p tcp --dport 49 \
  -s 10.0.0.0/24 \
  -m state --state NEW \
  -m recent --name tacacs_conn --set \
  -m recent --name tacacs_conn --update --seconds 60 --hitcount 100 -j DROP \
  -j ACCEPT

# Management API - Admin network + localhost only
iptables -A INPUT -p tcp --dport 8080 \
  -s 10.0.1.0/24 \
  -m state --state NEW \
  -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 \
  -s 127.0.0.1 \
  -j ACCEPT

# Metrics - Monitoring server only
iptables -A INPUT -p tcp --dport 9090 \
  -s 10.0.2.100 \
  -m state --state NEW \
  -j ACCEPT

# SSH - Admin network only (if needed)
iptables -A INPUT -p tcp --dport 22 \
  -s 10.0.1.0/24 \
  -m state --state NEW \
  -j ACCEPT

# ICMP rate limiting
iptables -A INPUT -p icmp --icmp-type echo-request \
  -m limit --limit 1/s \
  -j ACCEPT

# Log dropped packets (for intrusion detection)
iptables -A INPUT -m limit --limit 5/min -j LOG \
  --log-prefix "iptables-dropped: " --log-level 4

# Save rules
iptables-save > /etc/iptables/rules.v4
```

### Layer 2: Application Access Control

**Objective:** Restrict access to authorized devices only

```bash
# Extract CNs from all authorized NAD certificates
for cert in /etc/tacacs/nads/*.crt; do
  openssl x509 -in "$cert" -noout -subject | \
    sed 's/.*CN = \([^,]*\).*/\1/'
done > /etc/tacacs/allowed-clients.txt

# Start server with CN allowlist
./tacacs-server \
  --tls-cert /etc/tacacs/certs/server.crt \
  --tls-key /etc/tacacs/certs/server.key \
  --tls-client-ca /etc/tacacs/certs/ca-bundle.crt \
  --tls-client-cn-file /etc/tacacs/allowed-clients.txt \
  ...
```

### Layer 3: Authentication Hardening

**Objective:** Strong multi-factor authentication

```bash
# Enhanced LDAP configuration with group restrictions
./tacacs-server \
  --ldap-url ldaps://ldap.example.com \
  --ldap-bind-dn "cn=tacacs,ou=services,dc=example,dc=com" \
  --ldap-bind-password-file /etc/tacacs/secrets/ldap-password \
  --ldap-base-dn "ou=users,dc=example,dc=com" \
  --ldap-search-filter "(&(uid={username})(memberOf=cn=network-admins,ou=groups,dc=example,dc=com))" \
  ...

# Note: This restricts authentication to users in the "network-admins" group
```

### Layer 4: Session Management

**Objective:** Strict session limits and timeouts

```bash
./tacacs-server \
  # Global limits
  --max-sessions 500 \
  --max-sessions-per-ip 10 \
  \
  # Aggressive timeouts
  --idle-timeout 300 \
  --keepalive-timeout 60 \
  \
  # Brute force protection (strict)
  --ascii-login-attempts 3 \
  --ascii-username-attempts 3 \
  --ascii-password-attempts 3 \
  --ascii-base-delay 2000 \
  --ascii-backoff-factor 3.0 \
  --ascii-max-delay 60000 \
  ...
```

### Layer 5: Audit and Monitoring

**Objective:** Comprehensive security event logging

```bash
# Enable structured JSON logging for SIEM ingestion
export RUST_LOG="tacacs_server=info"
export LOG_FORMAT="json"  # If supported

./tacacs-server \
  --api-listen 127.0.0.1:8080 \
  --metrics-listen 127.0.0.1:9090 \
  ...

# Configure rsyslog to forward to SIEM
cat > /etc/rsyslog.d/30-tacacs-siem.conf <<'EOF'
if $programname == 'tacacs-server' then {
  action(
    type="omfwd"
    target="siem.example.com"
    port="514"
    protocol="tcp"
    queue.type="LinkedList"
    queue.size="50000"
    queue.discardmark="45000"
    queue.filename="tacacs_siem"
    queue.maxdiskspace="500m"
    queue.saveonshutdown="on"
    action.resumeRetryCount="-1"
    action.reportSuspension="on"
    action.reportSuspensionContinuation="on"
  )
}
EOF
```

---

## Network Layer Security

### IP Allowlist/Blocklist Implementation

**Create IP filter configuration:**

```yaml
# /etc/tacacs/ip-filter.yaml

# Allowlist mode: Only these networks can connect
mode: allowlist

allowed_networks:
  # Production NAD network
  - 10.0.0.0/24
  - 10.1.0.0/24

  # DR site NADs
  - 10.100.0.0/24

  # Management for testing
  - 10.0.1.100/32

# Blocklist for known malicious IPs
blocked_ips:
  - 192.0.2.100  # Example blocked IP
  - 198.51.100.0/24  # Example blocked range

# Logging
log_blocked: true
log_allowed: false  # Too noisy for production
```

**Implement using iptables ipset:**

```bash
#!/bin/bash
# /usr/local/bin/tacacs-ip-filter-apply.sh

# Create ipset for allowlist
ipset create tacacs_allowlist hash:net

# Load allowed networks
cat <<EOF | while read network; do
  ipset add tacacs_allowlist $network
done
10.0.0.0/24
10.1.0.0/24
10.100.0.0/24
10.0.1.100/32
EOF

# Create ipset for blocklist
ipset create tacacs_blocklist hash:net

# Load blocked IPs
ipset add tacacs_blocklist 192.0.2.100
ipset add tacacs_blocklist 198.51.100.0/24

# Apply firewall rules
iptables -I INPUT 1 -p tcp --dport 49 -m set --match-set tacacs_blocklist src -j DROP
iptables -I INPUT 2 -p tcp --dport 49 -m set --match-set tacacs_allowlist src -j ACCEPT
iptables -A INPUT -p tcp --dport 49 -j DROP

# Make persistent
ipset save > /etc/ipset.conf
iptables-save > /etc/iptables/rules.v4
```

### DDoS Protection

```bash
# /etc/sysctl.d/99-tacacs-ddos-protection.conf

# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096

# Connection tracking
net.netfilter.nf_conntrack_max = 1000000
net.netfilter.nf_conntrack_tcp_timeout_established = 600

# Rate limiting
net.ipv4.icmp_ratelimit = 100
net.ipv4.icmp_msgs_per_sec = 50

# IP spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable IP source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.secure_redirects = 0

# Enable bad error message protection
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Apply settings
sysctl -p /etc/sysctl.d/99-tacacs-ddos-protection.conf
```

### Network Segmentation

**Recommended topology:**

```
┌─────────────────────────────────────────────┐
│ Management Network (10.0.1.0/24)            │
│  - Admin workstations                       │
│  - Monitoring server                        │
│  - SIEM                                     │
│  - Backup server                            │
└──────────────┬──────────────────────────────┘
               │ eth1: 10.0.1.10
               │
        ┌──────▼───────┐
        │  TACACS+     │
        │  Server      │
        │  (Dual NIC)  │
        └──────┬───────┘
               │ eth0: 10.0.0.10
               │
┌──────────────▼──────────────────────────────┐
│ NAD Network (10.0.0.0/24)                   │
│  - Routers (10.0.0.1-10.0.0.50)            │
│  - Switches (10.0.0.51-10.0.0.100)         │
│  - Firewalls (10.0.0.101-10.0.0.150)       │
└─────────────────────────────────────────────┘
```

**Interface configuration:**

```bash
# /etc/network/interfaces

# NAD-facing interface (TACACS+ protocol)
auto eth0
iface eth0 inet static
    address 10.0.0.10
    netmask 255.255.255.0
    # No default gateway on this interface

# Management interface (API, metrics, SSH)
auto eth1
iface eth1 inet static
    address 10.0.1.10
    netmask 255.255.255.0
    gateway 10.0.1.1
```

---

## Operating System Hardening

### Minimal OS Installation

**Debian/Ubuntu:**

```bash
# Install minimal system
debootstrap --variant=minbase stable /mnt/target http://deb.debian.org/debian/

# Install only required packages
apt install --no-install-recommends \
  systemd \
  openssh-server \
  iptables \
  rsyslog \
  ca-certificates \
  curl \
  prometheus-node-exporter

# Remove unnecessary packages
apt remove --purge \
  x11-common \
  bluetooth \
  avahi-daemon \
  cups

# Disable unnecessary services
systemctl disable bluetooth
systemctl disable avahi-daemon
systemctl disable cups
```

**RHEL/CentOS:**

```bash
# Minimal installation profile during install

# Remove unnecessary packages
yum remove \
  abrt \
  cups \
  avahi \
  bluetooth

# Disable unnecessary services
systemctl disable bluetooth
systemctl disable avahi-daemon
systemctl disable cups
```

### Kernel Hardening

```bash
# /etc/sysctl.d/99-tacacs-kernel-hardening.conf

# Kernel hardening
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.unprivileged_bpf_disabled = 1
kernel.unprivileged_userns_clone = 0
kernel.yama.ptrace_scope = 2

# Core dumps disabled
kernel.core_uses_pid = 1
kernel.core_pattern = |/bin/false

# Address space layout randomization
kernel.randomize_va_space = 2

# Restrict kernel logs
kernel.printk = 3 3 3 3

# Apply
sysctl -p /etc/sysctl.d/99-tacacs-kernel-hardening.conf
```

### SELinux Mandatory Access Control

**Enable SELinux enforcing mode:**

```bash
# /etc/selinux/config
SELINUX=enforcing
SELINUXTYPE=targeted

# Reboot to apply
reboot

# Verify after reboot
sestatus
# Expected: SELinux status: enabled, Current mode: enforcing
```

**Create custom SELinux policy:**

```bash
#!/bin/bash
# /usr/local/bin/tacacs-selinux-policy.sh

# Generate policy from audit log
ausearch -c tacacs-server --raw | audit2allow -M tacacs-server

# Review policy (IMPORTANT - manually verify!)
cat tacacs-server.te

# Example policy content:
cat > tacacs-server.te <<'EOF'
module tacacs-server 1.0;

require {
    type init_t;
    type unreserved_port_t;
    type tacacs_t;
    type tacacs_exec_t;
    type tacacs_var_lib_t;
    class tcp_socket { bind listen };
    class file { read write };
}

# Allow TACACS to bind to ports
allow tacacs_t unreserved_port_t:tcp_socket { bind listen };

# Allow reading configuration
allow tacacs_t tacacs_var_lib_t:file read;
EOF

# Compile and install policy
checkmodule -M -m -o tacacs-server.mod tacacs-server.te
semodule_package -o tacacs-server.pp -m tacacs-server.mod
semodule -i tacacs-server.pp

# Label files
semanage fcontext -a -t tacacs_exec_t "/usr/local/bin/tacacs-server"
semanage fcontext -a -t tacacs_var_lib_t "/etc/tacacs(/.*)?"
restorecon -Rv /usr/local/bin/tacacs-server /etc/tacacs
```

### AppArmor Profile (Alternative to SELinux)

```bash
# /etc/apparmor.d/usr.local.bin.tacacs-server

#include <tunables/global>

/usr/local/bin/tacacs-server {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/openssl>

  # Binary
  /usr/local/bin/tacacs-server mr,

  # Configuration files (read-only)
  /etc/tacacs/** r,

  # Certificates and keys
  /etc/tacacs/certs/*.crt r,
  /etc/tacacs/certs/*.key r,

  # Secrets (read-only)
  /etc/tacacs/secrets/* r,

  # Runtime data
  /var/lib/tacacs/** rw,

  # Logging
  /var/log/tacacs/** rw,

  # Network access
  network inet stream,
  network inet6 stream,

  # Deny everything else
  deny /home/** rw,
  deny /root/** rw,
  deny /tmp/** wx,
}
```

**Load AppArmor profile:**

```bash
# Parse and load profile
apparmor_parser -r /etc/apparmor.d/usr.local.bin.tacacs-server

# Verify profile loaded
aa-status | grep tacacs-server

# Enable on boot
ln -s /etc/apparmor.d/usr.local.bin.tacacs-server \
  /etc/apparmor.d/force-complain/
```

### Filesystem Hardening

```bash
# /etc/fstab - Mount options for security

# Separate partition for logs (if possible)
/dev/sdb1  /var/log  ext4  defaults,nodev,nosuid,noexec  0  2

# Temporary directories with restrictions
tmpfs  /tmp      tmpfs  defaults,nodev,nosuid,noexec,size=1G  0  0
tmpfs  /var/tmp  tmpfs  defaults,nodev,nosuid,noexec,size=512M  0  0

# Configuration directory (read-only remount)
# Note: Remount read-write only during configuration changes
mount -o remount,ro /etc/tacacs
```

---

## Application Security

### Secure Service Configuration

```ini
# /etc/systemd/system/tacacs-server.service
# Maximum security hardening

[Unit]
Description=TACACS+ Authentication Server (Hardened)
Documentation=https://github.com/your-org/usg-tacacs
After=network-online.target
Wants=network-online.target
ConditionPathExists=/etc/tacacs/certs/tacacs-server.key

[Service]
Type=simple
User=tacacs
Group=tacacs

# Capabilities (drop all, add only needed)
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

# Security hardening (maximum)
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectProc=invisible
ProcSubset=pid

# Filesystem restrictions
ReadWritePaths=/var/log/tacacs /var/lib/tacacs
ReadOnlyPaths=/etc/tacacs
InaccessiblePaths=/home /root /boot

# Network restrictions
RestrictAddressFamilies=AF_INET AF_INET6
IPAddressDeny=any
IPAddressAllow=localhost
IPAddressAllow=10.0.0.0/24
IPAddressAllow=10.0.1.0/24

# System call filtering
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @obsolete @debug
SystemCallErrorNumber=EPERM

# Namespace isolation
PrivateMounts=yes
PrivateUsers=yes

# Restrictions
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RemoveIPC=yes

# Resource limits
LimitNOFILE=65536
LimitNPROC=512
MemoryMax=1G
TasksMax=512
CPUQuota=200%

# Restart policy
Restart=always
RestartSec=10s

# Watchdog
WatchdogSec=60s

# Executable
ExecStart=/usr/local/bin/tacacs-server \
  --secret-file /etc/tacacs/secrets/tacacs-secret \
  --policy /etc/tacacs/policy.json \
  --tls-cert /etc/tacacs/certs/tacacs-server.crt \
  --tls-key /etc/tacacs/certs/tacacs-server.key \
  --tls-client-ca /etc/tacacs/certs/ca-bundle.crt \
  --tls-client-cn-file /etc/tacacs/allowed-clients.txt \
  --ldap-url ldaps://ldap.example.com \
  --ldap-bind-dn "cn=tacacs,ou=services,dc=example,dc=com" \
  --ldap-bind-password-file /etc/tacacs/secrets/ldap-password \
  --ldap-base-dn "ou=users,dc=example,dc=com" \
  --api-listen 127.0.0.1:8080 \
  --api-rbac-config /etc/tacacs/rbac.yaml \
  --metrics-listen 127.0.0.1:9090 \
  --max-sessions 500 \
  --max-sessions-per-ip 10 \
  --idle-timeout 300

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=tacacs-server
SyslogFacility=auth

[Install]
WantedBy=multi-user.target
```

### Policy Hardening

```json
{
  "policy_version": "1.0",
  "default_action": "deny",
  "strict_mode": true,

  "rules": [
    {
      "name": "admin-full-access",
      "users": ["network-admin"],
      "groups": ["network-admins"],
      "device_groups": ["routers", "switches", "firewalls"],
      "commands": {
        "allow": [".*"],
        "deny": []
      },
      "action": "permit"
    },
    {
      "name": "readonly-users",
      "users": [],
      "groups": ["network-readonly"],
      "device_groups": ["routers", "switches", "firewalls"],
      "commands": {
        "allow": ["show .*", "display .*"],
        "deny": ["configure", "write", "reload", "shutdown"]
      },
      "action": "permit"
    },
    {
      "name": "deny-dangerous-commands",
      "users": [".*"],
      "groups": [".*"],
      "device_groups": [".*"],
      "commands": {
        "deny": [
          "format.*",
          "erase.*",
          "delete.*flash:.*",
          "reload in.*",
          "shutdown"
        ]
      },
      "action": "deny",
      "priority": 100
    }
  ],

  "audit": {
    "log_all_requests": true,
    "log_denials": true,
    "alert_on_policy_violation": true
  }
}
```

### RBAC Hardening

```yaml
# /etc/tacacs/rbac.yaml - Least privilege RBAC

users:
  # Admins - full access
  admin:
    password: "$argon2id$v=19$m=65536,t=3,p=1$..."
    roles:
      - admin

  # Operators - read sessions, reload policy
  operator:
    password: "$argon2id$v=19$m=65536,t=3,p=1$..."
    roles:
      - operator

  # Monitoring - metrics only
  monitoring:
    password: "$argon2id$v=19$m=65536,t=3,p=1$..."
    roles:
      - metrics-reader

roles:
  admin:
    permissions:
      - sessions:read
      - sessions:write
      - sessions:delete
      - policy:read
      - policy:write
      - metrics:read
      - health:read

  operator:
    permissions:
      - sessions:read
      - policy:read
      - policy:write  # Can reload policy
      - health:read

  metrics-reader:
    permissions:
      - metrics:read
      - health:read

  # Explicit deny for undefined roles
  default:
    permissions: []
```

---

## Cryptographic Hardening

### TLS Configuration Best Practices

```rust
// Recommended TLS configuration in code

use rustls::{ServerConfig, ProtocolVersion, CipherSuite};

fn build_hardened_tls_config() -> ServerConfig {
    let mut config = ServerConfig::new(client_cert_verifier);

    // TLS 1.3 ONLY - no fallback
    config.versions = vec![&rustls::version::TLS13];

    // Cipher suites (ordered by preference)
    config.ciphersuites = vec![
        // AEAD with forward secrecy
        CipherSuite::TLS13_AES_256_GCM_SHA384,
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS13_AES_128_GCM_SHA256,
    ];

    // Require client certificates (mTLS)
    config.client_auth_required = true;

    // Disable session resumption (optional, for maximum security)
    config.ticketer = None;

    config
}
```

### Certificate Hardening

**High-security certificate requirements:**

```bash
# Use ECDSA P-384 for quantum resistance preparation
openssl ecparam -name secp384r1 -genkey -out server.key

# Or RSA 4096-bit minimum
openssl genrsa -out server.key 4096

# Certificate signing request with strong hash
openssl req -new -sha384 \
  -key server.key \
  -out server.csr \
  -config <(cat <<EOF
[req]
default_bits = 4096
prompt = no
default_md = sha384
distinguished_name = dn
req_extensions = req_ext

[dn]
C = US
ST = State
L = City
O = Organization
OU = Network Security
CN = tacacs.example.com

[req_ext]
subjectAltName = @alt_names
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = tacacs.example.com
DNS.2 = tacacs-dr.example.com
IP.1 = 10.0.0.10
IP.2 = 10.100.0.10
EOF
)

# Sign with SHA-384 (minimum)
openssl x509 -req -sha384 \
  -in server.csr \
  -CA ca.crt \
  -CAkey ca.key \
  -CAcreateserial \
  -out server.crt \
  -days 365 \
  -extensions req_ext \
  -extfile server.csr
```

### Secret Management

**Use hardware security module (HSM):**

```bash
#!/bin/bash
# /usr/local/bin/tacacs-hsm-init.sh

# PKCS#11 HSM integration example (YubiHSM, nCipher, etc.)

# Generate key in HSM
pkcs11-tool --module /usr/lib/libykcs11.so \
  --login --pin 123456 \
  --keypairgen --key-type RSA:4096 \
  --label "tacacs-server-key"

# Generate CSR using HSM key
openssl req -new -engine pkcs11 \
  -keyform engine \
  -key "pkcs11:object=tacacs-server-key" \
  -out server.csr

# After CA signing, import certificate to HSM
pkcs11-tool --module /usr/lib/libykcs11.so \
  --login --pin 123456 \
  --write-object server.crt \
  --type cert \
  --label "tacacs-server-cert"
```

**Encrypt secrets at rest:**

```bash
#!/bin/bash
# /usr/local/bin/tacacs-encrypt-secrets.sh

# Use age encryption for secrets
age-keygen -o /etc/tacacs/age-key.txt
chmod 400 /etc/tacacs/age-key.txt

# Encrypt secret file
age -r $(cat /etc/tacacs/age-key.txt | grep public | cut -d: -f2) \
  -o /etc/tacacs/secrets/tacacs-secret.age \
  /etc/tacacs/secrets/tacacs-secret

# Securely delete plaintext
shred -vfz -n 10 /etc/tacacs/secrets/tacacs-secret

# At runtime, decrypt on-the-fly
cat /etc/tacacs/secrets/tacacs-secret.age | \
  age -d -i /etc/tacacs/age-key.txt | \
  ./tacacs-server --secret "$(cat)"
```

---

## Monitoring and Detection

### Security Event Detection Rules

```yaml
# /etc/tacacs/detection-rules.yaml

rules:
  - name: brute-force-detection
    condition: |
      rate(auth_failures) > 10 per minute from same IP
    severity: high
    action:
      - alert: security-team
      - block: source_ip
      - log: siem

  - name: credential-stuffing
    condition: |
      failed_logins > 5 with different usernames from same IP in 60s
    severity: critical
    action:
      - alert: security-team
      - block: source_ip
      - log: siem

  - name: impossible-travel
    condition: |
      successful_auth from IP_A and IP_B where distance(IP_A, IP_B) > 1000km within 1 hour
    severity: high
    action:
      - alert: security-team
      - require: mfa_reauth
      - log: siem

  - name: privilege-escalation-attempt
    condition: |
      authorization_denied for privileged_command and retries > 3 within 5 minutes
    severity: critical
    action:
      - alert: security-team
      - terminate: session
      - log: siem

  - name: suspicious-command-pattern
    condition: |
      commands match regex: "(show.*run|copy.*tftp|reload|format)" in quick succession
    severity: medium
    action:
      - alert: security-team
      - log: siem

  - name: off-hours-access
    condition: |
      authentication between 00:00-06:00 or weekends
    severity: low
    action:
      - alert: security-team
      - log: siem
      - require: justification

  - name: unauthorized-device
    condition: |
      connection from IP not in known_devices list
    severity: high
    action:
      - alert: security-team
      - deny: connection
      - log: siem

  - name: certificate-validation-failure
    condition: |
      tls_error contains "certificate verify failed"
    severity: high
    action:
      - alert: security-team
      - log: siem
      - increment: threat_score for source_ip

  - name: session-hijacking-attempt
    condition: |
      session_id reuse or task_id violation detected
    severity: critical
    action:
      - alert: security-team
      - terminate: session
      - block: source_ip
      - log: siem

  - name: policy-reload-from-untrusted
    condition: |
      policy_reload_request from IP not in admin_network
    severity: critical
    action:
      - alert: security-team
      - deny: request
      - log: siem
```

### Anomaly Detection

```python
#!/usr/bin/env python3
# /usr/local/bin/tacacs-anomaly-detection.py

import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta

# Simple anomaly detection based on baselines
class AnomalyDetector:
    def __init__(self):
        self.baselines = {
            'auth_rate': 100,  # auths per minute
            'failure_rate': 5,  # failures per minute
            'unique_users': 50,  # unique users per hour
            'session_duration': 1800,  # average session seconds
        }

        self.thresholds = {
            'auth_rate_spike': 3.0,  # 3x baseline
            'failure_rate_spike': 5.0,  # 5x baseline
            'new_user_threshold': 10,  # new users in hour
            'long_session': 7200,  # 2 hour session
        }

    def detect_auth_rate_anomaly(self, current_rate):
        """Detect authentication rate spike"""
        if current_rate > self.baselines['auth_rate'] * self.thresholds['auth_rate_spike']:
            return {
                'type': 'auth_rate_spike',
                'severity': 'high',
                'message': f'Auth rate spike: {current_rate}/min (baseline: {self.baselines["auth_rate"]}/min)',
                'recommendation': 'Check for DDoS or legitimate traffic surge'
            }
        return None

    def detect_failure_spike(self, current_failure_rate):
        """Detect authentication failure spike"""
        if current_failure_rate > self.baselines['failure_rate'] * self.thresholds['failure_rate_spike']:
            return {
                'type': 'failure_rate_spike',
                'severity': 'critical',
                'message': f'Failure rate spike: {current_failure_rate}/min (baseline: {self.baselines["failure_rate"]}/min)',
                'recommendation': 'Possible brute force attack - review source IPs'
            }
        return None

    def detect_unusual_access_pattern(self, events):
        """Detect unusual access patterns"""
        anomalies = []

        # Group events by hour
        hourly_users = defaultdict(set)
        for event in events:
            hour = event['timestamp'].hour
            hourly_users[hour].add(event['username'])

        # Detect off-hours activity
        for hour in range(0, 6):  # Midnight to 6 AM
            if len(hourly_users[hour]) > 5:
                anomalies.append({
                    'type': 'off_hours_activity',
                    'severity': 'medium',
                    'message': f'{len(hourly_users[hour])} users active at {hour}:00',
                    'recommendation': 'Verify legitimate after-hours maintenance'
                })

        return anomalies

# Main detection loop
def main():
    detector = AnomalyDetector()

    # Read metrics from stdin (fed by Prometheus or direct query)
    for line in sys.stdin:
        try:
            metric = json.loads(line)

            # Check different anomaly types
            if 'auth_rate' in metric:
                anomaly = detector.detect_auth_rate_anomaly(metric['auth_rate'])
                if anomaly:
                    print(json.dumps(anomaly))

            if 'failure_rate' in metric:
                anomaly = detector.detect_failure_spike(metric['failure_rate'])
                if anomaly:
                    print(json.dumps(anomaly))

        except json.JSONDecodeError:
            continue

if __name__ == '__main__':
    main()
```

---

## High-Security Deployment

### Air-Gapped Environment Configuration

For environments requiring network isolation:

```bash
#!/bin/bash
# /usr/local/bin/tacacs-airgap-setup.sh

echo "=== Air-Gapped TACACS+ Deployment ==="

# 1. Prepare offline installation bundle
mkdir -p /opt/tacacs-airgap/{bin,certs,config,deps}

# 2. Copy binaries (built on internet-connected system)
cp /build/tacacs-server /opt/tacacs-airgap/bin/
chmod 755 /opt/tacacs-airgap/bin/tacacs-server

# 3. Generate certificates (offline CA)
cd /opt/tacacs-airgap/certs
# Use offline root CA to sign certificates
./offline-ca-sign.sh server.csr > server.crt

# 4. Local user database (no LDAP)
cat > /opt/tacacs-airgap/config/users.json <<'EOF'
{
  "users": [
    {
      "username": "admin",
      "password_hash": "$argon2id$v=19$m=65536,t=3,p=1$...",
      "groups": ["admins"]
    },
    {
      "username": "operator",
      "password_hash": "$argon2id$v=19$m=65536,t=3,p=1$...",
      "groups": ["operators"]
    }
  ]
}
EOF

# 5. Start without external dependencies
/opt/tacacs-airgap/bin/tacacs-server \
  --listen 0.0.0.0:49 \
  --tls-cert /opt/tacacs-airgap/certs/server.crt \
  --tls-key /opt/tacacs-airgap/certs/server.key \
  --tls-client-ca /opt/tacacs-airgap/certs/ca-bundle.crt \
  --secret-file /opt/tacacs-airgap/config/secret \
  --policy /opt/tacacs-airgap/config/policy.json \
  --user-file /opt/tacacs-airgap/config/users.json \
  --no-external-logging \
  --metrics-listen 127.0.0.1:9090

echo "Air-gapped deployment complete"
```

### High-Availability Configuration

```bash
#!/bin/bash
# /usr/local/bin/tacacs-ha-setup.sh

# Deploy with Keepalived for HA

# Install keepalived
apt install keepalived

# Configure VRRP
cat > /etc/keepalived/keepalived.conf <<'EOF'
vrrp_instance TACACS_HA {
    state MASTER  # or BACKUP on secondary
    interface eth0
    virtual_router_id 51
    priority 100  # 100 on master, 90 on backup
    advert_int 1

    authentication {
        auth_type PASS
        auth_pass SecurePassword123
    }

    virtual_ipaddress {
        10.0.0.10/24 dev eth0
    }

    notify_master "/usr/local/bin/tacacs-ha-master.sh"
    notify_backup "/usr/local/bin/tacacs-ha-backup.sh"
    notify_fault "/usr/local/bin/tacacs-ha-fault.sh"
}
EOF

# Health check script
cat > /etc/keepalived/check-tacacs.sh <<'EOF'
#!/bin/bash
# Check if TACACS service is healthy
systemctl is-active --quiet tacacs-server && \
  curl -sf http://127.0.0.1:8080/health > /dev/null
exit $?
EOF

chmod +x /etc/keepalived/check-tacacs.sh

# Start services
systemctl enable keepalived
systemctl start keepalived
systemctl enable tacacs-server
systemctl start tacacs-server
```

---

## Security Validation

### Automated Security Audit Script

```bash
#!/bin/bash
# /usr/local/bin/tacacs-security-audit.sh

echo "=== TACACS+ Security Audit ==="
echo "Date: $(date)"
echo ""

SCORE=0
MAX_SCORE=0
FINDINGS=()

check() {
  local name="$1"
  local command="$2"
  local expected="$3"

  MAX_SCORE=$((MAX_SCORE + 1))

  echo -n "Checking $name... "

  if eval "$command" | grep -q "$expected"; then
    echo "✓ PASS"
    SCORE=$((SCORE + 1))
  else
    echo "✗ FAIL"
    FINDINGS+=("$name")
  fi
}

# TLS Configuration
check "TLS 1.3 Only" "openssl s_client -connect localhost:49 -tls1_2 2>&1" "error"
check "Client Certificate Required" "openssl s_client -connect localhost:49 2>&1" "certificate required"

# File Permissions
check "Server Key Permissions" "stat -c %a /etc/tacacs/certs/server.key" "400"
check "Secret File Permissions" "stat -c %a /etc/tacacs/secrets/tacacs-secret" "400"
check "Config Directory Permissions" "stat -c %a /etc/tacacs" "750"

# Service Hardening
check "Service Running as Non-Root" "ps -u tacacs | grep tacacs-server" "tacacs"
check "SELinux Enforcing" "sestatus | grep 'Current mode'" "enforcing"
check "No New Privileges" "systemctl show tacacs-server -p NoNewPrivileges" "yes"
check "Private Tmp" "systemctl show tacacs-server -p PrivateTmp" "yes"

# Network Security
check "Firewall Active" "iptables -L INPUT" "DROP"
check "Port 49 Restricted" "iptables -L INPUT | grep 'dpt:49'" "10.0.0.0/24"

# Monitoring
check "Metrics Endpoint Responding" "curl -sf http://127.0.0.1:9090/metrics" "tacacs_"
check "Health Endpoint Responding" "curl -sf http://127.0.0.1:8080/health" "healthy"

# Certificate Validity
CERT_DAYS=$(( ($(date -d "$(openssl x509 -in /etc/tacacs/certs/server.crt -noout -enddate | cut -d= -f2)" +%s) - $(date +%s)) / 86400 ))
if [ $CERT_DAYS -gt 30 ]; then
  echo "Checking Certificate Expiration... ✓ PASS ($CERT_DAYS days remaining)"
  SCORE=$((SCORE + 1))
else
  echo "Checking Certificate Expiration... ✗ FAIL ($CERT_DAYS days remaining)"
  FINDINGS+=("Certificate Expiration")
fi
MAX_SCORE=$((MAX_SCORE + 1))

# Logging
check "Audit Logging Active" "journalctl -u tacacs-server -n 1" "tacacs-server"
check "SIEM Forwarding" "grep tacacs-server /etc/rsyslog.d/*.conf" "omfwd"

echo ""
echo "=== Audit Results ==="
echo "Score: $SCORE/$MAX_SCORE ($(( 100 * SCORE / MAX_SCORE ))%)"
echo ""

if [ ${#FINDINGS[@]} -gt 0 ]; then
  echo "Failed Checks:"
  for finding in "${FINDINGS[@]}"; do
    echo "  - $finding"
  done
  echo ""
  exit 1
else
  echo "✓ All security checks passed!"
  exit 0
fi
```

### Penetration Testing Checklist

```markdown
# TACACS+ Penetration Test Checklist

## Network Layer
- [ ] Port scan for unexpected open ports
- [ ] Test firewall rules bypass attempts
- [ ] Verify no response on filtered ports
- [ ] Test for banner grabbing information disclosure
- [ ] Attempt connections from unauthorized networks

## TLS/Cryptography
- [ ] Test for TLS downgrade attacks
- [ ] Verify no SSLv3/TLS1.0/TLS1.1 support
- [ ] Test weak cipher suite negotiation
- [ ] Certificate validation bypass attempts
- [ ] Test for NULL cipher acceptance
- [ ] Verify perfect forward secrecy

## Authentication
- [ ] Brute force testing (verify lockout)
- [ ] Credential stuffing attacks
- [ ] Username enumeration attempts
- [ ] Timing attack analysis
- [ ] Session fixation attempts
- [ ] Test authentication bypass vulnerabilities

## Authorization
- [ ] Privilege escalation attempts
- [ ] Policy bypass testing
- [ ] Command injection in authorization strings
- [ ] Test for horizontal privilege escalation

## Session Management
- [ ] Session hijacking attempts
- [ ] Concurrent session limit testing
- [ ] Idle timeout verification
- [ ] Session token prediction
- [ ] Test for session fixation

## Input Validation
- [ ] LDAP injection testing
- [ ] Path traversal in file parameters
- [ ] Command injection in policy strings
- [ ] Buffer overflow attempts
- [ ] Malformed packet handling

## Denial of Service
- [ ] Connection exhaustion testing
- [ ] Memory exhaustion attempts
- [ ] CPU exhaustion via expensive operations
- [ ] Slowloris-style attacks
- [ ] Amplification attack potential

## API Security
- [ ] Authentication bypass on management API
- [ ] Authorization checks on all endpoints
- [ ] CSRF protection verification
- [ ] Input validation on API parameters
- [ ] Rate limiting effectiveness

## Information Disclosure
- [ ] Error message analysis
- [ ] Log file access attempts
- [ ] Configuration file exposure
- [ ] Memory dump analysis
- [ ] Timing attack vectors

## Compliance
- [ ] Verify NIST SP 800-53 control implementation
- [ ] Audit log completeness
- [ ] Cryptographic algorithm compliance
- [ ] Certificate management practices
```

---

## Hardening Validation

After applying all hardening measures, validate with:

```bash
# Run security audit
/usr/local/bin/tacacs-security-audit.sh

# Run penetration tests
/usr/local/bin/tacacs-pentest.sh

# Verify compliance
/usr/local/bin/tacacs-compliance-check.sh

# Load test with hardening active
/usr/local/bin/tacacs-load-test.sh --connections 1000 --duration 300

# Review all findings
cat /var/log/tacacs/security-audit-$(date +%Y%m%d).log
```

**Expected Results:**
- Security audit score: 95%+
- All penetration tests blocked/logged
- Compliance checks: 100% pass
- Load test: < 5% performance degradation

---

## Summary

This hardening guide provides defense-in-depth configuration suitable for high-security environments. Implementation of these measures elevates the security posture from STRONG to EXCELLENT.

**Key Hardening Layers:**
1. Network perimeter filtering
2. Application-level allowlisting
3. Multi-factor authentication
4. Strict session controls
5. Comprehensive monitoring

**Result:** A production-hardened TACACS+ server suitable for environments with stringent security requirements, including government, financial, and critical infrastructure deployments.

---

**Document Version:** 1.0
**Last Updated:** 2026-01-11
**Next Review:** 2026-04-11
