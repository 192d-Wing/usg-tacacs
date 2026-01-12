# Secure Deployment Guide

**Project:** usg-tacacs TACACS+ Server
**Date:** 2026-01-11
**Audience:** Security Engineers, System Administrators

## Table of Contents

1. [Pre-Deployment Security Checklist](#pre-deployment-security-checklist)
2. [Certificate Management](#certificate-management)
3. [File Permissions and Ownership](#file-permissions-and-ownership)
4. [Network Security Configuration](#network-security-configuration)
5. [Secure Secrets Management](#secure-secrets-management)
6. [System Hardening](#system-hardening)
7. [Initial Configuration](#initial-configuration)
8. [Deployment Verification](#deployment-verification)
9. [Common Deployment Pitfalls](#common-deployment-pitfalls)

---

## Pre-Deployment Security Checklist

Complete this checklist before deploying to production:

### Infrastructure Security

- [ ] Dedicated server or isolated VM for TACACS+ service
- [ ] Minimal OS installation (no unnecessary packages)
- [ ] OS security patches up to date
- [ ] SELinux/AppArmor enabled and configured
- [ ] Firewall rules configured (see Network Security section)
- [ ] NTP configured for accurate audit timestamps
- [ ] Log aggregation configured (syslog/journald forwarding)
- [ ] Monitoring agent installed (Prometheus node_exporter)
- [ ] Backup system configured for configuration files

### Application Security

- [ ] TLS certificates generated and validated
- [ ] Client certificates prepared for all NADs
- [ ] Secrets generated with sufficient entropy (32+ bytes)
- [ ] Configuration files reviewed for security settings
- [ ] File permissions set correctly (see File Permissions section)
- [ ] RBAC configuration prepared for management API
- [ ] Policy file validated and tested
- [ ] Audit log rotation configured

### Compliance Requirements

- [ ] NIST SP 800-53 control requirements documented
- [ ] Audit logging requirements defined
- [ ] Backup and retention policies established
- [ ] Incident response procedures prepared
- [ ] Change management workflow documented

---

## Certificate Management

### Certificate Architecture

```
Production Certificate Hierarchy:

Root CA (Offline, HSM-protected)
  └─── Intermediate CA (Online, for signing)
         ├─── TACACS+ Server Certificate
         └─── NAD Client Certificates (per device)
```

### Server Certificate Requirements

**Minimum Standards:**

- **Algorithm:** RSA 4096-bit or ECDSA P-384
- **Validity:** 1-2 years maximum
- **Key Usage:** Digital Signature, Key Encipherment
- **Extended Key Usage:** Server Authentication
- **SAN:** DNS name and IP address of server

**Generate Server Certificate:**

```bash
# 1. Generate private key (keep this secure!)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
  -out tacacs-server.key

# 2. Set restrictive permissions immediately
chmod 400 tacacs-server.key
chown tacacs:tacacs tacacs-server.key

# 3. Generate CSR
openssl req -new -key tacacs-server.key \
  -out tacacs-server.csr \
  -subj "/CN=tacacs.example.com/O=Example Inc/C=US" \
  -addext "subjectAltName=DNS:tacacs.example.com,IP:10.0.1.100"

# 4. Sign with your CA (use your CA infrastructure)
# This example shows self-signed for testing ONLY
openssl x509 -req -in tacacs-server.csr \
  -signkey tacacs-server.key \
  -out tacacs-server.crt \
  -days 365 \
  -extensions v3_req \
  -extfile <(cat <<EOF
[v3_req]
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:tacacs.example.com,IP:10.0.1.100
EOF
)

# 5. Verify certificate
openssl x509 -in tacacs-server.crt -text -noout | \
  grep -A 1 "Subject Alternative Name"
```

### Client Certificate Requirements (NADs)

**Minimum Standards:**

- **Algorithm:** RSA 4096-bit or ECDSA P-384
- **Validity:** 1-2 years maximum
- **Key Usage:** Digital Signature, Key Agreement
- **Extended Key Usage:** Client Authentication
- **CN/SAN:** Device FQDN or identifier

**Generate NAD Client Certificate:**

```bash
# 1. Generate key for NAD
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
  -out nad-router01.key

# 2. Generate CSR
openssl req -new -key nad-router01.key \
  -out nad-router01.csr \
  -subj "/CN=router01.example.com/O=Example Inc/C=US"

# 3. Sign with CA
# (Use your CA infrastructure - example shows manual signing)
openssl x509 -req -in nad-router01.csr \
  -CA intermediate-ca.crt -CAkey intermediate-ca.key \
  -out nad-router01.crt \
  -days 365 -CAcreateserial \
  -extensions v3_req \
  -extfile <(cat <<EOF
[v3_req]
keyUsage = digitalSignature, keyAgreement
extendedKeyUsage = clientAuth
subjectAltName = DNS:router01.example.com
EOF
)

# 4. Bundle for distribution to NAD
cat nad-router01.crt intermediate-ca.crt > nad-router01-chain.crt
```

### Certificate Allowlist Configuration

**Use CN/SAN allowlisting for defense in depth:**

```bash
# Extract CN from all authorized NAD certificates
for cert in nads/*.crt; do
  openssl x509 -in "$cert" -noout -subject | \
    sed 's/.*CN=\([^,]*\).*/\1/'
done > allowed-clients.txt

# Start server with allowlist
./tacacs-server \
  --tls-cert server.crt \
  --tls-key server.key \
  --tls-client-ca ca-bundle.crt \
  --tls-client-cn-file allowed-clients.txt
```

### Certificate Expiration Monitoring

**Create monitoring script:**

```bash
#!/bin/bash
# /usr/local/bin/check-cert-expiry.sh

CERT_PATH="/etc/tacacs/certs/tacacs-server.crt"
WARN_DAYS=30
CRIT_DAYS=7

NOT_AFTER=$(openssl x509 -in "$CERT_PATH" -noout -enddate | cut -d= -f2)
EXPIRY_EPOCH=$(date -d "$NOT_AFTER" +%s)
NOW_EPOCH=$(date +%s)
DAYS_LEFT=$(( ($EXPIRY_EPOCH - $NOW_EPOCH) / 86400 ))

if [ $DAYS_LEFT -le $CRIT_DAYS ]; then
  echo "CRITICAL: Certificate expires in $DAYS_LEFT days!"
  exit 2
elif [ $DAYS_LEFT -le $WARN_DAYS ]; then
  echo "WARNING: Certificate expires in $DAYS_LEFT days"
  exit 1
else
  echo "OK: Certificate valid for $DAYS_LEFT days"
  exit 0
fi
```

**Add to cron:**

```bash
# Check certificate daily at 9 AM
0 9 * * * /usr/local/bin/check-cert-expiry.sh || \
  logger -t tacacs-cert -p daemon.err "Certificate expiring soon"
```

---

## File Permissions and Ownership

### Recommended Directory Structure

```
/etc/tacacs/
├── config.yaml              # Main configuration (640, tacacs:tacacs)
├── policy.json              # Authorization policy (640, tacacs:tacacs)
├── rbac.yaml                # RBAC configuration (640, tacacs:tacacs)
├── certs/
│   ├── tacacs-server.crt    # Server certificate (644, tacacs:tacacs)
│   ├── tacacs-server.key    # Server private key (400, tacacs:tacacs) ⚠️
│   └── ca-bundle.crt        # CA certificates (644, tacacs:tacacs)
└── secrets/
    ├── tacacs-secret        # NAD shared secret (400, tacacs:tacacs) ⚠️
    └── ldap-password        # LDAP bind password (400, tacacs:tacacs) ⚠️

/var/lib/tacacs/
└── (runtime data if needed)

/var/log/tacacs/
├── access.log               # Audit logs (640, tacacs:tacacs)
└── error.log                # Error logs (640, tacacs:tacacs)
```

### Set Permissions Script

```bash
#!/bin/bash
# /usr/local/bin/tacacs-set-permissions.sh

TACACS_USER="tacacs"
TACACS_GROUP="tacacs"

# Create dedicated user if not exists
if ! id "$TACACS_USER" >/dev/null 2>&1; then
  useradd -r -s /sbin/nologin -d /var/lib/tacacs "$TACACS_USER"
fi

# Configuration directory
chmod 750 /etc/tacacs
chown -R "$TACACS_USER:$TACACS_GROUP" /etc/tacacs

# Configuration files
chmod 640 /etc/tacacs/config.yaml
chmod 640 /etc/tacacs/policy.json
chmod 640 /etc/tacacs/rbac.yaml

# Certificates
chmod 755 /etc/tacacs/certs
chmod 644 /etc/tacacs/certs/tacacs-server.crt
chmod 644 /etc/tacacs/certs/ca-bundle.crt
chmod 400 /etc/tacacs/certs/tacacs-server.key

# Secrets (most restrictive)
chmod 700 /etc/tacacs/secrets
chmod 400 /etc/tacacs/secrets/*

# Logs
chmod 750 /var/log/tacacs
chmod 640 /var/log/tacacs/*.log

# Runtime directory
chmod 750 /var/lib/tacacs

echo "Permissions set successfully"
```

### Verification

```bash
# Verify no world-readable secrets
find /etc/tacacs -type f \( -perm -004 -o -perm -002 \) \
  -exec ls -la {} \; | grep -E "(secret|key|password)"

# Should return empty - if not, fix permissions immediately!
```

---

## Network Security Configuration

### Firewall Rules (iptables)

```bash
#!/bin/bash
# /etc/tacacs/firewall-rules.sh

# Allow TACACS+ from authorized NAD network only
iptables -A INPUT -p tcp --dport 49 \
  -s 10.0.0.0/24 \
  -m state --state NEW,ESTABLISHED \
  -j ACCEPT

# Allow management API from admin network only
iptables -A INPUT -p tcp --dport 8080 \
  -s 10.0.1.0/24 \
  -m state --state NEW,ESTABLISHED \
  -j ACCEPT

# Allow Prometheus metrics from monitoring server
iptables -A INPUT -p tcp --dport 9090 \
  -s 10.0.2.100 \
  -m state --state NEW,ESTABLISHED \
  -j ACCEPT

# Drop all other inbound to TACACS+ ports
iptables -A INPUT -p tcp --dport 49 -j DROP
iptables -A INPUT -p tcp --dport 8080 -j DROP
iptables -A INPUT -p tcp --dport 9090 -j DROP
```

### Firewall Rules (firewalld)

```bash
# Create rich rules for TACACS+ access
firewall-cmd --permanent --zone=public \
  --add-rich-rule='rule family="ipv4" source address="10.0.0.0/24" port port="49" protocol="tcp" accept'

# Management API (admin network)
firewall-cmd --permanent --zone=public \
  --add-rich-rule='rule family="ipv4" source address="10.0.1.0/24" port port="8080" protocol="tcp" accept'

# Prometheus (monitoring server)
firewall-cmd --permanent --zone=public \
  --add-rich-rule='rule family="ipv4" source address="10.0.2.100" port port="9090" protocol="tcp" accept'

firewall-cmd --reload
```

### Network Isolation

**Recommended Network Segmentation:**

```
Management Network (10.0.1.0/24)
  - Admin workstations
  - Management API access
  - Logging/monitoring servers

NAD Network (10.0.0.0/24)
  - Network devices (routers, switches, firewalls)
  - TACACS+ protocol access only

DMZ/Transit (if applicable)
  - TACACS+ server with dual interfaces
  - One interface to NAD network
  - One interface to management network
```

### TCP Tuning for High-Volume Deployments

```bash
# /etc/sysctl.d/99-tacacs.conf

# Increase connection backlog
net.core.somaxconn = 4096

# TCP keepalive for dead connection detection
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5

# Increase local port range for ephemeral connections
net.ipv4.ip_local_port_range = 32768 60999

# Enable TCP Fast Open (TLS 1.3 compatible)
net.ipv4.tcp_fastopen = 3

# Apply settings
sysctl -p /etc/sysctl.d/99-tacacs.conf
```

---

## Secure Secrets Management

### Secret Generation Best Practices

**Generate cryptographically secure secrets:**

```bash
# TACACS+ NAD shared secret (32 bytes = 256 bits)
openssl rand -base64 32 > /etc/tacacs/secrets/tacacs-secret
chmod 400 /etc/tacacs/secrets/tacacs-secret
chown tacacs:tacacs /etc/tacacs/secrets/tacacs-secret

# Verify entropy
wc -c /etc/tacacs/secrets/tacacs-secret
# Should show 45 bytes (32 bytes + base64 encoding + newline)
```

### Avoiding Common Mistakes

**❌ NEVER do this:**

```bash
# DON'T pass secrets as CLI arguments (visible in process list!)
./tacacs-server --secret "mysecret123"

# DON'T store secrets in environment variables (inherited by children)
export TACACS_SECRET="mysecret123"
./tacacs-server --secret "$TACACS_SECRET"

# DON'T commit secrets to version control
git add secrets/tacacs-secret  # DANGEROUS!
```

**✅ DO this instead:**

```bash
# Use file-based secret provisioning
./tacacs-server --secret-file /etc/tacacs/secrets/tacacs-secret

# Or use secure secret management systems
./tacacs-server --secret-file <(vault kv get -field=secret secret/tacacs/nad-secret)
```

### Integration with Secret Management Systems

**HashiCorp Vault:**

```bash
#!/bin/bash
# /usr/local/bin/tacacs-start-vault.sh

# Authenticate to Vault (use appropriate auth method)
export VAULT_ADDR="https://vault.example.com"
vault login -method=cert \
  -client-cert=/etc/tacacs/vault-client.crt \
  -client-key=/etc/tacacs/vault-client.key

# Fetch secrets and start server
TACACS_SECRET=$(vault kv get -field=secret secret/tacacs/nad-secret)
LDAP_PASSWORD=$(vault kv get -field=password secret/tacacs/ldap-bind)

# Start server with secrets from Vault
./tacacs-server \
  --secret "$TACACS_SECRET" \
  --ldap-bind-password "$LDAP_PASSWORD" \
  --tls-cert /etc/tacacs/certs/server.crt \
  --tls-key /etc/tacacs/certs/server.key \
  --tls-client-ca /etc/tacacs/certs/ca-bundle.crt
```

**AWS Secrets Manager:**

```bash
#!/bin/bash
# Fetch from AWS Secrets Manager
TACACS_SECRET=$(aws secretsmanager get-secret-value \
  --secret-id tacacs/nad-secret \
  --query SecretString --output text)

./tacacs-server --secret "$TACACS_SECRET" ...
```

### Secret Rotation Procedures

**Step 1: Generate new secret**

```bash
openssl rand -base64 32 > /etc/tacacs/secrets/tacacs-secret.new
chmod 400 /etc/tacacs/secrets/tacacs-secret.new
```

**Step 2: Update NADs (gradual rollout)**

```
Day 1: Update 25% of NADs with new secret
Day 2: Update 50% of NADs
Day 3: Update 75% of NADs
Day 4: Update 100% of NADs
```

**Step 3: Switch server to new secret**

```bash
mv /etc/tacacs/secrets/tacacs-secret /etc/tacacs/secrets/tacacs-secret.old
mv /etc/tacacs/secrets/tacacs-secret.new /etc/tacacs/secrets/tacacs-secret

# Reload server configuration
systemctl reload tacacs-server
```

**Step 4: Verify and cleanup**

```bash
# Monitor for authentication failures
journalctl -u tacacs-server -f | grep -i "authentication failed"

# After 24 hours with no issues, securely delete old secret
shred -vfz -n 10 /etc/tacacs/secrets/tacacs-secret.old
```

---

## System Hardening

### SELinux Configuration

**Create custom policy module:**

```bash
# Generate policy from audit logs
grep tacacs /var/log/audit/audit.log | audit2allow -M tacacs-custom

# Review policy (inspect tacacs-custom.te)
cat tacacs-custom.te

# Install policy
semodule -i tacacs-custom.te

# Label files correctly
semanage fcontext -a -t tacacs_exec_t "/usr/local/bin/tacacs-server"
semanage fcontext -a -t tacacs_config_t "/etc/tacacs(/.*)?"
restorecon -Rv /etc/tacacs /usr/local/bin/tacacs-server
```

### systemd Service Hardening

```ini
# /etc/systemd/system/tacacs-server.service

[Unit]
Description=TACACS+ Authentication Server
Documentation=https://github.com/your-org/usg-tacacs
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=tacacs
Group=tacacs

# Executable
ExecStart=/usr/local/bin/tacacs-server \
  --secret-file /etc/tacacs/secrets/tacacs-secret \
  --policy /etc/tacacs/policy.json \
  --tls-cert /etc/tacacs/certs/server.crt \
  --tls-key /etc/tacacs/certs/server.key \
  --tls-client-ca /etc/tacacs/certs/ca-bundle.crt \
  --ldap-url ldaps://ldap.example.com \
  --ldap-bind-dn "cn=tacacs,ou=services,dc=example,dc=com" \
  --ldap-bind-password-file /etc/tacacs/secrets/ldap-password \
  --ldap-base-dn "ou=users,dc=example,dc=com" \
  --api-listen 127.0.0.1:8080 \
  --api-rbac-config /etc/tacacs/rbac.yaml

# Restart on failure
Restart=on-failure
RestartSec=5s

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/tacacs /var/lib/tacacs
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
RemoveIPC=true
PrivateMounts=true

# Resource limits
LimitNOFILE=65536
LimitNPROC=512

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=tacacs-server

[Install]
WantedBy=multi-user.target
```

### Kernel Security Hardening

```bash
# /etc/sysctl.d/99-tacacs-security.conf

# Disable IP forwarding (not a router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Enable source validation (anti-spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP ping requests (optional - may impact monitoring)
# net.ipv4.icmp_echo_ignore_all = 1

# Log suspicious packets
net.ipv4.conf.all.log_martians = 1

# Protect against SYN flood attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048

# Apply settings
sysctl -p /etc/sysctl.d/99-tacacs-security.conf
```

---

## Initial Configuration

### Minimal Production Configuration

```bash
#!/bin/bash
# Start TACACS+ server with secure defaults

/usr/local/bin/tacacs-server \
  # TLS Configuration
  --tls-cert /etc/tacacs/certs/server.crt \
  --tls-key /etc/tacacs/certs/server.key \
  --tls-client-ca /etc/tacacs/certs/ca-bundle.crt \
  --tls-client-cn-file /etc/tacacs/allowed-clients.txt \
  \
  # Authentication
  --secret-file /etc/tacacs/secrets/tacacs-secret \
  --ldap-url ldaps://ldap.example.com \
  --ldap-bind-dn "cn=tacacs,ou=services,dc=example,dc=com" \
  --ldap-bind-password-file /etc/tacacs/secrets/ldap-password \
  --ldap-base-dn "ou=users,dc=example,dc=com" \
  \
  # Authorization
  --policy /etc/tacacs/policy.json \
  \
  # Session Management
  --max-sessions 1000 \
  --max-sessions-per-ip 50 \
  --idle-timeout 300 \
  \
  # Brute Force Protection
  --ascii-login-attempts 3 \
  --ascii-username-attempts 3 \
  --ascii-password-attempts 3 \
  --ascii-base-delay 1000 \
  --ascii-backoff-factor 2.0 \
  --ascii-max-delay 30000 \
  \
  # Management API
  --api-listen 127.0.0.1:8080 \
  --api-rbac-config /etc/tacacs/rbac.yaml \
  \
  # Metrics
  --metrics-listen 127.0.0.1:9090
```

### Configuration Validation

```bash
#!/bin/bash
# /usr/local/bin/tacacs-validate-config.sh

set -e

echo "Validating TACACS+ configuration..."

# Check certificate validity
echo "✓ Checking server certificate..."
openssl x509 -in /etc/tacacs/certs/server.crt -noout -checkend 86400
if [ $? -ne 0 ]; then
  echo "✗ Server certificate expires within 24 hours!"
  exit 1
fi

# Check certificate chain
echo "✓ Verifying certificate chain..."
openssl verify -CAfile /etc/tacacs/certs/ca-bundle.crt \
  /etc/tacacs/certs/server.crt

# Check private key matches certificate
echo "✓ Verifying private key matches certificate..."
CERT_MODULUS=$(openssl x509 -noout -modulus -in /etc/tacacs/certs/server.crt | openssl md5)
KEY_MODULUS=$(openssl rsa -noout -modulus -in /etc/tacacs/certs/server.key | openssl md5)
if [ "$CERT_MODULUS" != "$KEY_MODULUS" ]; then
  echo "✗ Private key does not match certificate!"
  exit 1
fi

# Check file permissions
echo "✓ Checking file permissions..."
if [ $(stat -c %a /etc/tacacs/certs/server.key) != "400" ]; then
  echo "✗ Server private key has incorrect permissions (should be 400)"
  exit 1
fi

if [ $(stat -c %a /etc/tacacs/secrets/tacacs-secret) != "400" ]; then
  echo "✗ TACACS secret has incorrect permissions (should be 400)"
  exit 1
fi

# Check secret entropy
echo "✓ Checking secret strength..."
SECRET_LENGTH=$(wc -c < /etc/tacacs/secrets/tacacs-secret)
if [ $SECRET_LENGTH -lt 32 ]; then
  echo "✗ TACACS secret is too short (< 32 bytes)"
  exit 1
fi

# Validate JSON policy file
echo "✓ Validating policy file..."
jq empty /etc/tacacs/policy.json

# Validate RBAC YAML
echo "✓ Validating RBAC configuration..."
python3 -c "import yaml; yaml.safe_load(open('/etc/tacacs/rbac.yaml'))"

echo "✓ All configuration checks passed!"
```

---

## Deployment Verification

### Post-Deployment Testing

```bash
#!/bin/bash
# /usr/local/bin/tacacs-deployment-test.sh

set -e

TACACS_HOST="tacacs.example.com"
API_URL="https://127.0.0.1:8080"

echo "=== TACACS+ Deployment Verification ==="

# 1. Check service is running
echo "✓ Checking service status..."
systemctl is-active --quiet tacacs-server || {
  echo "✗ Service is not running!"
  exit 1
}

# 2. Check listening ports
echo "✓ Checking listening ports..."
ss -tlnp | grep -q ":49 " || {
  echo "✗ TACACS+ port 49 not listening!"
  exit 1
}
ss -tlnp | grep -q ":8080 " || {
  echo "✗ Management API port 8080 not listening!"
  exit 1
}
ss -tlnp | grep -q ":9090 " || {
  echo "✗ Metrics port 9090 not listening!"
  exit 1
}

# 3. Check TLS handshake
echo "✓ Testing TLS handshake..."
timeout 5 openssl s_client -connect ${TACACS_HOST}:49 \
  -cert /etc/tacacs/test-client.crt \
  -key /etc/tacacs/test-client.key \
  -CAfile /etc/tacacs/certs/ca-bundle.crt \
  </dev/null 2>&1 | grep -q "Verify return code: 0" || {
  echo "✗ TLS handshake failed!"
  exit 1
}

# 4. Check management API health
echo "✓ Checking management API..."
curl -sf ${API_URL}/health || {
  echo "✗ Management API health check failed!"
  exit 1
}

# 5. Check metrics endpoint
echo "✓ Checking metrics endpoint..."
curl -sf http://127.0.0.1:9090/metrics | grep -q "tacacs_" || {
  echo "✗ Metrics endpoint not responding!"
  exit 1
}

# 6. Verify audit logging
echo "✓ Checking audit logs..."
journalctl -u tacacs-server -n 1 --no-pager | grep -q "tacacs-server" || {
  echo "✗ No recent log entries!"
  exit 1
}

# 7. Check resource usage
echo "✓ Checking resource usage..."
MEM_USAGE=$(systemctl show tacacs-server -p MemoryCurrent --value)
if [ $MEM_USAGE -gt $((1024*1024*1024)) ]; then  # 1GB
  echo "⚠ Warning: Memory usage is high: $(($MEM_USAGE / 1024 / 1024)) MB"
fi

echo "✓ All deployment checks passed!"
echo ""
echo "Next steps:"
echo "1. Configure NADs with server certificate and credentials"
echo "2. Test authentication from a NAD device"
echo "3. Review audit logs: journalctl -u tacacs-server -f"
echo "4. Monitor metrics: curl http://127.0.0.1:9090/metrics"
```

### Load Testing

```bash
#!/bin/bash
# Simple connection load test

TACACS_HOST="tacacs.example.com"
TACACS_PORT=49
CONNECTIONS=100

echo "Testing $CONNECTIONS concurrent connections..."

for i in $(seq 1 $CONNECTIONS); do
  (timeout 1 openssl s_client -connect ${TACACS_HOST}:${TACACS_PORT} \
    -cert test-client.crt -key test-client.key \
    -CAfile ca-bundle.crt </dev/null 2>&1 | \
    grep -q "Verify return code: 0" && echo "OK" || echo "FAIL") &
done

wait

echo "Load test complete. Check logs for errors."
```

---

## Common Deployment Pitfalls

### Issue 1: Certificate Validation Failures

**Symptom:** NADs cannot connect, logs show "certificate verify failed"

**Causes:**

- Server certificate expired
- Client certificate not trusted by server CA
- CN/SAN allowlist doesn't include client CN
- Clock skew between server and NAD

**Resolution:**

```bash
# Check server certificate expiration
openssl x509 -in /etc/tacacs/certs/server.crt -noout -dates

# Check client certificate trusted by CA bundle
openssl verify -CAfile /etc/tacacs/certs/ca-bundle.crt client.crt

# Check CN allowlist
cat /etc/tacacs/allowed-clients.txt

# Verify time synchronization
timedatectl status
```

### Issue 2: File Permission Errors

**Symptom:** Server fails to start with "Permission denied" errors

**Causes:**

- Private key not readable by tacacs user
- Config files have incorrect ownership
- SELinux/AppArmor blocking access

**Resolution:**

```bash
# Fix ownership
chown -R tacacs:tacacs /etc/tacacs

# Fix permissions
chmod 400 /etc/tacacs/certs/server.key
chmod 400 /etc/tacacs/secrets/*

# Check SELinux denials
ausearch -m avc -ts recent | grep tacacs

# Temporarily disable SELinux to test (NOT for production!)
# setenforce 0
```

### Issue 3: Connection Limits Exhausted

**Symptom:** New connections rejected, logs show "session limit exceeded"

**Causes:**

- Too many idle connections not timing out
- DDoS or connection exhaustion attack
- Limits set too low for environment

**Resolution:**

```bash
# Check current session count
curl -s http://127.0.0.1:8080/sessions | jq '.total'

# Review idle timeout settings
journalctl -u tacacs-server | grep "idle-timeout"

# Identify top connection sources
curl -s http://127.0.0.1:8080/sessions | \
  jq -r '.sessions[].peer_addr' | cut -d: -f1 | sort | uniq -c | sort -rn

# Increase limits if legitimate traffic
# Edit systemd service file and add:
# --max-sessions 2000 --max-sessions-per-ip 100
```

### Issue 4: LDAP Authentication Failures

**Symptom:** Users cannot authenticate, logs show "LDAP bind failed"

**Causes:**

- LDAP server not reachable
- LDAP bind credentials incorrect
- LDAPS certificate validation failing
- LDAP base DN incorrect

**Resolution:**

```bash
# Test LDAP connectivity
ldapsearch -H ldaps://ldap.example.com \
  -D "cn=tacacs,ou=services,dc=example,dc=com" \
  -W -b "ou=users,dc=example,dc=com" \
  "(uid=testuser)"

# Check LDAP certificate
openssl s_client -connect ldap.example.com:636 -showcerts

# Verify LDAP bind credentials
cat /etc/tacacs/secrets/ldap-password
```

### Issue 5: Brute Force Protection Too Aggressive

**Symptom:** Legitimate users locked out after typos

**Causes:**

- Attempt limits set too low
- Backoff delays too long
- No mechanism to unlock accounts

**Resolution:**

```bash
# Adjust brute force settings (in systemd service file)
# Increase attempts before lockout:
# --ascii-login-attempts 5
# --ascii-username-attempts 5
# --ascii-password-attempts 5

# Reduce max delay:
# --ascii-max-delay 15000  # 15 seconds instead of 30

# Monitor failed attempts
journalctl -u tacacs-server | grep "authentication failed"
```

---

## Security Configuration Checklist

Before going live, verify:

**TLS Configuration:**

- [ ] TLS 1.3 enforced (no fallback)
- [ ] Client certificates required (mTLS)
- [ ] Certificate chain validation enabled
- [ ] CN/SAN allowlist configured
- [ ] Legacy mode disabled (or documented exception)

**Access Control:**

- [ ] Firewall rules restrict access to NAD network only
- [ ] Management API bound to localhost or admin network
- [ ] Metrics endpoint restricted to monitoring server
- [ ] Per-IP connection limits configured
- [ ] Global session limits configured

**Authentication:**

- [ ] LDAPS (not plain LDAP) configured
- [ ] Brute force protection enabled
- [ ] Idle timeout configured (5-15 minutes)
- [ ] Strong secrets generated (32+ bytes)

**Audit & Monitoring:**

- [ ] Structured logging enabled
- [ ] Audit logs forwarded to SIEM
- [ ] Prometheus metrics exposed
- [ ] Alert rules configured
- [ ] Log rotation configured

**System Hardening:**

- [ ] Dedicated service account (non-root)
- [ ] systemd security directives enabled
- [ ] SELinux/AppArmor enforced
- [ ] File permissions restrictive (400 for secrets)
- [ ] Kernel security hardening applied

---

## Next Steps

After successful deployment:

1. **Configure NAD devices** - See [NAD Configuration Guide](NAD_CONFIGURATION.md)
2. **Set up monitoring** - See [Operations Guide](OPERATIONS_SECURITY.md)
3. **Test failover procedures** - Document and practice incident response
4. **Schedule security reviews** - Quarterly configuration audits
5. **Plan for updates** - Establish patch management process

---

## Support and Resources

- **Security Advisories:** Subscribe to project security mailing list
- **Documentation:** <https://github.com/your-org/usg-tacacs/wiki>
- **Issue Tracking:** <https://github.com/your-org/usg-tacacs/issues>
- **Community:** Join Slack/Discord for support

---

**Document Version:** 1.0
**Last Updated:** 2026-01-11
**Next Review:** 2026-04-11
