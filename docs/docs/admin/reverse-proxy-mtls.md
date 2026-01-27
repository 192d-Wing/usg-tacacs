# Management API Reverse Proxy with mTLS

This guide covers deploying the TACACS+ Management API behind a reverse proxy with mutual TLS (mTLS) authentication.

## Architecture

```
┌─────────────┐    HTTPS/mTLS     ┌──────────────┐    HTTP      ┌─────────────────┐
│   Client    │ ───────────────> │    Nginx/    │ ──────────> │  TACACS+ API    │
│ (with cert) │   (TLS + cert)    │   HAProxy    │  (header)   │  (localhost)    │
└─────────────┘                   └──────────────┘             └─────────────────┘
                                         │
                                         ├─ TLS termination
                                         ├─ Client cert validation
                                         └─ Extract CN → X-User-CN header
```

## Why Use a Reverse Proxy?

**Industry Best Practice:**
- ✅ Separation of concerns (TLS vs application logic)
- ✅ Flexibility (load balancing, SSL offloading)
- ✅ Standard pattern (Kubernetes, Istio, service meshes)
- ✅ Centralized certificate management
- ✅ Rate limiting and DDoS protection

## NIST SP 800-53 Controls

| Control | Name | Implementation |
|---------|------|----------------|
| **SC-8** | Transmission Confidentiality | TLS 1.3 with strong ciphers |
| **IA-3** | Device Identification | Client certificate validation |
| **IA-5(2)** | PKI-Based Authentication | mTLS with client certificates |
| **AC-3** | Access Enforcement | Certificate CN mapped to RBAC roles |

---

## Nginx Configuration

### Prerequisites

```bash
# Install Nginx with SSL support
apt-get install nginx-full

# Create certificate directories
mkdir -p /etc/nginx/certs/api
chmod 700 /etc/nginx/certs/api
```

### Generate Certificates

```bash
# Server certificate for API (signed by your CA)
openssl req -new -x509 -days 365 -nodes \
  -out /etc/nginx/certs/api/server.pem \
  -keyout /etc/nginx/certs/api/server-key.pem \
  -subj "/CN=api.tacacs.internal"

# Client CA bundle (for validating client certificates)
cp /path/to/client-ca.pem /etc/nginx/certs/api/client-ca.pem

# Set permissions
chmod 600 /etc/nginx/certs/api/*.pem
```

### Nginx Configuration File

**File:** `/etc/nginx/sites-available/tacacs-api`

```nginx
# NIST SC-8: TLS 1.3 with strong ciphers only
upstream tacacs_api {
    server 127.0.0.1:8080;
    keepalive 32;
}

server {
    listen 8443 ssl http2;
    server_name api.tacacs.internal;

    # NIST SC-8: TLS configuration
    ssl_certificate /etc/nginx/certs/api/server.pem;
    ssl_certificate_key /etc/nginx/certs/api/server-key.pem;
    ssl_protocols TLSv1.3;
    ssl_ciphers 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256';
    ssl_prefer_server_ciphers on;

    # NIST IA-3: Client certificate authentication (mTLS)
    ssl_client_certificate /etc/nginx/certs/api/client-ca.pem;
    ssl_verify_client on;
    ssl_verify_depth 2;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;

    # Logging for audit (NIST AU-2/AU-12)
    access_log /var/log/nginx/tacacs-api-access.log combined;
    error_log /var/log/nginx/tacacs-api-error.log warn;

    location /api/ {
        # NIST AC-3: Extract client certificate CN and pass to backend
        proxy_set_header X-User-CN $ssl_client_s_dn_cn;

        # Standard proxy headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Proxy configuration
        proxy_pass http://tacacs_api;
        proxy_http_version 1.1;
        proxy_set_header Connection "";

        # Timeouts
        proxy_connect_timeout 5s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }

    # Health check endpoint (no client cert required)
    location /health {
        ssl_verify_client optional;
        proxy_pass http://tacacs_api/health;
    }
}
```

### Enable and Test

```bash
# Enable site
ln -s /etc/nginx/sites-available/tacacs-api /etc/nginx/sites-enabled/

# Test configuration
nginx -t

# Reload Nginx
systemctl reload nginx
```

---

## HAProxy Configuration

### Prerequisites

```bash
# Install HAProxy 2.4+
apt-get install haproxy

# Create certificate directory
mkdir -p /etc/haproxy/certs
chmod 700 /etc/haproxy/certs
```

### Combine Certificates

HAProxy requires certificate and key in one file:

```bash
cat /path/to/server.pem /path/to/server-key.pem > /etc/haproxy/certs/api.pem
cp /path/to/client-ca.pem /etc/haproxy/certs/client-ca.pem
chmod 600 /etc/haproxy/certs/*.pem
```

### HAProxy Configuration File

**File:** `/etc/haproxy/haproxy.cfg`

```haproxy
global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

    # NIST SC-8: TLS 1.3 only with strong ciphers
    ssl-default-bind-ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
    ssl-default-bind-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
    ssl-default-bind-options ssl-min-ver TLSv1.3 no-tls-tickets

defaults
    log global
    mode http
    option httplog
    option dontlognull
    timeout connect 5s
    timeout client 30s
    timeout server 30s

frontend tacacs_api_frontend
    bind *:8443 ssl crt /etc/haproxy/certs/api.pem ca-file /etc/haproxy/certs/client-ca.pem verify required

    # NIST AC-3: Extract client certificate CN
    http-request set-header X-User-CN %{+Q}[ssl_c_s_dn(cn)]

    # Security headers
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"
    http-response set-header X-Content-Type-Options "nosniff"
    http-response set-header X-Frame-Options "DENY"

    default_backend tacacs_api_backend

backend tacacs_api_backend
    # NIST AU-2: Logging for audit trail
    option httplog

    # Health check
    option httpchk GET /health
    http-check expect status 200

    server tacacs1 127.0.0.1:8080 check inter 5s rise 2 fall 3
```

### Enable and Test

```bash
# Test configuration
haproxy -c -f /etc/haproxy/haproxy.cfg

# Restart HAProxy
systemctl restart haproxy
```

---

## TACACS+ Server Configuration

Start the API server on localhost (no TLS, reverse proxy handles it):

```bash
tacacs-server \
  --api-enabled \
  --api-listen 127.0.0.1:8080 \
  --api-rbac-config /etc/tacacs/rbac.json \
  --listen-tls 0.0.0.0:300 \
  --tls-cert /etc/tacacs/server.pem \
  --tls-key /etc/tacacs/server-key.pem \
  --client-ca /etc/tacacs/client-ca.pem \
  --policy /etc/tacacs/policy.json
```

**RBAC Configuration** (`/etc/tacacs/rbac.json`):

```json
{
  "roles": {
    "admin": ["read:*", "write:*"],
    "operator": ["read:*", "write:sessions"],
    "viewer": ["read:status", "read:metrics"]
  },
  "users": {
    "CN=admin.tacacs.internal": "admin",
    "CN=noc.tacacs.internal": "operator",
    "CN=monitor.tacacs.internal": "viewer"
  }
}
```

---

## Client Certificate Setup

### Generate Client Certificates

```bash
# Generate client key
openssl genrsa -out client.key 2048

# Generate CSR with CN matching RBAC config
openssl req -new -key client.key -out client.csr \
  -subj "/CN=admin.tacacs.internal/O=TACACS/C=US"

# Sign with your CA
openssl x509 -req -in client.csr \
  -CA /path/to/client-ca.pem \
  -CAkey /path/to/client-ca-key.pem \
  -CAcreateserial \
  -out client.pem \
  -days 365 \
  -sha256

# Create PKCS#12 bundle for browsers
openssl pkcs12 -export -out client.p12 \
  -inkey client.key \
  -in client.pem \
  -certfile /path/to/client-ca.pem
```

### Test with curl

```bash
# Test status endpoint
curl --cert client.pem --key client.key \
  --cacert /path/to/server-ca.pem \
  https://api.tacacs.internal:8443/api/v1/status

# Test policy reload
curl -X POST \
  --cert client.pem --key client.key \
  --cacert /path/to/server-ca.pem \
  https://api.tacacs.internal:8443/api/v1/policy/reload

# Test session listing
curl --cert client.pem --key client.key \
  --cacert /path/to/server-ca.pem \
  https://api.tacacs.internal:8443/api/v1/sessions
```

---

## Security Hardening

### 1. Certificate Revocation

**Nginx with CRL:**

```nginx
ssl_client_certificate /etc/nginx/certs/api/client-ca.pem;
ssl_crl /etc/nginx/certs/api/crl.pem;
ssl_verify_client on;
```

**Update CRL periodically:**

```bash
# Download latest CRL
curl -o /etc/nginx/certs/api/crl.pem https://ca.example.com/crl.pem

# Reload Nginx
systemctl reload nginx
```

### 2. Rate Limiting (Nginx)

```nginx
# Define rate limit zone
http {
    limit_req_zone $ssl_client_s_dn_cn zone=api_ratelimit:10m rate=10r/s;
}

server {
    location /api/ {
        limit_req zone=api_ratelimit burst=20 nodelay;
        # ... rest of config
    }
}
```

### 3. IP Allowlisting (HAProxy)

```haproxy
frontend tacacs_api_frontend
    # Only allow from trusted networks
    acl allowed_networks src 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
    http-request deny if !allowed_networks
    # ... rest of config
```

### 4. Audit Logging

**Nginx:**

```nginx
# Custom log format with client cert info
log_format api_audit '$remote_addr - $ssl_client_s_dn_cn [$time_local] '
                     '"$request" $status $body_bytes_sent '
                     '"$http_user_agent" cert_serial=$ssl_client_serial';

access_log /var/log/nginx/tacacs-api-audit.log api_audit;
```

**HAProxy:**

```haproxy
# Detailed logging
option httplog
log-format "%ci:%cp [%tr] %ft %b/%s %TR/%Tw/%Tc/%Tr/%Ta %ST %B %CC %CS %tsc %ac/%fc/%bc/%sc/%rc %sq/%bq %hr %hs {%[ssl_c_s_dn(cn)]} %{+Q}r"
```

---

## Monitoring

### Prometheus Metrics

Monitor reverse proxy metrics alongside API metrics:

**Nginx:**

```bash
# Install nginx-prometheus-exporter
apt-get install prometheus-nginx-exporter

# Configure stub_status
location /nginx_status {
    stub_status;
    allow 127.0.0.1;
    deny all;
}
```

**HAProxy:**

```haproxy
# Enable stats endpoint
listen stats
    bind *:8404
    stats enable
    stats uri /haproxy_stats
    stats refresh 30s
    stats show-legends
    stats show-node
```

### Health Checks

```bash
# Check Nginx backend connectivity
curl -k https://api.tacacs.internal:8443/health

# Check HAProxy stats
curl http://localhost:8404/haproxy_stats
```

---

## Troubleshooting

### Certificate Verification Failures

**Check client certificate:**

```bash
# Verify certificate is valid
openssl x509 -in client.pem -text -noout

# Check CN matches RBAC config
openssl x509 -in client.pem -noout -subject

# Verify certificate chain
openssl verify -CAfile client-ca.pem client.pem
```

**Check Nginx logs:**

```bash
# Check for SSL errors
tail -f /var/log/nginx/tacacs-api-error.log | grep -i ssl

# Check access logs for denied requests
tail -f /var/log/nginx/tacacs-api-access.log | grep " 403 "
```

### RBAC Permission Denials

**Check X-User-CN header:**

```nginx
# Add debug logging
location /api/ {
    add_header X-Debug-CN $ssl_client_s_dn_cn always;
    # ... rest of config
}
```

**Verify RBAC configuration:**

```bash
# Check RBAC config syntax
jq . /etc/tacacs/rbac.json

# Check user-to-role mapping
jq '.users["CN=admin.tacacs.internal"]' /etc/tacacs/rbac.json
```

### Connection Issues

**Test reverse proxy → backend:**

```bash
# From reverse proxy host
curl http://127.0.0.1:8080/api/v1/status \
  -H "X-User-CN: CN=admin.tacacs.internal"
```

**Check firewall rules:**

```bash
# Allow API port
ufw allow 8443/tcp

# Check current rules
ufw status numbered
```

---

## Production Deployment Checklist

- [ ] TLS 1.3 enforced (no TLS 1.2 or lower)
- [ ] Strong ciphers only (AES-256-GCM, ChaCha20-Poly1305)
- [ ] Client certificate validation enabled
- [ ] Certificate revocation (CRL or OCSP) configured
- [ ] Rate limiting configured
- [ ] IP allowlisting applied
- [ ] Audit logging enabled with rotation
- [ ] Monitoring and alerting configured
- [ ] Regular certificate rotation schedule
- [ ] Disaster recovery plan documented

---

## References

- [NIST SP 800-52 Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final) - TLS Guidelines
- [NIST SP 800-57](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final) - Key Management
- [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446) - TLS 1.3
- [Nginx SSL Module](https://nginx.org/en/docs/http/ngx_http_ssl_module.html)
- [HAProxy SSL Configuration](https://www.haproxy.com/documentation/hapee/latest/security/tls/)
