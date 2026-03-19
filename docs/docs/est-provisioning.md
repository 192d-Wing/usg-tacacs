---
icon: lucide/key-round
---

# EST Certificate Provisioning

`usg-tacacs` supports zero-touch certificate provisioning using RFC 7030 EST (Enrollment over Secure Transport). This enables automated certificate lifecycle management without manual certificate distribution.

## Overview

EST integration provides:

- **Bootstrap Enrollment**: Automatic certificate enrollment on first run
- **Automated Renewal**: Certificates renew before expiration based on configurable thresholds
- **Zero-Touch Deployment**: Server starts degraded, enrolls certificates, then becomes ready
- **Monitoring Integration**: Prometheus metrics for certificate expiration and renewal tracking

## Quick Start

### Basic Configuration

The minimal EST configuration requires:

```bash
usg-tacacs-server \
  --est-enabled \
  --est-server-url https://est.example.com/.well-known/est \
  --est-username bootstrap-user \
  --est-password secret123 \
  --est-common-name tacacs-01.internal \
  --listen-tls 0.0.0.0:300 \
  --client-ca /etc/tacacs/client-ca.pem \
  --policy /etc/tacacs/policy.json
```

### Bootstrap Workflow

1. Server starts without certificates
2. Health endpoint returns `200 OK` but ready endpoint returns `503 Service Unavailable`
3. EST enrollment begins in background
4. Once certificates are obtained, ready endpoint returns `200 OK`
5. TLS listener becomes active

## Configuration

### CLI Arguments

All EST configuration can be provided via command-line arguments:

| Argument | Environment Variable | Description | Default |
|----------|---------------------|-------------|---------|
| `--est-enabled` | `EST_ENABLED` | Enable EST provisioning | `false` |
| `--est-server-url` | `EST_SERVER_URL` | EST server URL (e.g., `https://est.example.com/.well-known/est`) | Required |
| `--est-username` | `EST_USERNAME` | HTTP Basic Auth username for bootstrap | Optional |
| `--est-password` | `EST_PASSWORD` | HTTP Basic Auth password | Optional |
| `--est-password-file` | `EST_PASSWORD_FILE` | Path to password file (alternative to `--est-password`) | Optional |
| `--est-client-cert` | `EST_CLIENT_CERT` | Client certificate for mTLS auth (alternative to username/password) | Optional |
| `--est-client-key` | `EST_CLIENT_KEY` | Client private key for mTLS auth | Optional |
| `--est-ca-label` | `EST_CA_LABEL` | CA label for fetching EST CA certificates | Optional |
| `--est-common-name` | `EST_COMMON_NAME` | Common name for certificate (e.g., `tacacs-01.internal`) | Required |
| `--est-organization` | `EST_ORGANIZATION` | Organization name for certificate | Optional |
| `--est-cert-path` | `EST_CERT_PATH` | Path to write enrolled certificate | `/etc/tacacs/server.crt` |
| `--est-key-path` | `EST_KEY_PATH` | Path to write generated private key | `/etc/tacacs/server.key` |
| `--est-ca-cert-path` | `EST_CA_CERT_PATH` | Path to write EST CA certificate | `/etc/tacacs/ca.crt` |
| `--est-renewal-threshold` | `EST_RENEWAL_THRESHOLD` | Renewal threshold percentage (70 = renew when ≤70% time remains) | `70` |
| `--est-renewal-check-interval` | `EST_RENEWAL_CHECK_INTERVAL` | Check interval for renewal in seconds | `3600` (1 hour) |
| `--est-bootstrap-timeout` | `EST_BOOTSTRAP_TIMEOUT` | Bootstrap enrollment timeout in seconds | `300` (5 minutes) |
| `--est-initial-enrollment-required` | `EST_INITIAL_ENROLLMENT_REQUIRED` | Exit on enrollment failure (vs. start degraded) | `false` |

### Environment Variables

All CLI arguments can be provided via environment variables:

```bash
export EST_ENABLED=true
export EST_SERVER_URL=https://est.example.com/.well-known/est
export EST_USERNAME=bootstrap-user
export EST_PASSWORD=secret123
export EST_COMMON_NAME=tacacs-01.internal

usg-tacacs-server --listen-tls 0.0.0.0:300 --client-ca /etc/tacacs/client-ca.pem --policy /etc/tacacs/policy.json
```

### Configuration File

EST can also be configured via the secrets configuration file:

```json
{
  "est": {
    "enabled": true,
    "server_url": "https://est.example.com/.well-known/est",
    "username": "bootstrap-user",
    "password_file": "/etc/tacacs/est-password",
    "common_name": "tacacs-01.internal",
    "organization": "Example Corp",
    "cert_path": "/etc/tacacs/server.crt",
    "key_path": "/etc/tacacs/server.key",
    "ca_cert_path": "/etc/tacacs/ca.crt",
    "renewal_threshold_percent": 70,
    "renewal_check_interval_secs": 3600,
    "bootstrap_timeout_secs": 300,
    "initial_enrollment_required": false
  }
}
```

## Authentication Methods

EST supports two authentication methods for enrollment:

### HTTP Basic Authentication

Used for initial bootstrap enrollment:

```bash
--est-username bootstrap-user \
--est-password secret123
```

Or with password file:

```bash
--est-username bootstrap-user \
--est-password-file /run/secrets/est-password
```

The password file should contain only the password with no trailing newline.

### mTLS Authentication

Used when you already have a client certificate (e.g., manufacturer-issued):

```bash
--est-client-cert /etc/tacacs/est-client.crt \
--est-client-key /etc/tacacs/est-client.key
```

This is useful for:
- Factory-provisioned devices with manufacturer certificates
- Staged enrollment (bootstrap with HTTP Basic, renew with enrolled cert)
- High-security environments requiring certificate-based enrollment

## Certificate Renewal

### Renewal Threshold

The `renewal_threshold_percent` parameter controls when certificates are renewed:

- `70` (default): Renew when ≤70% of time until expiration remains
- `100`: Renew immediately when checked
- `30`: Renew when ≤30% of time remains

**Example**: Certificate expires in 100 days
- 70% threshold: Renews when ≤70 days remain
- 30% threshold: Renews when ≤30 days remain

### Renewal Process

1. Background task checks certificate expiration every `renewal_check_interval_secs`
2. If renewal threshold is met, generates new CSR
3. Calls EST `/simplereenroll` endpoint
4. Writes new certificate to disk
5. Broadcasts `SecretChange::TlsCertificates` event
6. TLS acceptor reloads certificates without downtime

### Manual Renewal Trigger

To force immediate renewal, restart the server. On startup, it checks if renewal is needed.

## Monitoring and Metrics

### Prometheus Metrics

EST integration exports the following Prometheus metrics via `/metrics`:

```prometheus
# Certificate expiration timestamp (Unix seconds)
tacacs_certificate_expiry_timestamp_seconds 1735776000

# Days until certificate expiration
tacacs_certificate_validity_days 45.2

# Certificate renewal attempts by result and source
tacacs_certificate_renewal_total{result="success",source="est"} 3
tacacs_certificate_renewal_total{result="failure",source="est"} 0
```

### Alerting Examples

**Certificate Expiring Soon** (Prometheus AlertManager):

```yaml
groups:
  - name: tacacs_certificates
    interval: 1m
    rules:
      - alert: TacacsCertificateExpiringSoon
        expr: tacacs_certificate_validity_days < 7
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "TACACS+ certificate expires in {{ $value }} days"
          description: "Certificate on {{ $labels.instance }} expires soon"

      - alert: TacacsCertificateExpired
        expr: tacacs_certificate_validity_days <= 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "TACACS+ certificate has expired"
          description: "Certificate on {{ $labels.instance }} is expired"

      - alert: TacacsRenewalFailures
        expr: rate(tacacs_certificate_renewal_total{result="failure"}[5m]) > 0
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "TACACS+ certificate renewal failures detected"
          description: "EST renewal failures on {{ $labels.instance }}"
```

### Health Checks

EST integration affects health endpoint responses:

**During Bootstrap Enrollment**:
```bash
curl http://localhost:8080/health
# Returns: 200 OK

curl http://localhost:8080/ready
# Returns: 503 Service Unavailable (until certificates obtained)
```

**After Successful Enrollment**:
```bash
curl http://localhost:8080/ready
# Returns: 200 OK
```

**Detailed Health Status** (future enhancement):
```bash
curl http://localhost:8080/health/detailed
{
  "status": "ready",
  "certificate_expiry": "2027-02-15T10:30:00Z",
  "certificate_source": "est",
  "est_enabled": true
}
```

## Deployment Scenarios

### Scenario 1: Docker Container with Bootstrap

```dockerfile
FROM tacacs-server:latest

# Copy policy and client CA
COPY policy.json /etc/tacacs/policy.json
COPY client-ca.pem /etc/tacacs/client-ca.pem

# EST credentials via environment
ENV EST_ENABLED=true
ENV EST_SERVER_URL=https://est.internal/.well-known/est
ENV EST_USERNAME=bootstrap
ENV EST_COMMON_NAME=tacacs-prod-01.internal
ENV EST_CERT_PATH=/data/server.crt
ENV EST_KEY_PATH=/data/server.key
ENV EST_CA_CERT_PATH=/data/ca.crt

# Password via secret mount
ENV EST_PASSWORD_FILE=/run/secrets/est-password

CMD ["usg-tacacs-server", \
     "--listen-tls", "0.0.0.0:300", \
     "--client-ca", "/etc/tacacs/client-ca.pem", \
     "--policy", "/etc/tacacs/policy.json"]
```

Mount EST password as Docker secret:

```bash
echo "bootstrap-secret123" | docker secret create est_password -

docker service create \
  --name tacacs-server \
  --secret est_password \
  --publish 49:49 \
  --env EST_PASSWORD_FILE=/run/secrets/est_password \
  tacacs-server:latest
```

### Scenario 2: Kubernetes Deployment

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: tacacs-est-credentials
type: Opaque
stringData:
  password: "bootstrap-secret123"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tacacs-server
spec:
  replicas: 3
  selector:
    matchLabels:
      app: tacacs-server
  template:
    metadata:
      labels:
        app: tacacs-server
    spec:
      containers:
      - name: tacacs-server
        image: tacacs-server:latest
        env:
        - name: EST_ENABLED
          value: "true"
        - name: EST_SERVER_URL
          value: "https://est.internal/.well-known/est"
        - name: EST_USERNAME
          value: "bootstrap"
        - name: EST_PASSWORD
          valueFrom:
            secretKeyRef:
              name: tacacs-est-credentials
              key: password
        - name: EST_COMMON_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: EST_ORGANIZATION
          value: "Example Corp"
        volumeMounts:
        - name: cert-storage
          mountPath: /data
        - name: policy
          mountPath: /etc/tacacs
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
      volumes:
      - name: cert-storage
        emptyDir: {}
      - name: policy
        configMap:
          name: tacacs-policy
```

### Scenario 3: Systemd Service

```ini
# /etc/systemd/system/tacacs-server.service
[Unit]
Description=TACACS+ Server with EST
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=tacacs
Group=tacacs
Restart=always
RestartSec=10

# EST Configuration
Environment="EST_ENABLED=true"
Environment="EST_SERVER_URL=https://est.internal/.well-known/est"
Environment="EST_USERNAME=tacacs-bootstrap"
Environment="EST_PASSWORD_FILE=/etc/tacacs/secrets/est-password"
Environment="EST_COMMON_NAME=tacacs-01.internal"
Environment="EST_CERT_PATH=/var/lib/tacacs/certs/server.crt"
Environment="EST_KEY_PATH=/var/lib/tacacs/certs/server.key"
Environment="EST_CA_CERT_PATH=/var/lib/tacacs/certs/ca.crt"

ExecStart=/usr/local/bin/usg-tacacs-server \
  --listen-tls 0.0.0.0:300 \
  --client-ca /etc/tacacs/client-ca.pem \
  --policy /etc/tacacs/policy.json

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/tacacs/certs

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
# Create directory structure
sudo mkdir -p /var/lib/tacacs/certs /etc/tacacs/secrets
sudo chown -R tacacs:tacacs /var/lib/tacacs

# Store EST password securely
echo -n "bootstrap-secret123" | sudo tee /etc/tacacs/secrets/est-password
sudo chmod 600 /etc/tacacs/secrets/est-password
sudo chown tacacs:tacacs /etc/tacacs/secrets/est-password

# Enable and start service
sudo systemctl enable tacacs-server
sudo systemctl start tacacs-server

# Check status
sudo systemctl status tacacs-server
sudo journalctl -u tacacs-server -f
```

## Troubleshooting

### Bootstrap Enrollment Fails

**Symptom**: Server starts but never becomes ready

**Check logs**:
```bash
grep "EST enrollment" /var/log/tacacs-server.log
```

**Common causes**:

1. **Incorrect EST server URL**
   ```
   ERROR failed to connect to EST server: connection refused
   ```
   Solution: Verify `EST_SERVER_URL` is correct and EST server is reachable

2. **Authentication failure**
   ```
   ERROR EST enrollment failed: HTTP 401 Unauthorized
   ```
   Solution: Check username/password or client certificate credentials

3. **Network timeout**
   ```
   ERROR bootstrap enrollment timeout after 300 seconds
   ```
   Solution: Increase `--est-bootstrap-timeout` or check network connectivity

4. **Invalid CSR**
   ```
   ERROR EST enrollment failed: invalid CSR parameters
   ```
   Solution: Verify `--est-common-name` format is valid

### Certificate Renewal Failures

**Symptom**: Certificate expires and renewal attempts fail

**Check metrics**:
```bash
curl http://localhost:8080/metrics | grep certificate_renewal_total
```

**Common causes**:

1. **EST server unavailable**
   - Solution: Check EST server availability and DNS resolution

2. **Expired authentication credentials**
   - Solution: Update EST username/password or client certificate

3. **Rate limiting**
   - Solution: Adjust `--est-renewal-check-interval` to reduce request frequency

### Permission Errors

**Symptom**:
```
ERROR failed to write certificate: Permission denied
```

**Solution**: Ensure the user running the server has write access to certificate paths:

```bash
# Check current permissions
ls -la /etc/tacacs/

# Fix permissions
sudo chown tacacs:tacacs /etc/tacacs/server.{crt,key}
sudo chmod 600 /etc/tacacs/server.key
sudo chmod 644 /etc/tacacs/server.crt
```

### Verification

**Check certificate was enrolled**:
```bash
# View certificate details
openssl x509 -in /etc/tacacs/server.crt -text -noout

# Check serial number
openssl x509 -in /etc/tacacs/server.crt -serial -noout

# Check expiration
openssl x509 -in /etc/tacacs/server.crt -enddate -noout
```

**Test TLS connection**:
```bash
# Test TLS handshake
openssl s_client -connect localhost:300 \
  -cert /etc/tacacs/client.crt \
  -key /etc/tacacs/client.key \
  -CAfile /etc/tacacs/ca.crt
```

## Security Considerations

### NIST SP 800-53 Controls

EST implementation addresses the following security controls:

| Control | Name | Implementation |
|---------|------|----------------|
| **IA-5** | Authenticator Management | Automated certificate lifecycle with renewal before expiration |
| **SC-17** | PKI Certificates | RFC 7030-compliant enrollment and renewal |
| **SC-12** | Cryptographic Key Management | Private keys generated client-side, never transmitted |
| **CM-3** | Configuration Change Control | Automated provisioning with audit trail |
| **AU-12** | Audit Generation | All EST operations logged with outcomes |

### Best Practices

1. **Secure Password Storage**: Use `--est-password-file` instead of `--est-password` to avoid exposing passwords in process listings

2. **Restrict Certificate Paths**: Ensure private key has 0600 permissions:
   ```bash
   chmod 600 /etc/tacacs/server.key
   chmod 644 /etc/tacacs/server.crt
   ```

3. **Use Separate EST Credentials**: Don't reuse EST bootstrap credentials across multiple servers

4. **Monitor Renewal**: Set up alerts for renewal failures and certificate expiration

5. **Staged Rollout**: Test EST enrollment in non-production before deploying to production

6. **Network Segmentation**: Place EST server on management network separate from production

7. **Certificate Validation**: Verify EST server certificate chain to prevent MITM attacks

8. **Renewal Threshold**: Set renewal threshold high enough (70%+) to allow time for troubleshooting

## Integration with OpenBao PKI

EST can be used alongside OpenBao PKI for different certificate types:

- **EST**: Server TLS certificates for network device authentication
- **OpenBao PKI**: Internal certificates for secrets management

Example configuration using both:

```bash
usg-tacacs-server \
  --est-enabled \
  --est-server-url https://est.internal/.well-known/est \
  --est-username bootstrap \
  --est-password secret123 \
  --est-common-name tacacs-01.internal \
  --openbao-enabled \
  --openbao-address https://openbao.internal:8200 \
  --openbao-role-id-file /etc/tacacs/openbao-role-id \
  --openbao-secret-id-file /etc/tacacs/openbao-secret-id
```

This configuration:
- Uses EST for TLS server certificates (public-facing)
- Uses OpenBao for secrets management (internal keys, passwords)

## References

- [RFC 7030: Enrollment over Secure Transport](https://datatracker.ietf.org/doc/html/rfc7030)
- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [usg-est-client Library](https://gitlab.com/192d-wing/usg-est-client)
- [TLS Configuration Guide](./tls.md)
- [Operations Guide](./operations.md)
