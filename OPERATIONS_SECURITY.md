# Operations Security Guide

**Project:** usg-tacacs TACACS+ Server
**Date:** 2026-01-11
**Audience:** Security Operations, DevOps, System Administrators

## Table of Contents

1. [Daily Operations](#daily-operations)
2. [Security Monitoring](#security-monitoring)
3. [Incident Response](#incident-response)
4. [Audit Log Management](#audit-log-management)
5. [Performance Monitoring](#performance-monitoring)
6. [Backup and Recovery](#backup-and-recovery)
7. [Maintenance Procedures](#maintenance-procedures)
8. [Security Event Playbooks](#security-event-playbooks)
9. [Troubleshooting Guide](#troubleshooting-guide)

---

## Daily Operations

### Daily Security Checklist

```bash
#!/bin/bash
# /usr/local/bin/tacacs-daily-checks.sh
# Run daily via cron: 0 8 * * * /usr/local/bin/tacacs-daily-checks.sh

DATE=$(date +%Y-%m-%d)
LOG_FILE="/var/log/tacacs/daily-checks-${DATE}.log"

exec > >(tee -a "$LOG_FILE")
exec 2>&1

echo "=== TACACS+ Daily Security Checks - $DATE ==="

# 1. Service health
echo "[1/8] Checking service status..."
if ! systemctl is-active --quiet tacacs-server; then
  echo "❌ CRITICAL: TACACS+ service is not running!"
  systemctl status tacacs-server
else
  echo "✓ Service is running"
fi

# 2. Certificate expiration
echo "[2/8] Checking certificate expiration..."
CERT_PATH="/etc/tacacs/certs/tacacs-server.crt"
DAYS_LEFT=$(( ($(date -d "$(openssl x509 -in $CERT_PATH -noout -enddate | cut -d= -f2)" +%s) - $(date +%s)) / 86400 ))
if [ $DAYS_LEFT -lt 30 ]; then
  echo "⚠️  WARNING: Certificate expires in $DAYS_LEFT days"
else
  echo "✓ Certificate valid for $DAYS_LEFT days"
fi

# 3. Failed authentication attempts (last 24h)
echo "[3/8] Checking authentication failures..."
FAIL_COUNT=$(journalctl -u tacacs-server --since "24 hours ago" | \
  grep -c "authentication failed" || echo 0)
if [ $FAIL_COUNT -gt 100 ]; then
  echo "⚠️  WARNING: $FAIL_COUNT authentication failures in last 24 hours"
else
  echo "✓ $FAIL_COUNT authentication failures (normal)"
fi

# 4. Session limit usage
echo "[4/8] Checking session limits..."
CURRENT_SESSIONS=$(curl -sf http://127.0.0.1:8080/sessions | jq '.total' || echo 0)
MAX_SESSIONS=$(journalctl -u tacacs-server | grep "max-sessions" | tail -1 | grep -oP 'max-sessions \K\d+' || echo 1000)
USAGE_PERCENT=$((100 * CURRENT_SESSIONS / MAX_SESSIONS))
if [ $USAGE_PERCENT -gt 80 ]; then
  echo "⚠️  WARNING: Session usage at ${USAGE_PERCENT}% (${CURRENT_SESSIONS}/${MAX_SESSIONS})"
else
  echo "✓ Session usage at ${USAGE_PERCENT}% (${CURRENT_SESSIONS}/${MAX_SESSIONS})"
fi

# 5. Disk space for logs
echo "[5/8] Checking log disk space..."
LOG_USAGE=$(df /var/log | tail -1 | awk '{print $5}' | tr -d '%')
if [ $LOG_USAGE -gt 80 ]; then
  echo "⚠️  WARNING: Log partition at ${LOG_USAGE}% capacity"
else
  echo "✓ Log partition at ${LOG_USAGE}% capacity"
fi

# 6. Recent error log entries
echo "[6/8] Checking for critical errors..."
ERROR_COUNT=$(journalctl -u tacacs-server --since "24 hours ago" -p err | wc -l)
if [ $ERROR_COUNT -gt 10 ]; then
  echo "⚠️  WARNING: $ERROR_COUNT error-level log entries in last 24 hours"
  journalctl -u tacacs-server --since "24 hours ago" -p err | tail -5
else
  echo "✓ $ERROR_COUNT error-level log entries (normal)"
fi

# 7. Unusual connection sources
echo "[7/8] Checking for unusual connection sources..."
NEW_IPS=$(comm -13 \
  <(cat /var/lib/tacacs/known-ips.txt 2>/dev/null | sort) \
  <(journalctl -u tacacs-server --since "24 hours ago" | \
    grep -oP 'peer_addr=\K[0-9.]+' | sort -u) | wc -l)
if [ $NEW_IPS -gt 5 ]; then
  echo "⚠️  WARNING: $NEW_IPS new IP addresses seen in last 24 hours"
else
  echo "✓ $NEW_IPS new IP addresses (expected)"
fi

# 8. Resource usage
echo "[8/8] Checking resource usage..."
CPU_USAGE=$(ps -p $(pgrep tacacs-server) -o %cpu --no-headers | awk '{print int($1)}')
MEM_USAGE=$(ps -p $(pgrep tacacs-server) -o %mem --no-headers | awk '{print int($1)}')
if [ $CPU_USAGE -gt 80 ]; then
  echo "⚠️  WARNING: High CPU usage: ${CPU_USAGE}%"
elif [ $MEM_USAGE -gt 80 ]; then
  echo "⚠️  WARNING: High memory usage: ${MEM_USAGE}%"
else
  echo "✓ Resource usage normal (CPU: ${CPU_USAGE}%, MEM: ${MEM_USAGE}%)"
fi

echo ""
echo "=== Daily checks complete ==="
echo "Report saved to: $LOG_FILE"
```

### Scheduled Tasks

Add to `/etc/crontab`:

```bash
# Daily security checks
0 8 * * * root /usr/local/bin/tacacs-daily-checks.sh

# Certificate expiration check
0 9 * * * root /usr/local/bin/check-cert-expiry.sh

# Weekly configuration backup
0 2 * * 0 root /usr/local/bin/tacacs-backup-config.sh

# Monthly security report
0 3 1 * * root /usr/local/bin/tacacs-monthly-report.sh
```

---

## Security Monitoring

### Prometheus Metrics Collection

**Key Metrics to Monitor:**

```yaml
# prometheus.yml - TACACS+ job configuration

scrape_configs:
  - job_name: 'tacacs-server'
    static_configs:
      - targets: ['tacacs.example.com:9090']
    scrape_interval: 15s
    scrape_timeout: 10s

    # TLS configuration for scraping
    scheme: https
    tls_config:
      ca_file: /etc/prometheus/certs/ca.crt
      cert_file: /etc/prometheus/certs/client.crt
      key_file: /etc/prometheus/certs/client.key
```

**Critical Alert Rules:**

```yaml
# /etc/prometheus/rules/tacacs-alerts.yml

groups:
  - name: tacacs_security
    interval: 30s
    rules:
      # Authentication failures
      - alert: HighAuthenticationFailureRate
        expr: rate(tacacs_authn_failure_total[5m]) > 0.1
        for: 2m
        labels:
          severity: warning
          component: tacacs
        annotations:
          summary: "High authentication failure rate"
          description: "{{ $value }} authentication failures per second (threshold: 0.1/s)"

      - alert: BruteForceAttack
        expr: sum(rate(tacacs_authn_failure_total[1m])) by (source_ip) > 1
        for: 1m
        labels:
          severity: critical
          component: tacacs
        annotations:
          summary: "Potential brute force attack from {{ $labels.source_ip }}"
          description: "{{ $value }} failed auth attempts per second from single IP"

      # Session limits
      - alert: SessionLimitApproached
        expr: (tacacs_sessions_active / tacacs_sessions_max) > 0.9
        for: 5m
        labels:
          severity: warning
          component: tacacs
        annotations:
          summary: "Session limit approaching capacity"
          description: "{{ $value | humanizePercentage }} of session limit in use"

      - alert: SessionLimitExceeded
        expr: tacacs_session_limit_exceeded_total > 0
        for: 1m
        labels:
          severity: critical
          component: tacacs
        annotations:
          summary: "Session limit exceeded - connections being rejected"
          description: "{{ $value }} connection attempts rejected due to limits"

      # Per-IP limits
      - alert: PerIpLimitExceeded
        expr: rate(tacacs_per_ip_limit_exceeded_total[5m]) > 0
        for: 2m
        labels:
          severity: warning
          component: tacacs
        annotations:
          summary: "Per-IP connection limits being hit"
          description: "Multiple IPs hitting connection limits"

      # Service availability
      - alert: TacacsServiceDown
        expr: up{job="tacacs-server"} == 0
        for: 1m
        labels:
          severity: critical
          component: tacacs
        annotations:
          summary: "TACACS+ service is down"
          description: "Service has been unreachable for 1 minute"

      # TLS certificate expiration
      - alert: TlsCertificateExpiringSoon
        expr: (tacacs_tls_cert_expiry_timestamp - time()) / 86400 < 30
        for: 1h
        labels:
          severity: warning
          component: tacacs
        annotations:
          summary: "TLS certificate expires in {{ $value | humanizeDuration }}"
          description: "Certificate renewal required soon"

      - alert: TlsCertificateExpiringVeryNearby
        expr: (tacacs_tls_cert_expiry_timestamp - time()) / 86400 < 7
        for: 1h
        labels:
          severity: critical
          component: tacacs
        annotations:
          summary: "TLS certificate expires in {{ $value | humanizeDuration }}"
          description: "URGENT: Certificate renewal required immediately"

      # Policy reload failures
      - alert: PolicyReloadFailed
        expr: increase(tacacs_policy_reload_failures_total[10m]) > 0
        for: 1m
        labels:
          severity: warning
          component: tacacs
        annotations:
          summary: "Policy reload failed"
          description: "Failed to reload policy configuration"

      # Idle session cleanup
      - alert: HighIdleSessionCount
        expr: tacacs_idle_sessions_terminated_total > 50
        for: 5m
        labels:
          severity: info
          component: tacacs
        annotations:
          summary: "High number of idle session terminations"
          description: "{{ $value }} sessions terminated due to inactivity"

      # Resource usage
      - alert: HighMemoryUsage
        expr: process_resident_memory_bytes{job="tacacs-server"} > 1073741824  # 1GB
        for: 10m
        labels:
          severity: warning
          component: tacacs
        annotations:
          summary: "High memory usage"
          description: "Memory usage: {{ $value | humanize1024 }}"

      - alert: HighCpuUsage
        expr: rate(process_cpu_seconds_total{job="tacacs-server"}[5m]) > 0.8
        for: 10m
        labels:
          severity: warning
          component: tacacs
        annotations:
          summary: "High CPU usage"
          description: "CPU usage at {{ $value | humanizePercentage }}"
```

### Grafana Dashboard

**Import this dashboard JSON:**

```json
{
  "dashboard": {
    "title": "TACACS+ Security Overview",
    "panels": [
      {
        "title": "Authentication Success Rate",
        "targets": [
          {
            "expr": "rate(tacacs_authn_success_total[5m])"
          }
        ],
        "type": "graph"
      },
      {
        "title": "Authentication Failures by Method",
        "targets": [
          {
            "expr": "sum(rate(tacacs_authn_failure_total[5m])) by (method)"
          }
        ],
        "type": "graph"
      },
      {
        "title": "Active Sessions",
        "targets": [
          {
            "expr": "tacacs_sessions_active"
          }
        ],
        "type": "gauge",
        "fieldConfig": {
          "max": "tacacs_sessions_max"
        }
      },
      {
        "title": "Top Connection Sources",
        "targets": [
          {
            "expr": "topk(10, count(tacacs_connection_established_total) by (source_ip))"
          }
        ],
        "type": "table"
      },
      {
        "title": "TLS Handshake Failures",
        "targets": [
          {
            "expr": "rate(tacacs_tls_handshake_errors_total[5m])"
          }
        ],
        "type": "graph"
      },
      {
        "title": "Policy Enforcement Decisions",
        "targets": [
          {
            "expr": "sum(rate(tacacs_policy_decisions_total[5m])) by (result)"
          }
        ],
        "type": "pie"
      }
    ]
  }
}
```

### SIEM Integration

**Forwarding logs to Splunk:**

```bash
# /etc/rsyslog.d/30-tacacs.conf

# Forward TACACS+ logs to Splunk
if $programname == 'tacacs-server' then {
  action(
    type="omfwd"
    target="splunk.example.com"
    port="514"
    protocol="tcp"
    queue.type="LinkedList"
    queue.size="10000"
    queue.filename="tacacs_fwd"
    queue.maxdiskspace="100m"
    queue.saveonshutdown="on"
    action.resumeRetryCount="-1"
  )
  stop
}
```

**Splunk Search Queries:**

```spl
# Failed authentication attempts by IP
index=tacacs sourcetype=tacacs_server "authentication failed"
| stats count by peer_addr
| sort -count
| head 20

# Brute force detection
index=tacacs sourcetype=tacacs_server "authentication failed"
| bucket _time span=1m
| stats count by _time, peer_addr
| where count > 10

# Unusual authentication times (outside business hours)
index=tacacs sourcetype=tacacs_server "authentication success"
| eval hour=strftime(_time, "%H")
| where hour < 7 OR hour > 19
| stats count by user, peer_addr

# Policy violation attempts
index=tacacs sourcetype=tacacs_server "authorization denied"
| stats count by user, command
| sort -count

# Certificate validation errors
index=tacacs sourcetype=tacacs_server "certificate verify failed"
| stats count by peer_addr
| sort -count
```

---

## Incident Response

### Security Incident Classification

| Severity | Description | Response Time | Examples |
|----------|-------------|---------------|----------|
| **P0 - Critical** | Service compromise or outage | 15 minutes | Certificate compromise, root access gained, service down |
| **P1 - High** | Active security threat | 1 hour | Brute force attack, unauthorized access attempt, DDoS |
| **P2 - Medium** | Potential security issue | 4 hours | Unusual traffic patterns, configuration drift, expired cert |
| **P3 - Low** | Security observation | 24 hours | Failed authentication spike, policy violation |

### Incident Response Playbook

```bash
#!/bin/bash
# /usr/local/bin/tacacs-incident-response.sh
#
# Usage: tacacs-incident-response.sh [incident-type]
# Types: brute-force, compromise, dos, certificate, policy

INCIDENT_TYPE=$1
INCIDENT_ID="INC-$(date +%Y%m%d-%H%M%S)"
INCIDENT_DIR="/var/log/tacacs/incidents/${INCIDENT_ID}"

mkdir -p "$INCIDENT_DIR"
cd "$INCIDENT_DIR"

echo "=== TACACS+ Incident Response ==="
echo "Incident ID: $INCIDENT_ID"
echo "Type: $INCIDENT_TYPE"
echo "Started: $(date)"
echo ""

# 1. Capture current state
echo "[1/5] Capturing system state..."
systemctl status tacacs-server > systemctl-status.txt
journalctl -u tacacs-server -n 1000 > recent-logs.txt
curl -s http://127.0.0.1:8080/sessions > active-sessions.json
ps aux | grep tacacs > process-info.txt
ss -tulpn | grep -E "(49|8080|9090)" > network-sockets.txt
curl -s http://127.0.0.1:9090/metrics > metrics-snapshot.txt

# 2. Type-specific data collection
case "$INCIDENT_TYPE" in
  brute-force)
    echo "[2/5] Analyzing brute force attack..."
    journalctl -u tacacs-server --since "1 hour ago" | \
      grep "authentication failed" | \
      grep -oP 'peer_addr=\K[0-9.]+' | \
      sort | uniq -c | sort -rn > attack-sources.txt

    echo "Top attack sources:"
    head -10 attack-sources.txt
    ;;

  compromise)
    echo "[2/5] Collecting compromise evidence..."
    journalctl -u tacacs-server --since "24 hours ago" > full-24h-logs.txt
    find /etc/tacacs -type f -exec stat {} \; > file-metadata.txt
    md5sum /usr/local/bin/tacacs-server > binary-hash.txt
    ;;

  dos)
    echo "[2/5] Analyzing DoS attack..."
    ss -tan | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn > connection-sources.txt
    curl -s http://127.0.0.1:8080/sessions | \
      jq -r '.sessions[].peer_addr' | cut -d: -f1 | sort | uniq -c | sort -rn > session-sources.txt
    ;;

  certificate)
    echo "[2/5] Checking certificate status..."
    openssl x509 -in /etc/tacacs/certs/tacacs-server.crt -text -noout > server-cert-details.txt
    openssl verify -CAfile /etc/tacacs/certs/ca-bundle.crt /etc/tacacs/certs/tacacs-server.crt > cert-verification.txt 2>&1
    ;;

  *)
    echo "[2/5] Generic data collection..."
    ;;
esac

# 3. Identify affected entities
echo "[3/5] Identifying affected users/devices..."
journalctl -u tacacs-server --since "1 hour ago" | \
  grep -oP 'user=\K[^,]+' | sort -u > affected-users.txt
journalctl -u tacacs-server --since "1 hour ago" | \
  grep -oP 'peer_addr=\K[0-9.]+' | sort -u > affected-ips.txt

# 4. Generate initial report
echo "[4/5] Generating incident report..."
cat > incident-report.txt <<EOF
=== TACACS+ Security Incident Report ===

Incident ID: $INCIDENT_ID
Type: $INCIDENT_TYPE
Detection Time: $(date)
Responder: $(whoami)

SYSTEM STATE:
- Service Status: $(systemctl is-active tacacs-server)
- Active Sessions: $(curl -s http://127.0.0.1:8080/sessions | jq '.total')
- Affected Users: $(wc -l < affected-users.txt)
- Affected IPs: $(wc -l < affected-ips.txt)

TIMELINE:
$(journalctl -u tacacs-server --since "1 hour ago" | tail -20)

NEXT STEPS:
1. Review collected evidence in: $INCIDENT_DIR
2. Determine containment strategy
3. Execute remediation plan
4. Document lessons learned

EOF

cat incident-report.txt

echo ""
echo "[5/5] Incident response data collection complete"
echo "Evidence directory: $INCIDENT_DIR"
echo ""
echo "Recommended actions:"
case "$INCIDENT_TYPE" in
  brute-force)
    echo "- Block attacking IPs at firewall"
    echo "- Increase backoff delays temporarily"
    echo "- Verify no accounts compromised"
    ;;
  compromise)
    echo "- Rotate all secrets immediately"
    echo "- Revoke/reissue certificates"
    echo "- Review audit logs for unauthorized changes"
    echo "- Consider taking server offline pending investigation"
    ;;
  dos)
    echo "- Implement rate limiting at firewall"
    echo "- Reduce per-IP connection limits"
    echo "- Contact ISP if volumetric attack"
    ;;
  certificate)
    echo "- Verify certificate validity"
    echo "- Check certificate revocation status"
    echo "- Renew certificate if needed"
    ;;
esac
```

### Emergency Procedures

**Block an attacking IP:**

```bash
#!/bin/bash
# Block IP at firewall level
ATTACK_IP="$1"

if [ -z "$ATTACK_IP" ]; then
  echo "Usage: $0 <IP_ADDRESS>"
  exit 1
fi

echo "Blocking $ATTACK_IP at firewall..."

# iptables
iptables -I INPUT 1 -s "$ATTACK_IP" -j DROP
iptables-save > /etc/iptables/rules.v4

# firewalld
firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$ATTACK_IP' reject"
firewall-cmd --reload

echo "IP $ATTACK_IP blocked successfully"
logger -t tacacs-security "Blocked attacking IP: $ATTACK_IP"
```

**Emergency service shutdown:**

```bash
#!/bin/bash
# Emergency shutdown with evidence preservation

REASON="$1"

if [ -z "$REASON" ]; then
  echo "Usage: $0 '<reason for shutdown>'"
  exit 1
fi

echo "EMERGENCY SHUTDOWN INITIATED"
echo "Reason: $REASON"
echo "Time: $(date)"

# Capture final state
SNAPSHOT_DIR="/var/log/tacacs/emergency-shutdown-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$SNAPSHOT_DIR"

journalctl -u tacacs-server -n 5000 > "$SNAPSHOT_DIR/final-logs.txt"
curl -s http://127.0.0.1:8080/sessions > "$SNAPSHOT_DIR/final-sessions.json"
curl -s http://127.0.0.1:9090/metrics > "$SNAPSHOT_DIR/final-metrics.txt"

# Stop service
systemctl stop tacacs-server

# Log event
logger -t tacacs-security "EMERGENCY SHUTDOWN: $REASON"

echo "Service stopped. Evidence preserved in: $SNAPSHOT_DIR"
echo "IMPORTANT: Follow incident response procedures before restart"
```

---

## Audit Log Management

### Log Rotation Configuration

```bash
# /etc/logrotate.d/tacacs-server

/var/log/tacacs/*.log {
    daily
    rotate 90
    compress
    delaycompress
    notifempty
    missingok
    copytruncate
    create 0640 tacacs tacacs

    # Archive old logs to long-term storage
    postrotate
        /usr/local/bin/tacacs-archive-logs.sh
    endscript
}
```

### Log Archival Script

```bash
#!/bin/bash
# /usr/local/bin/tacacs-archive-logs.sh

ARCHIVE_DIR="/mnt/audit-archive/tacacs"
RETENTION_DAYS=2555  # 7 years for compliance

mkdir -p "$ARCHIVE_DIR"

# Find and archive rotated logs
find /var/log/tacacs -name "*.log.*.gz" -type f | while read -r logfile; do
  BASENAME=$(basename "$logfile")
  DEST="$ARCHIVE_DIR/$BASENAME"

  # Copy to archive with verification
  cp "$logfile" "$DEST"

  if md5sum -c <(md5sum "$logfile") --status; then
    rm "$logfile"
    echo "Archived: $BASENAME"
  else
    echo "ERROR: Checksum mismatch for $BASENAME" >&2
  fi
done

# Purge old archives beyond retention
find "$ARCHIVE_DIR" -type f -mtime +$RETENTION_DAYS -delete
```

### Audit Log Analysis

```bash
#!/bin/bash
# /usr/local/bin/tacacs-analyze-logs.sh
# Generate daily audit report

DATE=${1:-$(date -d yesterday +%Y-%m-%d)}
LOG_FILE="/var/log/tacacs/access.log*"
REPORT_FILE="/var/log/tacacs/reports/audit-report-${DATE}.txt"

mkdir -p "$(dirname "$REPORT_FILE")"

{
echo "=== TACACS+ Audit Report for $DATE ==="
echo ""

echo "AUTHENTICATION SUMMARY:"
echo "Total authentication attempts: $(grep "$DATE" $LOG_FILE | grep -c "authentication")"
echo "Successful authentications: $(grep "$DATE" $LOG_FILE | grep -c "authentication success")"
echo "Failed authentications: $(grep "$DATE" $LOG_FILE | grep -c "authentication failed")"
echo ""

echo "TOP USERS (by authentication count):"
grep "$DATE" $LOG_FILE | grep "authentication success" | \
  grep -oP 'user=\K[^,]+' | sort | uniq -c | sort -rn | head -10
echo ""

echo "TOP SOURCE IPs:"
grep "$DATE" $LOG_FILE | grep -oP 'peer_addr=\K[0-9.]+' | \
  sort | uniq -c | sort -rn | head -10
echo ""

echo "AUTHORIZATION DENIALS:"
grep "$DATE" $LOG_FILE | grep "authorization denied" | \
  grep -oP 'user=\K[^,]+' | sort | uniq -c | sort -rn
echo ""

echo "POLICY VIOLATIONS:"
grep "$DATE" $LOG_FILE | grep "policy violation" | wc -l
echo ""

echo "SESSION LIMIT EVENTS:"
grep "$DATE" $LOG_FILE | grep "session limit exceeded" | wc -l
echo ""

echo "TLS ERRORS:"
grep "$DATE" $LOG_FILE | grep "TLS error" | wc -l
echo ""

} > "$REPORT_FILE"

echo "Audit report generated: $REPORT_FILE"
```

---

## Performance Monitoring

### Performance Metrics Dashboard

```bash
#!/bin/bash
# /usr/local/bin/tacacs-performance-report.sh

echo "=== TACACS+ Performance Report ==="
echo "Generated: $(date)"
echo ""

# Service uptime
echo "SERVICE UPTIME:"
systemctl show tacacs-server -p ActiveEnterTimestamp --value | \
  xargs -I {} date -d {} "+Started: %Y-%m-%d %H:%M:%S"
echo "Uptime: $(systemctl show tacacs-server -p ActiveEnterTimestampMonotonic --value | \
  awk '{print int($1/1000000) " seconds"}')"
echo ""

# Resource usage
echo "RESOURCE USAGE:"
PID=$(pgrep tacacs-server)
ps -p $PID -o pid,ppid,user,%cpu,%mem,vsz,rss,stat,start_time,time,comm --no-headers
echo ""

# Network connections
echo "NETWORK CONNECTIONS:"
ss -s
echo ""

# Request rates (from Prometheus)
echo "REQUEST RATES (last 5 minutes):"
curl -s http://127.0.0.1:9090/metrics | grep -E "tacacs_(authn|authz|acct)_" | \
  grep "_total" | tail -10
echo ""

# Session statistics
echo "SESSION STATISTICS:"
curl -s http://127.0.0.1:8080/sessions | jq '{
  total_sessions: .total,
  sessions_by_state: [.sessions | group_by(.state) | .[] | {state: .[0].state, count: length}],
  average_request_count: ([.sessions[].request_count] | add / length)
}'
echo ""

# Latency percentiles (if available in metrics)
echo "LATENCY PERCENTILES:"
curl -s http://127.0.0.1:9090/metrics | \
  grep "tacacs_request_duration" | grep "quantile"
```

### Load Testing Results Storage

```bash
#!/bin/bash
# /usr/local/bin/tacacs-load-test.sh
# Run regular load tests and track performance trends

TEST_ID="load-test-$(date +%Y%m%d-%H%M%S)"
RESULTS_DIR="/var/log/tacacs/load-tests/$TEST_ID"

mkdir -p "$RESULTS_DIR"

echo "Starting load test: $TEST_ID"

# Capture baseline metrics
curl -s http://127.0.0.1:9090/metrics > "$RESULTS_DIR/metrics-before.txt"

# Run load test (example using custom test tool)
# Replace with your actual load testing tool
./tacacs-load-generator \
  --host tacacs.example.com \
  --duration 60s \
  --connections 100 \
  --requests-per-conn 10 \
  > "$RESULTS_DIR/load-test-output.txt"

# Capture post-test metrics
sleep 5
curl -s http://127.0.0.1:9090/metrics > "$RESULTS_DIR/metrics-after.txt"

# Calculate performance delta
python3 <<EOF > "$RESULTS_DIR/performance-analysis.txt"
# Parse metrics and calculate deltas
# This is a placeholder - implement actual analysis
print("Load Test Results:")
print("Test ID: $TEST_ID")
print("Duration: 60s")
print("Concurrent connections: 100")
print("Total requests: ~1000")
print("")
print("Performance metrics:")
print("- Average latency: TBD")
print("- P95 latency: TBD")
print("- P99 latency: TBD")
print("- Throughput: TBD req/s")
print("- Error rate: TBD%")
EOF

cat "$RESULTS_DIR/performance-analysis.txt"

echo "Load test complete. Results in: $RESULTS_DIR"
```

---

## Backup and Recovery

### Configuration Backup

```bash
#!/bin/bash
# /usr/local/bin/tacacs-backup-config.sh

BACKUP_DIR="/backup/tacacs"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_FILE="$BACKUP_DIR/tacacs-config-$TIMESTAMP.tar.gz"

mkdir -p "$BACKUP_DIR"

echo "Creating configuration backup..."

# Create encrypted backup
tar czf - \
  /etc/tacacs \
  /etc/systemd/system/tacacs-server.service \
  /var/lib/tacacs \
  | gpg --encrypt --recipient ops@example.com > "$BACKUP_FILE.gpg"

if [ $? -eq 0 ]; then
  echo "Backup created: $BACKUP_FILE.gpg"

  # Verify backup integrity
  gpg --decrypt "$BACKUP_FILE.gpg" | tar tzf - > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    echo "Backup verification: OK"
  else
    echo "ERROR: Backup verification failed!" >&2
    exit 1
  fi

  # Cleanup old backups (keep 30 days)
  find "$BACKUP_DIR" -name "tacacs-config-*.tar.gz.gpg" -mtime +30 -delete

  # Copy to offsite backup
  scp "$BACKUP_FILE.gpg" backup-server:/backups/tacacs/

else
  echo "ERROR: Backup failed!" >&2
  exit 1
fi
```

### Disaster Recovery Procedure

```bash
#!/bin/bash
# /usr/local/bin/tacacs-restore-config.sh

BACKUP_FILE="$1"

if [ -z "$BACKUP_FILE" ]; then
  echo "Usage: $0 <backup-file.tar.gz.gpg>"
  exit 1
fi

if [ ! -f "$BACKUP_FILE" ]; then
  echo "ERROR: Backup file not found: $BACKUP_FILE"
  exit 1
fi

echo "DISASTER RECOVERY - Configuration Restore"
echo "Backup file: $BACKUP_FILE"
read -p "This will overwrite current configuration. Continue? (yes/NO): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
  echo "Restore cancelled"
  exit 0
fi

# Stop service
echo "Stopping TACACS+ service..."
systemctl stop tacacs-server

# Backup current state before restore
EMERGENCY_BACKUP="/tmp/tacacs-pre-restore-$(date +%Y%m%d-%H%M%S).tar.gz"
tar czf "$EMERGENCY_BACKUP" /etc/tacacs /var/lib/tacacs
echo "Current state backed up to: $EMERGENCY_BACKUP"

# Restore from backup
echo "Restoring configuration..."
gpg --decrypt "$BACKUP_FILE" | tar xzf - -C /

if [ $? -eq 0 ]; then
  echo "Configuration restored successfully"

  # Verify configuration
  echo "Validating restored configuration..."
  /usr/local/bin/tacacs-validate-config.sh

  if [ $? -eq 0 ]; then
    echo "Starting service..."
    systemctl start tacacs-server

    echo "Recovery complete!"
    echo "Emergency backup available at: $EMERGENCY_BACKUP"
  else
    echo "ERROR: Configuration validation failed!"
    echo "Service not started. Review configuration and start manually."
    exit 1
  fi
else
  echo "ERROR: Restore failed!"
  echo "Restoring previous state from: $EMERGENCY_BACKUP"
  tar xzf "$EMERGENCY_BACKUP" -C /
  systemctl start tacacs-server
  exit 1
fi
```

---

## Maintenance Procedures

### Certificate Renewal

```bash
#!/bin/bash
# /usr/local/bin/tacacs-renew-certificate.sh

NEW_CERT="$1"
NEW_KEY="$2"

if [ -z "$NEW_CERT" ] || [ -z "$NEW_KEY" ]; then
  echo "Usage: $0 <new-cert.crt> <new-key.key>"
  exit 1
fi

echo "=== Certificate Renewal Procedure ==="

# 1. Validate new certificate
echo "[1/6] Validating new certificate..."
openssl x509 -in "$NEW_CERT" -noout -checkend 0
if [ $? -ne 0 ]; then
  echo "ERROR: Certificate is expired or invalid"
  exit 1
fi

# 2. Verify key matches certificate
echo "[2/6] Verifying key matches certificate..."
CERT_MOD=$(openssl x509 -noout -modulus -in "$NEW_CERT" | openssl md5)
KEY_MOD=$(openssl rsa -noout -modulus -in "$NEW_KEY" | openssl md5)
if [ "$CERT_MOD" != "$KEY_MOD" ]; then
  echo "ERROR: Private key does not match certificate"
  exit 1
fi

# 3. Backup current certificates
echo "[3/6] Backing up current certificates..."
BACKUP_DIR="/etc/tacacs/certs/backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp /etc/tacacs/certs/tacacs-server.{crt,key} "$BACKUP_DIR/"

# 4. Install new certificates
echo "[4/6] Installing new certificates..."
install -m 644 -o tacacs -g tacacs "$NEW_CERT" /etc/tacacs/certs/tacacs-server.crt
install -m 400 -o tacacs -g tacacs "$NEW_KEY" /etc/tacacs/certs/tacacs-server.key

# 5. Reload service
echo "[5/6] Reloading service..."
systemctl reload tacacs-server

if [ $? -eq 0 ]; then
  echo "[6/6] Certificate renewal complete!"

  # Verify service still running
  sleep 2
  systemctl is-active --quiet tacacs-server
  if [ $? -eq 0 ]; then
    echo "✓ Service is healthy"

    # Display new certificate details
    echo ""
    echo "New certificate details:"
    openssl x509 -in /etc/tacacs/certs/tacacs-server.crt -noout -subject -dates
  else
    echo "ERROR: Service failed after reload!"
    echo "Restoring previous certificates..."
    cp "$BACKUP_DIR"/* /etc/tacacs/certs/
    systemctl reload tacacs-server
    exit 1
  fi
else
  echo "ERROR: Failed to reload service!"
  echo "Restoring previous certificates..."
  cp "$BACKUP_DIR"/* /etc/tacacs/certs/
  systemctl restart tacacs-server
  exit 1
fi
```

### Software Updates

```bash
#!/bin/bash
# /usr/local/bin/tacacs-update.sh

NEW_BINARY="$1"

if [ -z "$NEW_BINARY" ]; then
  echo "Usage: $0 <path-to-new-tacacs-server-binary>"
  exit 1
fi

echo "=== TACACS+ Software Update Procedure ==="

# 1. Verify new binary
echo "[1/7] Verifying new binary..."
if [ ! -x "$NEW_BINARY" ]; then
  echo "ERROR: Binary not executable or not found"
  exit 1
fi

# Check version
"$NEW_BINARY" --version
read -p "Proceed with update? (yes/NO): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
  echo "Update cancelled"
  exit 0
fi

# 2. Backup current binary
echo "[2/7] Backing up current binary..."
cp /usr/local/bin/tacacs-server "/usr/local/bin/tacacs-server.bak.$(date +%Y%m%d)"

# 3. Run pre-update tests
echo "[3/7] Running pre-update tests..."
curl -sf http://127.0.0.1:8080/health > /tmp/pre-update-health.json

# 4. Install new binary
echo "[4/7] Installing new binary..."
install -m 755 "$NEW_BINARY" /usr/local/bin/tacacs-server

# 5. Restart service
echo "[5/7] Restarting service..."
systemctl restart tacacs-server

# 6. Health check
echo "[6/7] Performing post-update health check..."
sleep 5

if systemctl is-active --quiet tacacs-server; then
  echo "✓ Service is running"

  # Verify API responds
  if curl -sf http://127.0.0.1:8080/health > /dev/null; then
    echo "✓ API is responding"

    # Compare versions
    echo "[7/7] Update complete!"
    /usr/local/bin/tacacs-server --version

  else
    echo "ERROR: API not responding!"
    echo "Rolling back..."
    cp /usr/local/bin/tacacs-server.bak.* /usr/local/bin/tacacs-server
    systemctl restart tacacs-server
    exit 1
  fi
else
  echo "ERROR: Service failed to start!"
  echo "Rolling back..."
  cp /usr/local/bin/tacacs-server.bak.* /usr/local/bin/tacacs-server
  systemctl restart tacacs-server
  exit 1
fi
```

---

## Security Event Playbooks

### Playbook 1: Brute Force Attack

**Detection:** High rate of authentication failures from single IP

**Response:**

1. **Confirm attack** (< 5 minutes)
   ```bash
   journalctl -u tacacs-server --since "5 minutes ago" | \
     grep "authentication failed" | \
     grep -oP 'peer_addr=\K[0-9.]+' | sort | uniq -c | sort -rn
   ```

2. **Block attacking IP** (< 10 minutes)
   ```bash
   /usr/local/bin/tacacs-block-ip.sh <ATTACKER_IP>
   ```

3. **Verify no successful authentications** (< 15 minutes)
   ```bash
   journalctl -u tacacs-server | \
     grep "<ATTACKER_IP>" | grep "authentication success"
   ```

4. **Document incident** (< 30 minutes)
   - Log IP address, time range, affected accounts
   - Create incident ticket
   - Notify security team

5. **Review and adjust** (< 24 hours)
   - Increase brute force thresholds if needed
   - Add IP to permanent blocklist
   - Review related logs for coordinated attacks

### Playbook 2: Certificate Compromise

**Detection:** Unauthorized certificate usage, certificate appears in breach reports

**Response:**

1. **Immediate revocation** (< 15 minutes)
   ```bash
   # Add to CRL
   openssl ca -revoke /path/to/compromised-cert.crt \
     -config /etc/ssl/openssl.cnf

   # Update and publish CRL
   openssl ca -gencrl -out /var/www/crl/current.crl
   ```

2. **Block certificate at server** (< 15 minutes)
   ```bash
   # Remove from allowlist
   grep -v "compromised-device.example.com" \
     /etc/tacacs/allowed-clients.txt > /tmp/allowed-clients.txt
   mv /tmp/allowed-clients.txt /etc/tacacs/allowed-clients.txt

   # Reload configuration
   systemctl reload tacacs-server
   ```

3. **Terminate active sessions** (< 20 minutes)
   ```bash
   # Find sessions using compromised certificate
   curl -s http://127.0.0.1:8080/sessions | \
     jq '.sessions[] | select(.device_id == "compromised-device")'

   # Terminate sessions
   curl -X DELETE http://127.0.0.1:8080/sessions/<SESSION_ID>
   ```

4. **Issue replacement certificate** (< 1 hour)
   ```bash
   # Generate new certificate for legitimate device
   /usr/local/bin/tacacs-issue-client-cert.sh new-device-name
   ```

5. **Investigate breach** (< 24 hours)
   - Review all authentications using compromised cert
   - Check for unauthorized commands/access
   - Identify root cause of compromise

6. **Lessons learned** (< 1 week)
   - Update certificate management procedures
   - Implement additional monitoring
   - Train staff on secure certificate handling

---

## Troubleshooting Guide

### Service Won't Start

**Symptoms:** `systemctl start tacacs-server` fails

**Diagnostic steps:**

```bash
# Check service status and recent logs
systemctl status tacacs-server
journalctl -u tacacs-server -n 50 --no-pager

# Common issues:

# 1. Port already in use
ss -tlnp | grep -E "(49|8080|9090)"
# Solution: Kill conflicting process or change port

# 2. Certificate/key permissions
ls -la /etc/tacacs/certs/
# Solution: chmod 400 server.key, chown tacacs:tacacs

# 3. Missing secret file
test -f /etc/tacacs/secrets/tacacs-secret && echo "exists" || echo "missing"
# Solution: Create secret file with proper permissions

# 4. Invalid configuration
/usr/local/bin/tacacs-validate-config.sh
# Solution: Fix configuration errors reported

# 5. SELinux denial
ausearch -m avc -ts recent | grep tacacs
# Solution: Create SELinux policy or temporarily: setenforce 0
```

### High Memory Usage

**Symptoms:** Process consuming > 1GB RAM

**Diagnostic steps:**

```bash
# Check memory usage
ps -p $(pgrep tacacs-server) -o pid,vsz,rss,%mem,cmd

# Check session count
curl -s http://127.0.0.1:8080/sessions | jq '.total'

# Check for memory leak indicators
pmap -x $(pgrep tacacs-server) | tail -1

# Mitigation:
# - Lower session limits
# - Reduce idle timeout
# - Restart service during maintenance window
systemctl restart tacacs-server
```

### Slow Authentication Response

**Symptoms:** NADs reporting timeout errors

**Diagnostic steps:**

```bash
# Check LDAP response time
time ldapsearch -H ldaps://ldap.example.com \
  -D "cn=tacacs,dc=example,dc=com" -W \
  -b "ou=users,dc=example,dc=com" "(uid=testuser)"

# Check network latency
ping -c 10 ldap.example.com

# Check CPU usage
top -p $(pgrep tacacs-server)

# Check request rates
curl -s http://127.0.0.1:9090/metrics | grep tacacs_request_duration

# Solutions:
# - Optimize LDAP queries (add indexes)
# - Increase LDAP connection pool
# - Scale horizontally (add more servers)
# - Enable caching (if supported)
```

---

## Contact and Escalation

### On-Call Rotation

| Time Window | Primary | Secondary | Manager |
|-------------|---------|-----------|---------|
| Business Hours (9-5 EST) | ops-team@example.com | security@example.com | ops-manager@example.com |
| After Hours | on-call@example.com | backup-oncall@example.com | incident-manager@example.com |

### Escalation Matrix

| Severity | Notification | Response | Escalation |
|----------|-------------|----------|------------|
| P0 - Critical | Immediate page | 15 min | Manager + Security Team |
| P1 - High | Phone + email | 1 hour | Manager if not resolved in 2h |
| P2 - Medium | Email | 4 hours | Manager if not resolved in 8h |
| P3 - Low | Ticket | 24 hours | None |

---

**Document Version:** 1.0
**Last Updated:** 2026-01-11
**Next Review:** 2026-04-11
