# Analyze Network Traffic Patterns

Analyze packet captures, IDS alerts, and firewall logs to identify attack patterns, anomalies, and security threats in FirewallX telemetry data.

## Purpose

Transform raw network telemetry into actionable intelligence by detecting:
- Port scans and reconnaissance activity
- Brute-force login attempts
- DDoS and flood attacks
- Data exfiltration patterns
- Malware command & control (C2) communication
- Policy violations and unauthorized access

## Data Sources

### 1. FirewallX Engine Logs

Parse structured logs from `engine.process()`:
```json
{
  "timestamp": "2026-03-15T10:23:45.123Z",
  "action": "DROP",
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.5",
  "src_port": 54321,
  "dst_port": 22,
  "protocol": "TCP",
  "direction": "inbound",
  "reason": "rule_match",
  "rule_id": 42
}
```

### 2. IDS/IPS Alerts

Analyze behavioral detection events:
- **Port Scan**: Multiple ports from single source in short timeframe
- **Flood Attack**: Excessive packet rate exceeding thresholds
- **Brute Force**: Repeated authentication failures to same service
- **Blacklisted IP**: Matches threat intelligence feeds

### 3. DPI Inspection Results

Review payload inspection matches:
- SQL injection signatures
- XSS attack patterns
- Path traversal attempts
- Malicious executable uploads
- Shellcode and exploit payloads

### 4. VPN Gateway Events

Monitor tunnel lifecycle:
- Failed handshake attempts
- Authentication failures
- Unusual traffic volumes through tunnels
- Unauthorized peer connections

## Analysis Techniques

### 1. Time-Series Aggregation

Group events by:
- Source IP (per-second/minute/hour rates)
- Destination port (service-specific analysis)
- Action type (allow vs. drop ratios)
- Country code (geo-based patterns)

**Example Query:**
```sql
SELECT src_ip, COUNT(*) as drops_per_minute
FROM firewall_logs
WHERE action = 'DROP'
  AND timestamp >= NOW() - INTERVAL '5 minutes'
GROUP BY src_ip
HAVING COUNT(*) > 100
ORDER BY drops_per_minute DESC;
```

### 2. Pattern Recognition

Identify known attack signatures:

**Port Scan Detection:**
```rust
// Pseudo-code for scan detection
if unique_ports_accessed(src_ip, window=60s) > threshold {
    alert(PortScan, src_ip, confidence=HIGH);
}
```

**DDoS Detection:**
```rust
if packets_per_second(dst_ip, window=10s) > max_pps {
    alert(FloodAttack, dst_ip, confidence=CRITICAL);
    trigger_rate_limiting();
}
```

### 3. Statistical Anomalies

Detect deviations from baseline:
- Unusual traffic volume spikes (3σ from mean)
- New geographic sources accessing sensitive services
- Off-hours access patterns
- Protocol distribution changes

### 4. Correlation Analysis

Link related events:
- Same source across multiple rules
- Sequential attacks from botnet IPs
- Coordinated scans from multiple sources
- C2 beaconing patterns (periodic callbacks)

## Output Reports

### 1. Executive Summary

High-level threat overview:
```
📊 Security Report (Last 24 Hours)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Packets Analyzed: 1,234,567
Allowed: 98.2% | Dropped: 1.8%
Threats Detected: 47
  - Port Scans: 12
  - Brute Force: 8
  - DPI Blocked: 23
  - Blacklisted IPs: 4

Top Attackers:
  1. 203.0.113.50 (Russia) - 234 drops
  2. 198.51.100.25 (China) - 189 drops
  3. 192.0.2.100 (Unknown) - 156 drops
```

### 2. Detailed Incident Reports

For each significant event:

**Incident #1: Coordinated Port Scan**
```
Severity: HIGH
Timeframe: 2026-03-15 10:15:00 - 10:20:00 UTC
Source: 203.0.113.50 (ASN: EvilCorp Ltd)
Targets: 10.0.0.0/24 subnet
Ports Scanned: 1-1024 (all common services)
Packets: 3,456
Action Taken: Source added to blocklist at 10:20:03

Recommendation: 
  ✓ Block entire ASN range if false positives acceptable
  ✓ Enable IDS aggressive mode for next 24 hours
  ✓ Review exposed services for vulnerabilities
```

### 3. Recommended Actions

Prioritized response items:

```bash
# Immediate: Block top attacker
firewallx rule add \
  --name "Block persistent scanner" \
  --action drop \
  --src_ip "203.0.113.50" \
  --protocol any \
  --direction inbound

# Short-term: Harden exposed services
firewallx rule add \
  --name "Rate limit SSH" \
  --action allow \
  --port 22 \
  --protocol tcp \
  --direction inbound \
  --max-rate "10/s"

# Long-term: Implement geo-blocking policy
firewallx rule add \
  --name "Block high-risk regions" \
  --action drop \
  --country "RU,CN,KP,IR" \
  --protocol any \
  --direction inbound
```

## Integration Points

### 1. SIEM Forwarding

Configure FirewallX to stream to external SIEM:

```toml
# config.toml
[siem]
enabled = true
url = "https://splunk.internal:8088/services/collector"
api_key = "${SPLUNK_HEC_TOKEN}"
batch_size = 100
flush_interval_secs = 5
```

### 2. Prometheus Metrics

Export analysis counters:

```rust
// Example metrics
firewallx_packets_total{action="drop", reason="ids_blocked"} 1234
firewallx_packets_total{action="drop", reason="dpi_blocked"} 567
firewallx_ips_detected_scans_total 47
firewallx_blocklist_size 892
```

### 3. Automated Response

Trigger automated playbooks:
- Auto-block IPs exceeding thresholds
- Notify SOC team via Slack/PagerDuty
- Create Jira tickets for critical incidents
- Update WAF rules based on DPI findings

## Tools & Commands

### Real-Time Monitoring

```bash
# Watch live drops
tail -f /var/log/firewallx.log | grep "DROP"

# Top talkers by packet count
firewallx stats --top-sources --limit 20

# IDS alerts summary
firewallx ids alerts --since 1h --group-by kind
```

### Historical Analysis

```bash
# Export logs for offline analysis
firewallx logs export --format json --output analysis.json

# Generate daily report
firewallx reports daily --date 2026-03-15 --output report.md
```

## Machine Learning Opportunities

Future enhancements:
- Unsupervised anomaly detection on traffic patterns
- Clustering similar attack campaigns
- Predictive blocking based on early indicators
- NLP classification of DPI payloads
- Reinforcement learning for optimal rule ordering
