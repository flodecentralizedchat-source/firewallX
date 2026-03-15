# Troubleshoot Firewall Connectivity Issues

Systematic diagnostic approach to identify and resolve firewall misconfigurations, false positives, eBPF attachment failures, and performance bottlenecks in FirewallX deployments.

## Purpose

Provide structured troubleshooting methodology for common FirewallX issues including:
- Legitimate traffic being blocked (false positives)
- Traffic that should be blocked getting through (false negatives)
- eBPF program failing to load or attach
- High CPU/memory usage
- VPN tunnel connectivity problems
- SIEM integration failures

## Diagnostic Framework

### Step 1: Gather Initial Information

**Collect baseline data:**

```bash
# Check service status
systemctl status firewallx --no-pager

# View recent logs
journalctl -u firewallx --since "10 minutes ago" --no-pager

# List active rules
sudo firewallx rule list

# Check eBPF status (Linux only)
sudo bpftool prog list | grep firewallx

# View current connections
sudo firewallx stats connections

# Check system resources
top -bn1 | grep firewallx
free -h
```

### Step 2: Identify the Symptom Category

Categorize the issue to focus troubleshooting:

| Symptom | Likely Cause | Priority |
|---------|-------------|----------|
| Can't SSH to server | Overly restrictive inbound rules | HIGH |
| Web server unreachable | Default deny blocking legitimate traffic | HIGH |
| Slow network throughput | eBPF inefficiency or resource contention | MEDIUM |
| High CPU usage | Too many DPI signatures or IDS alerts | MEDIUM |
| VPN not connecting | Tunnel configuration error | HIGH |
| SIEM not receiving logs | Network/API misconfiguration | LOW |

## Common Issues & Solutions

### Issue 1: False Positives (Legitimate Traffic Blocked)

**Symptoms:**
- Users report inability to access services
- Applications timing out on network calls
- Specific ports/protocols not working

**Diagnosis:**

```bash
# Find what's being dropped
sudo firewallx logs --action DROP --since 1h | sort | uniq -c | sort -rn | head -20

# Check if specific IP is being blocked
sudo firewallx logs --src_ip 192.168.1.100 --action DROP

# Test rule evaluation with packet simulation
sudo firewallx test-packet \
  --src-ip 192.168.1.100 \
  --dst-ip 10.0.0.5 \
  --dst-port 443 \
  --protocol tcp \
  --direction inbound
```

**Resolution:**

```bash
# Option 1: Add allow rule with higher priority
sudo firewallx rule add \
  --priority 10 \
  --name "Allow internal network HTTPS" \
  --action allow \
  --src_ip "192.168.1.0/24" \
  --port 443 \
  --protocol tcp \
  --direction inbound

# Option 2: Modify existing rule to exclude trusted IPs
sudo firewallx rule modify --id 42 \
  --exclude-src "192.168.1.0/24"

# Option 3: Temporarily disable problematic rule
sudo firewallx rule disable --id 42

# Verify fix
sudo firewallx test-packet --src-ip 192.168.1.100 --dst-port 443 --protocol tcp
```

### Issue 2: False Negatives (Malicious Traffic Not Blocked)

**Symptoms:**
- Security scans show open ports that should be blocked
- IDS not triggering on known attack patterns
- Blocklist IPs still getting through

**Diagnosis:**

```bash
# Check if default deny policy exists
sudo firewallx rule list | grep "default"

# Verify blocklist is loaded
sudo firewallx blocklist count

# Test blocklist effectiveness
for ip in $(cat malicious_ips.txt); do
    sudo firewallx test-packet --src-ip $ip --dst-port 22 --protocol tcp
done

# Check IDS is enabled and monitoring
sudo firewallx ids status
```

**Resolution:**

```bash
# Add explicit default deny if missing
sudo firewallx rule add \
  --priority 9999 \
  --name "Default deny all inbound" \
  --action drop \
  --protocol any \
  --direction inbound

# Reload blocklist from feeds
sudo firewallx blocklist refresh

# Manually add missing block
sudo firewallx rule add \
  --name "Block known attacker" \
  --action drop \
  --src_ip "203.0.113.50" \
  --protocol any \
  --direction inbound

# Enable IDS aggressive mode
sudo sed -i 's/ids_sensitivity = "normal"/ids_sensitivity = "aggressive"/' /etc/firewallx/config.toml
sudo systemctl restart firewallx
```

### Issue 3: eBPF Program Fails to Load

**Symptoms:**
```
Warning: eBPF kernel program not loaded. Running in standard userspace mode.
```

**Diagnosis:**

```bash
# Check kernel version (need 5.10+ for full eBPF support)
uname -r

# Verify BPF filesystem is mounted
mount | grep bpf

# Check RLIMIT_MEMLOCK
ulimit -l

# Try loading manually with verbose output
sudo bpftool prog loadall firewallx-ebpf /sys/fs/bpf type xdp
```

**Common Causes & Fixes:**

**A. Kernel too old:**
```bash
# Minimum requirements
# - Basic eBPF: Kernel 4.19+
# - XDP native: Kernel 5.10+
# - Full feature set: Kernel 5.15+

# Upgrade kernel (Ubuntu/Debian)
sudo apt install linux-generic-hwe-22.04
sudo reboot
```

**B. Memory lock limit too low:**
```bash
# Temporarily increase limit
ulimit -l unlimited

# Permanently set in /etc/security/limits.conf
echo "* soft memlock unlimited" >> /etc/security/limits.conf
echo "* hard memlock unlimited" >> /etc/security/limits.conf

# Reboot or re-login for changes to take effect
```

**C. Driver doesn't support native XDP:**
```bash
# Check driver support
ethtool -i eth0 | grep driver

# Use generic XDP as fallback
sudo ip link set dev eth0 xdp-generic obj firewallx-ebpf.o sec .text

# Or switch to userspace-only mode
sudo sed -i 's/ebpf_enabled = true/ebpf_enabled = false/' /etc/firewallx/config.toml
sudo systemctl restart firewallx
```

**D. Verification failed:**
```bash
# Get detailed verifier error
sudo dmesg | tail -50 | grep -i "bpf\|verifier"

# Common fix: Reduce program complexity
# Edit firewallx-ebpf/src/main.rs and simplify logic
# Split into multiple programs with tail calls
```

### Issue 4: High CPU Usage

**Symptoms:**
- Firewall consuming >50% CPU continuously
- System load average very high
- Packet processing latency increased

**Diagnosis:**

```bash
# Profile which module is using CPU
sudo perf top -p $(pgrep firewallx)

# Check number of DPI signatures loaded
sudo firewallx dpi stats

# Monitor alert rate
watch -n1 'sudo firewallx ids alerts --since 1m | wc -l'

# Check ring buffer overflow (indicates too many events)
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep "ringbuf"
```

**Resolution:**

**A. Too many DPI signatures:**
```bash
# Disable unused signature categories
sudo firewallx dpi disable-category "malware"
sudo firewallx dpi disable-category "policy-violation"

# Or reduce to essential signatures only
sudo firewallx dpi select --min-severity HIGH
```

**B. Excessive IDS alerts:**
```bash
# Increase alert thresholds
sudo firewallx ids threshold set port-scan --packets 100 --window 60
sudo firewallx ids threshold set brute-force --attempts 20 --window 120

# Disable noisy detections
sudo firewallx ids disable-detection flood-attack
```

**C. Optimize eBPF performance:**
```rust
// In firewallx-ebpf/src/main.rs
// Use per-CPU maps to reduce lock contention
#[map]
pub static mut STATS: PerCpuArray<Stats> = PerCpuArray::new();

// Reduce HashMap lookups by caching hot entries
#[map]
pub static mut BLOCKLIST_CACHE: LruCache<u32, u8> = LruCache::new(1024);
```

**D. Tune batch processing:**
```toml
# config.toml optimizations
[performance]
event_batch_size = 256      # Process events in larger batches
alert_coalesce_secs = 5     # Combine alerts within time window
dpi_cache_size = 4096       # Cache frequent payload matches
```

### Issue 5: VPN Tunnel Failures

**Symptoms:**
- WireGuard peers can't establish tunnels
- Handshake timeouts
- Traffic not routing through tunnel

**Diagnosis:**

```bash
# Check VPN gateway status
sudo firewallx vpn status

# View peer configurations
sudo firewallx vpn peer list

# Check active tunnels
sudo firewallx vpn tunnel list

# Test handshake initiation
sudo firewallx vpn test-handshake --peer-ip 203.0.113.100
```

**Resolution:**

**A. Incorrect WireGuard config:**
```bash
# Validate configuration file
sudo firewallx vpn validate-config /path/to/wg0.conf

# Fix common issues:
# - Ensure private key is correct (not public key!)
# - Verify endpoint address is reachable
# - Check allowed IPs includes remote network
# - Confirm listening port is not firewalled

# Re-import corrected config
sudo firewallx vpn import --file /corrected/wg0.conf
```

**B. Firewall blocking VPN traffic:**
```bash
# Allow WireGuard port (default 51820)
sudo firewallx rule add \
  --name "Allow WireGuard UDP" \
  --action allow \
  --port 51820 \
  --protocol udp \
  --direction both

# If using IPSec, allow ESP protocol
sudo firewallx rule add \
  --name "Allow IPSec ESP" \
  --action allow \
  --protocol esp \
  --direction both
```

**C. NAT traversal issues:**
```bash
# Enable NAT-T for IPSec
sudo firewallx vpn set nat-traversal enabled

# For WireGuard behind NAT, use PersistentKeepalive
# Add to peer config:
# PersistentKeepalive = 25
```

### Issue 6: SIEM Integration Failures

**Symptoms:**
- Logs not appearing in SIEM dashboard
- HTTP 401/403 errors when forwarding
- Connection refused to SIEM endpoint

**Diagnosis:**

```bash
# Check SIEM configuration
sudo firewallx siem config

# Test connectivity to SIEM
curl -v https://siem.internal:8088/services/collector \
  -H "Authorization: Splunk ${SIEM_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"text": "test"}'

# View SIEM send failures
sudo firewallx siem stats failures
```

**Resolution:**

```bash
# Fix API key authentication
export SIEM_API_KEY="correct-key-here"
sudo firewallx siem set api-key "${SIEM_API_KEY}"

# Update SIEM URL if changed
sudo firewallx siem set url "https://new-siem-url:8088/services/collector"

# Adjust batch settings for large deployments
sudo firewallx siem set batch-size 500
sudo firewallx siem set flush-interval 10

# Enable TLS verification (or disable for self-signed certs)
sudo firewallx siem set verify-tls false  # Only for testing!
```

## Advanced Debugging Techniques

### 1. Enable Verbose Logging

```bash
# Maximum verbosity for troubleshooting
export RUST_LOG=firewallx=trace,aya=debug
sudo systemctl restart firewallx

# Watch live trace output
sudo journalctl -u firewallx -f

# Filter to specific modules
sudo journalctl -u firewallx -f | grep -E "dpi|ids|ebpf"
```

### 2. Packet Capture Analysis

```bash
# Capture packets before firewall processing
sudo tcpdump -i eth0 -w /tmp/capture.pcap host 192.168.1.100

# Analyze with Wireshark or tcpdump
tcpdump -r /tmp/capture.pcap -nn -vv

# Or use tshark for protocol analysis
tshark -r /tmp/capture.pcap -Y "tcp.port == 22" -V
```

### 3. Rule Chain Visualization

```bash
# Show rule evaluation order
sudo firewallx rule list --verbose --show-priority

# Output example:
# Priority  ID   Name                        Action  Hits
# --------  ---  --------------------------  ------  ----
# 10        1    Allow established          ALLOW   45,234
# 20        2    Allow SSH from LAN         ALLOW   1,234
# 50        3    Block Russia               DROP    892
# 9999      999  Default deny               DROP    12,456
```

### 4. Performance Profiling

```bash
# Profile with perf
sudo perf record -F 99 -p $(pgrep firewallx) --call-graph dwarf sleep 30
sudo perf report --stdio

# Or use cargo-flamegraph for Rust-specific profiling
cargo flamegraph --root --freq 99 -- ./target/release/firewallx start
```

### 5. Core Dump Analysis

```bash
# Enable core dumps
ulimit -c unlimited

# If firewall crashes, analyze core dump
gdb ./target/release/firewallx /var/coredumps/core.<pid>

# In gdb:
# bt              # Backtrace
# info threads    # See all threads
# frame N         # Navigate stack frames
```

## Recovery Procedures

### Rollback to Previous Configuration

```bash
# List available backups
ls -lh /etc/firewallx/backups/

# Restore yesterday's config
sudo cp /etc/firewallx/backups/config-$(date -d yesterday +%Y%m%d).toml \
        /etc/firewallx/config.toml

# Restart with restored config
sudo systemctl restart firewallx

# Verify restoration
sudo firewallx rule list
```

### Emergency Access Recovery

If you've locked yourself out:

```bash
# Physical/console access required
# Boot into single-user mode or recovery mode

# Mount root filesystem
mount -o remount,rw /

# Temporarily stop firewall
systemctl stop firewallx

# Or flush all rules
iptables -F
ip6tables -F

# Edit config to remove problematic rules
nano /etc/firewallx/config.toml

# Restart with clean config
systemctl start firewallx
```

## Preventive Measures

### Monitoring Setup

```bash
# Create health check script
cat > /usr/local/bin/firewallx-health.sh << 'EOF'
#!/bin/bash
if ! systemctl is-active --quiet firewallx; then
    echo "CRITICAL: FirewallX not running!"
    exit 1
fi

if ! sudo firewallx rule list > /dev/null 2>&1; then
    echo "CRITICAL: Cannot communicate with firewall daemon!"
    exit 1
fi

echo "OK: FirewallX healthy"
exit 0
EOF

chmod +x /usr/local/bin/firewallx-health.sh

# Add to crontab for monitoring
*/5 * * * * /usr/local/bin/firewallx-health.sh || mail -s "Firewall Alert" admin@example.com
```

### Regular Maintenance Tasks

```bash
# Weekly: Rotate logs
sudo logrotate -f /etc/logrotate.d/firewallx

# Monthly: Review and clean up old rules
sudo firewallx rule list --sort hits | tail -20  # Least used rules

# Quarterly: Update threat intelligence feeds
sudo firewallx feed update

# Biannually: Review and test disaster recovery plan
sudo firewallx dr test-scenario full-outage
```
