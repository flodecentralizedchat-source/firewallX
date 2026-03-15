# FirewallX Architecture & Execution Flow

This document explains how the FirewallX codebase works, from packet arrival to final decision.

## 🏗️ High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        User Space                            │
├─────────────────────────────────────────────────────────────┤
│  ┌───────────┐  ┌──────────┐  ┌─────────┐  ┌────────────┐  │
│  │   CLI     │  │  Engine  │  │   API   │  │   AI Agent │  │
│  │  (main)   │  │ (lib.rs) │  │ (Axum)  │  │  (OpenAI)  │  │
│  └─────┬─────┘  └────┬─────┘  └────┬────┘  └─────┬──────┘  │
│        │            │             │               │         │
│        └────────────┴─────────────┴───────────────┘         │
│                             │                                │
│                    ┌────────▼────────┐                       │
│                    │  FirewallEngine │                       │
│                    │  - Rules        │                       │
│                    │  - DPI          │                       │
│                    │  - IDS          │                       │
│                    │  - VPN          │                       │
│                    │  - Rate Limiter │                       │
│                    │  - QoS          │                       │
│                    │  - SIEM         │                       │
│                    └────────┬────────┘                       │
└─────────────────────────────┼────────────────────────────────┘
                              │
                    ┌─────────▼──────────┐
                    │   eBPF (XDP Hook)  │  ← Optional kernel acceleration
                    │   - Blocklist Map  │
                    │   - Ring Buffer    │
                    │   - Packet Drops   │
                    └─────────┬──────────┘
                              │
                    ┌─────────▼──────────┐
                    │   Linux Kernel     │
                    │   Network Stack    │
                    └────────────────────┘
```

## 📦 Module Structure

### Core Modules

#### 1. **Main Entry Point** (`firewallx/src/main.rs`)

**Purpose:** CLI interface and engine orchestration

**Flow:**
```rust
main() 
  ├─→ Parse CLI arguments (Clap)
  ├─→ Load config.toml
  ├─→ Initialize tracing/logging
  ├─→ Match command:
  │   ├─→ install  → Setup systemd service
  │   ├─→ rule     → Manage firewall rules
  │   ├─→ feed     → Manage threat intel feeds
  │   ├─→ vpn      → Manage VPN tunnels
  │   ├─→ siem     → Configure SIEM logging
  │   └─→ start    → Launch firewall engine
  └─→ start_firewall()
       ├─→ Create FirewallEngine
       ├─→ Mount RateLimiter (optional)
       ├─→ Mount QosManager (optional)
       ├─→ Mount SiemLogger (optional)
       ├─→ Import Suricata signatures
       ├─→ Fetch blocklist feeds
       ├─→ Setup VPN Gateway
       ├─→ Start Axum API server
       ├─→ Spawn AI Investigator (if enabled)
       └─→ Run demo packet tests
```

**Key Features:**
- CLI with subcommands via `clap`
- Configuration loading from `config.toml`
- Modular engine initialization
- Async runtime with Tokio
- REST API with Axum
- AI integration with async-openai

---

#### 2. **Firewall Engine** (`firewallx/src/modules/engine.rs`)

**Purpose:** Main packet processing pipeline

**Packet Flow:**
```
Packet Arrives
     │
     ▼
┌─────────────────┐
│ 1. State Check  │ ← Is this an established connection?
└────────┬────────┘
         │ No
         ▼
┌─────────────────┐
│ 2. Blocklist    │ ← Is IP in threat intel list?
└────────┬────────┘
         │ No
         ▼
┌─────────────────┐
│ 3. Rule Match   │ ← Evaluate rules by priority
└────────┬────────┘
         │ Allow
         ▼
┌─────────────────┐
│ 4. DPI Check    │ ← Scan payload for threats
└────────┬────────┘
         │ Clean
         ▼
┌─────────────────┐
│ 5. IDS Analysis │ ← Behavioral detection
└────────┬────────┘
         │ Safe
         ▼
┌─────────────────┐
│ 6. Add to State │ ← Cache for future packets
└────────┬────────┘
         │
         ▼
    ALLOW Packet
```

**Data Structures:**
```rust
pub struct FirewallEngine {
    ruleset: RuleSet,              // Ordered rule list
    state_table: StateTable,       // Connection tracking
    dpi: DpiEngine,                // Deep packet inspection
    ids: IdsEngine,                // Intrusion detection
    rate_limiter: Option<RateLimiter>, // Per-IP rate limiting
    qos_manager: Option<QosManager>,   // Bandwidth management
    siem: Option<SiemLogger>,      // External logging
    active_blocks: Vec<Ipv4Addr>,  // Dynamic blocklist
    stats: EngineStats,            // Counters
}
```

**Processing Logic:**
```rust
pub fn process(&mut self, pkt: &Packet) -> Decision {
    // 1. Check state table (fast path)
    if let Some(state) = self.state_table.get(pkt) {
        return state.action;
    }
    
    // 2. Check blocklist
    if self.active_blocks.contains(&pkt.src_ip) {
        self.stats.dropped += 1;
        return Decision::Drop;
    }
    
    // 3. Evaluate rules
    let rule_result = self.ruleset.evaluate(pkt);
    if rule_result.action == Action::Drop {
        self.stats.dropped += 1;
        return Decision::Drop;
    }
    
    // 4. DPI inspection (if payload present)
    if let Some(payload) = pkt.payload {
        let dpi_result = self.dpi.inspect(payload);
        if dpi_result.blocked {
            self.stats.dpi_blocked += 1;
            return Decision::DpiBlock;
        }
    }
    
    // 5. IDS analysis
    let alerts = self.ids.inspect(pkt);
    if !alerts.is_empty() {
        self.stats.ips_blocked += 1;
        if self.ids.is_ips_enabled() {
            return Decision::IpsBlock;
        }
    }
    
    // 6. Add to state table
    self.state_table.add(pkt, rule_result.action);
    
    self.stats.allowed += 1;
    rule_result.action
}
```

---

#### 3. **DPI Engine** (`firewallx/src/modules/dpi.rs`)

**Purpose:** Deep Packet Inspection - scan payloads for malicious content

**Signature Database:**
```rust
pub struct DpiEngine {
    signatures: Vec<DpiSignature>,
    app_protocol_db: HashMap<Vec<u8>, AppProtocol>,
}

pub struct DpiSignature {
    id: u32,
    name: String,
    action: Action,
    patterns: Vec<Vec<u8>>,      // Byte patterns to match
    regexes: Vec<Regex>,         // Regular expressions
    app_protocols: Vec<AppProtocol>,
}
```

**Inspection Flow:**
```
Payload Bytes
     │
     ▼
┌─────────────────┐
│ Protocol Detect │ ← HTTP, SSH, DNS, etc.
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Pattern Match   │ ← Aho-Corasick multi-pattern search
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Regex Match     │ ← Complex pattern matching
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Decision        │ ← Block or Allow
└─────────────────┘
```

**Built-in Signatures:**
- **SQL Injection**: `' OR '1'='1`, `UNION SELECT`, etc.
- **XSS**: `<script>`, `javascript:`, `onerror=`, etc.
- **Path Traversal**: `../../../`, `..\\..\\..\\`, etc.
- **Malware**: ELF headers (`\x7fELF`), PowerShell downloads, etc.
- **Shellcode**: Reverse shell patterns, C2 beacons

**Example Usage:**
```rust
let mut dpi = DpiEngine::new();
let payload = b"GET /login?user=' OR '1'='1 HTTP/1.1";
let result = dpi.inspect(payload);

assert!(result.blocked);
assert_eq!(result.matches[0].sig_id, 1001); // SQL injection
```

---

#### 4. **IDS Engine** (`firewallx/src/modules/ids.rs`)

**Purpose:** Behavioral intrusion detection and prevention

**Detection Algorithms:**

**A. Port Scan Detection:**
```rust
struct IpTracker {
    ports_accessed: HashSet<u16>,
    first_seen: Instant,
    packet_count: u64,
}

fn detect_port_scan(&mut self, pkt: &Packet) -> Option<Alert> {
    let tracker = self.ip_stats.entry(pkt.src_ip).or_default();
    
    tracker.ports_accessed.insert(pkt.dst_port);
    tracker.packet_count += 1;
    
    let elapsed = tracker.first_seen.elapsed().as_secs();
    
    if elapsed <= self.window.secs as u64 
        && tracker.ports_accessed.len() >= self.port_scan_threshold 
    {
        return Some(Alert {
            kind: AlertKind::PortScan,
            source_ip: pkt.src_ip,
            description: format!("Port scan detected: {} ports in {}s", 
                                 tracker.ports_accessed.len(), elapsed),
        });
    }
    
    None
}
```

**B. Flood Attack Detection:**
```rust
fn detect_flood(&mut self, pkt: &Packet) -> Option<Alert> {
    let tracker = self.ip_stats.entry(pkt.src_ip).or_default();
    
    tracker.packet_count += 1;
    let elapsed = tracker.first_seen.elapsed().as_secs();
    
    if elapsed <= 1 
        && tracker.packet_count >= self.flood_pps_threshold 
    {
        return Some(Alert {
            kind: AlertKind::FloodAttack,
            description: format!("{} pps from {}", tracker.packet_count, pkt.src_ip),
        });
    }
    
    None
}
```

**C. Brute Force Detection:**
```rust
fn detect_brute_force(&mut self, pkt: &Packet) -> Option<Alert> {
    // Track connections to auth ports (22, 3389, 21, etc.)
    if [22, 3389, 21, 23, 25].contains(&pkt.dst_port) {
        let counter = self.auth_attempts.entry(pkt.src_ip).or_default();
        *counter += 1;
        
        if *counter >= self.brute_force_threshold {
            return Some(Alert {
                kind: AlertKind::BruteForce,
                description: format!("{} failed auth attempts from {}", 
                                     counter, pkt.src_ip),
            });
        }
    }
    
    None
}
```

**IPS Mode:**
When IPS is enabled, the IDS automatically blocks IPs that trigger alerts:
```rust
if self.ips_mode {
    for alert in &alerts {
        self.blacklist.push(alert.source_ip);
        
        // Notify eBPF map for line-rate blocking
        if let Some(tx) = &self.alert_tx {
            tx.send(alert.clone()).await.ok();
        }
    }
}
```

---

#### 5. **VPN Gateway** (`firewallx/src/modules/vpn.rs`)

**Purpose:** Secure tunnel management (WireGuard + IPSec-style)

**Tunnel Lifecycle:**
```
1. Add Peer Configuration
   └─→ PeerConfig { peer_ip, cipher, auth_method, psk, network }

2. Initiate Tunnel
   └─→ Generate tunnel_id
   └─→ State: Negotiating

3. Complete Handshake
   └─→ Verify PSK
   └─→ Derive session keys
   └─→ State: Established

4. Route Traffic
   └─→ Encrypt outbound packets
   └─→ Decrypt inbound packets
   └─→ Update byte counters

5. Rekey (periodic)
   └─→ Generate new session keys
   └─→ Maintain tunnel continuity
```

**Data Structures:**
```rust
pub struct VpnGateway {
    peers: HashMap<Ipv4Addr, PeerConfig>,
    tunnels: HashMap<u32, Tunnel>,
    next_tunnel_id: u32,
}

pub struct Tunnel {
    id: u32,
    peer_ip: Ipv4Addr,
    state: TunnelState,
    cipher: CipherSuite,
    tx_key: [u8; 32],
    rx_key: [u8; 32],
    tx_bytes: u64,
    rx_bytes: u64,
}

pub enum TunnelState {
    Initiating,
    Negotiating,
    Established,
    Closed,
}
```

**Cryptographic Operations:**
```rust
// Supported ciphers
pub enum CipherSuite {
    Aes256Gcm,      // AES-256-GCM
    Chacha20Poly1305, // ChaCha20-Poly1305
}

// Authentication methods
pub enum AuthMethod {
    PreSharedKey,
    PublicKey,      // Future: X25519
}
```

---

#### 6. **Rate Limiter** (`firewallx/src/modules/rate_limiter.rs`)

**Purpose:** Fail2Ban-style per-IP rate limiting

**Algorithm:** Token bucket per IP

```rust
pub struct RateLimiter {
    max_events: u32,
    window: Duration,
    ip_counters: HashMap<Ipv4Addr, IpCounter>,
}

struct IpCounter {
    events: Vec<Instant>,
}

impl RateLimiter {
    pub fn check(&mut self, src_ip: Ipv4Addr) -> bool {
        let counter = self.ip_counters.entry(src_ip).or_default();
        let now = Instant::now();
        
        // Remove old events outside window
        counter.events.retain(|&t| now.duration_since(t) < self.window);
        
        if counter.events.len() as u32 >= self.max_events {
            return false; // Rate limited
        }
        
        counter.events.push(now);
        true // Allowed
    }
}
```

**Usage:**
```rust
// Allow max 100 connections per second per IP
rate_limiter = RateLimiter::new(100, Duration::from_secs(1));

if !rate_limiter.check(packet.src_ip) {
    return Decision::RateLimited;
}
```

---

#### 7. **QoS Manager** (`firewallx/src/modules/qos.rs`)

**Purpose:** Global bandwidth management

**Implementation:**
```rust
pub struct QosManager {
    max_bandwidth_bps: u64,      // Bytes per second
    current_usage: u64,
    last_update: Instant,
}

impl QosManager {
    pub fn check(&mut self, packet_size: usize) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        
        // Decay usage over time
        self.current_usage = (self.current_usage as f64 * (1.0 - elapsed)).max(0.0) as u64;
        
        if self.current_usage + packet_size as u64 > self.max_bandwidth_bps {
            return false; // Over quota
        }
        
        self.current_usage += packet_size as u64;
        self.last_update = now;
        true // Within quota
    }
}
```

---

#### 8. **SIEM Logger** (`firewallx/src/modules/siem.rs`)

**Purpose:** Forward logs to external SIEM (Splunk, ELK, Datadog)

**Integration:**
```rust
pub struct SiemLogger {
    url: String,
    api_key: Option<String>,
    client: reqwest::Client,
    batch: Vec<SiemEvent>,
}

#[derive(Serialize)]
pub struct SiemEvent {
    timestamp: DateTime<Utc>,
    event_type: String,
    severity: String,
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    details: String,
}

async fn flush(&mut self) {
    if self.batch.is_empty() {
        return;
    }
    
    let mut request = self.client.post(&self.url)
        .json(&self.batch);
    
    if let Some(key) = &self.api_key {
        request = request.header("Authorization", format!("Bearer {}", key));
    }
    
    match request.send().await {
        Ok(_) => tracing::info!("SIEM events forwarded"),
        Err(e) => tracing::error!("SIEM send failed: {}", e),
    }
    
    self.batch.clear();
}
```

---

#### 9. **Blocklist Manager** (`firewallx/src/modules/blocklist.rs`)

**Purpose:** Dynamic threat intelligence feed management

**Feed Updates:**
```rust
pub fn fetch_all_ips(&mut self) -> Result<Vec<Ipv4Addr>> {
    let mut all_ips = Vec::new();
    
    for feed_url in &self.feeds {
        match reqwest::blocking::get(feed_url)? {
            response => {
                let ips = parse_ips_from_response(response)?;
                all_ips.extend(ips);
            }
            Err(e) => tracing::warn!("Failed to fetch feed {}: {}", feed_url, e),
        }
    }
    
    Ok(all_ips)
}
```

**eBPF Integration:**
```rust
// Load IPs into kernel for line-rate blocking
#[cfg(target_os = "linux")]
if let Ok(mut block_map) = AyaHashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap()) {
    for ip in &ips {
        let ip_key = u32::from_be_bytes(ip.octets());
        block_map.insert(ip_key, 1u8, 0)?;
    }
}
```

---

## 🔄 Complete Packet Flow Example

Let's trace a real packet through the entire system:

### Scenario: Malicious HTTP Request

**Packet:**
```
Source:      203.0.113.50:54321
Destination: 10.0.0.5:80
Protocol:    TCP
Payload:     "GET /admin?cmd=<script>alert('xss')</script>"
```

**Step-by-Step Processing:**

1. **Packet Reception** (Linux kernel or demo mode)
   ```rust
   let pkt = Packet::new(
       Ipv4Addr::new(203,0,113,50),
       Ipv4Addr::new(10,0,0,5),
       54321, 80,
       Protocol::Tcp,
       Direction::Inbound,
       64, // TTL
   );
   pkt.payload = Some(b"GET /admin?cmd=<script>alert('xss')</script>");
   ```

2. **State Table Lookup**
   ```rust
   if state_table.contains(&pkt) {
       return Action::Allow; // Fast path
   }
   // First packet - continue processing
   ```

3. **Blocklist Check**
   ```rust
   if active_blocks.contains(&Ipv4Addr::new(203,0,113,50)) {
       stats.dropped += 1;
       return Decision::Drop;
   }
   // Not in blocklist - continue
   ```

4. **Rule Evaluation**
   ```rust
   for rule in ruleset.sorted_by_priority() {
       if rule.matches(&pkt) {
           if rule.action == Action::Drop {
               return Decision::Drop;
           }
           break;
       }
   }
   // No matching drop rule - continue
   ```

5. **DPI Inspection**
   ```rust
   let dpi_result = dpi.inspect(pkt.payload.unwrap());
   
   // XSS signature matches!
   // Signature ID: 1003
   // Pattern: "<script>"
   
   if dpi_result.blocked {
       stats.dpi_blocked += 1;
       return Decision::DpiBlock;  // ❌ BLOCKED
   }
   ```

6. **IDS Analysis** (if DPI didn't block)
   ```rust
   let alerts = ids.inspect(&pkt);
   
   // Check behavioral patterns:
   // - Is this part of a port scan? No
   // - Is this a flood? No
   // - Is this brute force? No
   
   if ips_enabled && !alerts.is_empty() {
       return Decision::IpsBlock;
   }
   ```

7. **State Table Addition**
   ```rust
   state_table.add(&pkt, Action::Allow);
   // Future packets from this flow will skip to step 1 and allow immediately
   ```

8. **Final Decision**
   ```rust
   stats.allowed += 1;
   return Decision::Allow;
   ```

**Result:** In our example, the packet is **BLOCKED by DPI** at step 5 due to XSS signature match.

---

## 📊 API Server (Axum)

The REST API provides programmatic access to firewall functions:

**Endpoints:**

```rust
// GET /health
async fn health_check() -> Json<HealthStatus>

// GET /stats
async fn get_stats(State(state): State<DashboardState>) -> Json<EngineStats>

// POST /rules
async fn create_rule(
    State(state): State<DashboardState>,
    Json(req): Json<CreateRuleRequest>,
) -> Result<Json<RuleResponse>>

// GET /rules
async fn list_rules(State(state): State<DashboardState>) -> Json<Vec<Rule>>

// DELETE /rules/:id
async fn delete_rule(
    State(state): State<DashboardState>,
    Path(id): Path<u32>,
) -> Result<Json<()>>

// GET /vpn/status
async fn vpn_status(State(state): State<DashboardState>) -> Json<VpnStatus>

// GET /ids/alerts
async fn list_alerts(State(state): State<DashboardState>) -> Json<Vec<Alert>>
```

**Frontend Integration:**
```typescript
// React/Vue frontend can call these endpoints
const stats = await fetch('http://localhost:3000/stats');
const data = await stats.json();
console.log(`Allowed: ${data.allowed}, Dropped: ${data.dropped}`);
```

---

## 🧪 Testing Strategy

The codebase has comprehensive test coverage:

**Test Categories:**

1. **Unit Tests** - Individual module testing
2. **Integration Tests** - End-to-end packet processing
3. **Property Tests** - Invariant validation
4. **Benchmark Tests** - Performance measurement

**Example Tests:**
```rust
#[test]
fn test_dpi_blocks_sql_injection() {
    let mut dpi = DpiEngine::new();
    let payload = b"' OR '1'='1";
    let result = dpi.inspect(payload);
    assert!(result.blocked);
    assert_eq!(result.matches[0].sig_id, 1001);
}

#[test]
fn test_ids_port_scan_detection() {
    let mut ids = IdsEngine::new();
    ids.port_scan_threshold = 10;
    
    let attacker = Ipv4Addr::new(6,6,6,6);
    for port in 1..=15 {
        let pkt = Packet::new(attacker, Ipv4Addr::new(10,0,0,1), 
                             9000, port, Protocol::Tcp, 
                             Direction::Inbound, 64);
        ids.inspect(&pkt);
    }
    
    let alerts = ids.drain_alerts();
    assert!(alerts.iter().any(|a| a.kind == AlertKind::PortScan));
}

#[test]
fn test_stateful_firewall() {
    let mut engine = FirewallEngine::new(RuleSet::default());
    
    // First packet - evaluated
    let pkt1 = Packet::new(..., 80, ...);
    assert_eq!(engine.process(&pkt1), Decision::Allow);
    
    // Return packet - should be allowed by state
    let pkt2 = Packet::new(..., 80, ...) // reversed IPs/ports
    pkt2.direction = Direction::Outbound;
    assert_eq!(engine.process(&pkt2), Decision::Allow);
}
```

---

## 🚀 Performance Optimizations

### 1. **Fast Path vs Slow Path**

```rust
// Fast path: Established connections (state table hit)
if state_table.contains(pkt) {
    return Action::Allow;  // ~100ns
}

// Slow path: Full evaluation
evaluate_rules(pkt);    // ~500ns
dpi_inspect(pkt);       // ~2μs
ids_analyze(pkt);       // ~1μs
```

### 2. **eBPF Hardware Acceleration**

On Linux with eBPF:
```rust
// Kernel-space blocklist lookup
// Runs at XDP hook before userspace
if BLOCKLIST_MAP.get(&src_ip) {
    return XDP_DROP;  // Line-rate, ~50ns
}
```

### 3. **Batching and Coalescing**

```rust
// Process events in batches
while let Ok(events) = ringbuf.read_events::<Event>(256) {
    process_batch(events);  // Amortize overhead
}
```

### 4. **Per-CPU Data Structures**

```rust
// Avoid lock contention
#[map]
pub static STATS: PerCpuArray<Stats>;

// Each CPU core updates its own counter
// No atomic operations needed
```

---

## 📈 Metrics & Monitoring

**Prometheus Metrics Exported:**
```rust
// Packet counters
firewallx_packets_total{action="allow"}
firewallx_packets_total{action="drop"}
firewallx_packets_total{action="dpi_block"}
firewallx_packets_total{action="ips_block"}

// State table size
firewallx_state_table_entries

// DPI statistics
firewallx_dpi_signatures_loaded
firewallx_dpi_matches_total

// IDS statistics
firewallx_ids_alerts_total{type="port_scan"}
firewallx_ids_alerts_total{type="flood"}
firewallx_ids_blacklist_size

// VPN statistics
firewallx_vpn_active_tunnels
firewallx_vpn_bytes_transmitted
firewallx_vpn_bytes_received

// Performance metrics
firewallx_processing_latency_seconds{quantile="0.5"}
firewallx_processing_latency_seconds{quantile="0.99"}
```

**Dashboard Example:**
```promql
# Packet drop rate
rate(firewallx_packets_total{action="drop"}[1m])

# Top blocked IPs
topk(10, sum by (src_ip) (firewallx_packets_total{action="drop"}))

# DPI effectiveness
sum(firewallx_packets_total{action="dpi_block"}) / sum(firewallx_packets_total)
```

---

## 🎯 Summary

FirewallX is a **multi-layered defense system** combining:

1. ✅ **Stateful packet inspection** - Track connections
2. ✅ **Deep packet inspection** - Payload analysis
3. ✅ **Intrusion detection/prevention** - Behavioral analysis
4. ✅ **Rate limiting** - Fail2Ban-style protection
5. ✅ **Threat intelligence** - Dynamic blocklists
6. ✅ **VPN gateway** - Secure tunnels
7. ✅ **QoS** - Bandwidth management
8. ✅ **SIEM integration** - Centralized logging
9. ✅ **eBPF acceleration** - Kernel-level performance
10. ✅ **AI analysis** - Autonomous threat investigation

All built in **Rust** for safety, speed, and concurrency! 🦀
