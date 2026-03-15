# Configure eBPF Performance Optimization

Tune eBPF program parameters, map sizes, and XDP hooks for maximum throughput and minimal latency in FirewallX deployments.

## Purpose

Optimize the FirewallX eBPF kernel module for:
- Line-rate packet processing (10Gbps+)
- Sub-microsecond decision latency
- Efficient memory utilization
- Scalability across CPU cores
- Minimal CPU overhead

## Configuration Areas

### 1. XDP Program Tuning

**Attachment Mode:**

Choose optimal XDP mode based on NIC capabilities:

```bash
# Native XDP (fastest - requires driver support)
ip link set dev eth0 xdp obj firewallx-ebpf.o sec .text

# Generic XDP (slower but universally compatible)
ip link set dev eth0 xdp-generic obj firewallx-ebpf.o sec .text

# Offload to NIC (if supported by hardware)
ip link set dev eth0 xdp offload obj firewallx-ebpf.o sec .text
```

**Driver Recommendations:**
- ✅ mlx5 (Mellanox ConnectX series) - Excellent
- ✅ ice (Intel E810) - Excellent  
- ✅ ena (AWS Nitro) - Good
- ⚠️ veth (Docker/containers) - Limited support
- ❌ Some older drivers - May not support native XDP

### 2. Map Size Optimization

**Blocklist HashMap:**

```rust
// In firewallx-ebpf/src/main.rs

#[map]
pub static mut BLOCKLIST: HashMap<u32, u8> = HashMap::with_max_entries(1_000_000);

// Tuning guidance:
// - 10K entries: ~40KB memory, <100ns lookup
// - 100K entries: ~400KB memory, ~150ns lookup  
// - 1M entries: ~4MB memory, ~200ns lookup
// - 10M entries: ~40MB memory, ~300ns lookup
```

**Configuration in userspace:**

```toml
# config.toml
[ebpf]
blocklist_max_entries = 1000000
ring_buffer_size_pages = 1024  # 4MB ring buffer for events
event_batch_size = 256         # Process events in batches
```

### 3. Ring Buffer Sizing

For high-throughput event logging:

```rust
// Larger buffers = less drops but higher memory usage
// Smaller buffers = more drops but lower latency

#[map]
pub static mut EVENTS: RingBuffer = RingBuffer::with_capacity(4 * 1024 * 1024); // 4MB

// Recommended sizes:
// - Low traffic (<10K pps): 1MB
// - Medium traffic (10-100K pps): 4MB
// - High traffic (>100K pps): 16MB+
```

### 4. Per-CPU Maps

Scale across CPU cores:

```rust
// Avoid lock contention with per-CPU counters
#[map]
pub static mut STATS: PerCpuArray<Stats> = PerCpuArray::new();

struct Stats {
    packets_processed: u64,
    packets_dropped: u64,
    bytes_processed: u64,
}

// Each CPU core gets its own counter instance
// No atomic operations needed = faster updates
```

### 5. Tail Calls for Modular Processing

Chain multiple eBPF programs:

```rust
// Program chain: XDP → DPI → IDS → Final Decision

#[program]
pub fn firewallx_xdp(ctx: XdpContext) -> XdpAction {
    // Quick initial filtering
    if is_in_blocklist(&ctx) {
        return XdpAction::Drop;
    }
    
    // Tail call to DPI for deep inspection
    dpi_program.call(&ctx);
    
    // Fallthrough to IDS
    ids_program.call(&ctx);
    
    XdpAction::Pass
}

// Benefits:
// - Each program stays within instruction limits
// - Easier to maintain and debug
// - Can skip stages dynamically
```

## Performance Benchmarks

### Expected Throughput

| Hardware | Cores | NIC Speed | Max PPS | Latency (p99) |
|----------|-------|-----------|---------|---------------|
| AWS c6i.xlarge | 4 | 12.5 Gbps | 10M | 2.5μs |
| Bare-metal (i9-13900K) | 8 | 25 Gbps | 20M | 1.2μs |
| Cloud (m6i.metal) | 16 | 100 Gbps | 50M | 0.8μs |

### Measurement Commands

```bash
# Measure XDP drop rate
bpftool prog show name firewallx_ebpf

# Check map memory usage
bpftool map list

# Profile eBPF program execution time
perf record -e bpf:bpf_prog_run -a sleep 10

# Monitor ring buffer drops
cat /sys/kernel/debug/tracing/trace_pipe | grep "ringbuf: lost"
```

## Troubleshooting

### Problem: High Drop Rate on Legitimate Traffic

**Diagnosis:**
```bash
# Check blocklist size
firewallx blocklist count

# Monitor false positives
firewallx logs --action DROP --since 1h | sort | uniq -c | head -20
```

**Solution:**
- Reduce blocklist aggressiveness
- Add whitelist entries for trusted IPs
- Lower IDS sensitivity thresholds

### Problem: eBPF Program Fails to Load

**Common Errors:**

1. **Verifier Error: "invalid memory access"**
   ```rust
   // WRONG: Accessing uninitialized variable
   let ip: u32;
   if (condition) { ip = src_ip; }
   check_ip(ip); // Verifier rejects this
   
   // RIGHT: Initialize at declaration
   let mut ip: u32 = 0;
   if (condition) { ip = src_ip; }
   check_ip(ip);
   ```

2. **Verifier Error: "too many instructions"**
   - Split into multiple programs with tail calls
   - Remove unnecessary helper function calls
   - Use BPF_F_INLINE attribute

3. **Map Creation Failed: "memory limit exceeded"**
   - Reduce `max_entries` parameter
   - Free unused maps before loading new ones
   - Check RLIMIT_MEMLOCK: `ulimit -l unlimited`

### Problem: Ring Buffer Events Dropped

**Symptoms:**
```
[ringbuf] Lost 1234 events (buffer full)
```

**Solutions:**
1. Increase ring buffer size:
   ```rust
   RingBuffer::with_capacity(16 * 1024 * 1024) // 16MB
   ```

2. Process events faster in userspace:
   ```rust
   // Batch processing
   while let Ok(events) = ringbuf.read_events::<Event>(batch_size=1024) {
       process_batch(events);
   }
   ```

3. Reduce event verbosity:
   ```toml
   # Only log significant events
   [logging]
   min_severity = "WARNING"  # Skip INFO/DEBUG
   sample_rate = 0.1         # Log 10% of allowed packets
   ```

## Advanced Optimizations

### 1. LRU Cache for Hot Blocklist Entries

```rust
// Keep frequently-accessed IPs in fast cache
#[map]
pub static mut BLOCKLIST_CACHE: LruCache<u32, u8> = 
    LruCache::with_max_entries(1024);

// Check cache first (O(1)), then full table (O(log n))
if BLOCKLIST_CACHE.get(&src_ip).is_some() {
    return XdpAction::Drop;
}
```

### 2. Bloom Filter for Space Efficiency

```rust
// Probabilistic membership test
// 10x smaller than HashMap, but has false positives
#[map]
pub static mut BLOCKLIST_BLOOM: BloomFilter = BloomFilter::new();

// Use as first-stage filter
if !BLOCKLIST_BLOOM.test(&src_ip) {
    return XdpAction::Pass; // Definitely not in blocklist
}
// Fall through to exact match for positive results
```

### 3. Jiffies-Based Time Checks

```rust
// Efficient time-based rules without clock syscalls
let now = unsafe { bpf_ktime_get_ns() };
let last_seen = get_last_packet_time(src_ip);

if now - last_seen < NANOSECONDS_PER_SECOND {
    increment_rate_counter(src_ip);
}
```

## Deployment Checklist

Before production deployment:

- [ ] Test on non-production system for 24+ hours
- [ ] Verify no critical services are blocked (false positives)
- [ ] Benchmark throughput with production-like traffic
- [ ] Set up monitoring for eBPF program health
- [ ] Configure alert for ring buffer overflows
- [ ] Document rollback procedure
- [ ] Train ops team on troubleshooting commands
- [ ] Schedule regular performance reviews
