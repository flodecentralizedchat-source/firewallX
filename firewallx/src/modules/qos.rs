// firewallx/src/modules/qos.rs
// Global Quality of Service and Traffic Shaping

use crate::modules::packet::{Packet, QosPriority};
use std::time::{Duration, Instant};

/// Monitors global throughput and enforces QoS dropping under heavy load.
pub struct QosManager {
    /// Maximum configured bandwidth capacity in bytes/sec
    pub max_bandwidth_bps: u64,
    /// Internal byte counter for the current second
    current_bytes: u64,
    /// Last execution time of the leaky bucket drain
    last_drain: Instant,
}

impl QosManager {
    pub fn new(max_bandwidth_bps: u64) -> Self {
        Self {
            max_bandwidth_bps,
            current_bytes: 0,
            last_drain: Instant::now(),
        }
    }

    /// Accumulates `bytes` and decays history based on time passed.
    /// Returns `true` if the packet should be DROPPED due to QoS saturation.
    pub fn check(&mut self, pkt: &Packet) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_drain);
        
        // Leaky bucket drain: reduce `current_bytes` based on elapsed time vs capacity
        if elapsed > Duration::from_millis(100) {
            let drain_amount = (self.max_bandwidth_bps as f64 * elapsed.as_secs_f64()) as u64;
            self.current_bytes = self.current_bytes.saturating_sub(drain_amount);
            self.last_drain = now;
        }

        let saturation_threshold = (self.max_bandwidth_bps as f64 * 0.90) as u64;
        let was_saturated = self.current_bytes > saturation_threshold;

        self.current_bytes += pkt.payload_len as u64;

        if was_saturated {
            // Drop Normal priority traffic to preserve High/Critical traffic
            if pkt.qos == QosPriority::Normal {
                return true; 
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use crate::modules::packet::{Protocol, Direction};

    fn dummy_pkt(priority: QosPriority, size: usize) -> Packet {
        let mut p = Packet::new(
            Ipv4Addr::new(1,2,3,4), Ipv4Addr::new(10,0,0,1),
            1234, 80, Protocol::Tcp, Direction::Inbound, size
        );
        p.qos = priority;
        p
    }

    #[test]
    fn test_qos_allows_under_threshold() {
        let mut qos = QosManager::new(100_000); // 100 KB/s max
        let pkt = dummy_pkt(QosPriority::Normal, 50_000);
        assert!(!qos.check(&pkt));
    }

    #[test]
    fn test_qos_drops_normal_when_saturated() {
        let mut qos = QosManager::new(100_000); // 100 KB/s
        
        // Push 95KB of normal traffic -> hits saturation threshold (90KB)
        let pkt1 = dummy_pkt(QosPriority::Normal, 95_000);
        assert!(!qos.check(&pkt1)); // Allowed because it pushes _into_ saturation limit

        // Saturation is tripped, so subsequent Normal packets drop
        let pkt_normal = dummy_pkt(QosPriority::Normal, 10_000);
        assert!(qos.check(&pkt_normal));

        // High priority traffic bypasses saturation drops
        let pkt_high = dummy_pkt(QosPriority::High, 10_000);
        assert!(!qos.check(&pkt_high));
    }
}
