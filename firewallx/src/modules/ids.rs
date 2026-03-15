// firewallx/src/modules/ids.rs
// Intrusion Detection & Prevention System (IDS/IPS)
//
// Detects attack patterns by combining:
//   - Rate-based detection  (port scans, brute force, DDoS floods)
//   - Anomaly detection     (oversized payloads, unusual flag combinations)
//   - Behavioural tracking  (per-source connection history)

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use serde::{Serialize, Deserialize};
use tokio::sync::mpsc;

use crate::modules::packet::{Direction, Packet, Protocol};

// ─────────────────────────────────────────────────────────────
// Alert types
// ─────────────────────────────────────────────────────────────

/// Category of intrusion event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertKind {
    PortScan,
    BruteForce,
    SynFlood,
    UdpFlood,
    IcmpFlood,
    OversizedPayload,
    ProtocolAnomaly,
    RepeatedReject,
    BlacklistedIp,
}

impl std::fmt::Display for AlertKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// A single IDS/IPS alert.
#[derive(Debug, Clone)]
pub struct Alert {
    pub kind: AlertKind,
    pub src_ip: Ipv4Addr,
    pub description: String,
    pub timestamp: Instant,
    /// If `true` (IPS mode), the engine will block the packet.
    pub block: bool,
}

impl Alert {
    fn new(kind: AlertKind, src_ip: Ipv4Addr, description: &str, block: bool) -> Self {
        Self { kind, src_ip, description: description.to_owned(), timestamp: Instant::now(), block }
    }
}

// ─────────────────────────────────────────────────────────────
// Per-source behavioural tracker
// ─────────────────────────────────────────────────────────────

#[derive(Debug)]
struct SourceRecord {
    /// All destination ports seen in the current window.
    ports_seen: Vec<u16>,
    /// Packet count in the current window.
    pkt_count: u64,
    /// SYN count (TCP only) in the current window.
    syn_count: u64,
    /// UDP packet count in the current window.
    udp_count: u64,
    /// ICMP count in the current window.
    icmp_count: u64,
    /// Rejected packet count in the current window.
    reject_count: u64,
    /// Start of the current measurement window.
    window_start: Instant,
    /// Whether this source is currently blocked (IPS mode).
    blocked_until: Option<Instant>,
}

impl SourceRecord {
    fn new() -> Self {
        Self {
            ports_seen: Vec::new(),
            pkt_count: 0,
            syn_count: 0,
            udp_count: 0,
            icmp_count: 0,
            reject_count: 0,
            window_start: Instant::now(),
            blocked_until: None,
        }
    }

    /// Reset counters if the measurement window has expired.
    fn maybe_reset(&mut self, window: Duration) {
        if self.window_start.elapsed() >= window {
            self.ports_seen.clear();
            self.pkt_count = 0;
            self.syn_count = 0;
            self.udp_count = 0;
            self.icmp_count = 0;
            self.reject_count = 0;
            self.window_start = Instant::now();
        }
    }

    fn is_blocked(&self) -> bool {
        self.blocked_until.map(|t| Instant::now() < t).unwrap_or(false)
    }
}

// ─────────────────────────────────────────────────────────────
// IDS configuration thresholds
// ─────────────────────────────────────────────────────────────

/// Tunable thresholds for all detectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsConfig {
    /// Detection window duration.
    pub window: Duration,
    /// Unique destination ports that trigger a port-scan alert.
    pub port_scan_threshold: usize,
    /// Packets per window that trigger a flood alert (per-protocol).
    pub flood_pps_threshold: u64,
    /// Failed/rejected packets per window for brute-force detection.
    pub brute_force_threshold: u64,
    /// Payload size (bytes) that triggers an oversized-payload alert.
    pub max_payload_bytes: usize,
    /// Duration to block a source after an IPS trigger.
    pub block_duration: Duration,
    /// Run in IPS mode (block) rather than IDS mode (alert only).
    pub ips_mode: bool,
}

impl Default for IdsConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(10),
            port_scan_threshold: 15,
            flood_pps_threshold: 500,
            brute_force_threshold: 10,
            max_payload_bytes: 65_000,
            block_duration: Duration::from_secs(300),
            ips_mode: false,
        }
    }
}

// ─────────────────────────────────────────────────────────────
// IDS/IPS engine
// ─────────────────────────────────────────────────────────────

/// The IDS/IPS engine.
pub struct IdsEngine {
    config: IdsConfig,
    sources: HashMap<Ipv4Addr, SourceRecord>,
    blacklist: Vec<Ipv4Addr>,
    alerts: Vec<Alert>,
    total_alerts: u64,
    pub alert_tx: Option<mpsc::Sender<Alert>>,
}

impl IdsEngine {
    pub fn new(config: IdsConfig) -> Self {
        Self {
            config,
            sources: HashMap::new(),
            blacklist: Vec::new(),
            alerts: Vec::new(),
            total_alerts: 0,
            alert_tx: None,
        }
    }

    /// Manually blacklist a source IP (always blocked in IPS mode).
    pub fn blacklist(&mut self, ip: Ipv4Addr) {
        if !self.blacklist.contains(&ip) {
            self.blacklist.push(ip);
        }
    }

    /// Remove an IP from the blacklist.
    pub fn unblacklist(&mut self, ip: &Ipv4Addr) -> bool {
        let before = self.blacklist.len();
        self.blacklist.retain(|x| x != ip);
        self.blacklist.len() < before
    }

    /// Inspect a packet. Returns a list of alerts (may be empty).
    /// In IPS mode, any alert with `block = true` means the packet should be dropped.
    pub fn inspect(&mut self, pkt: &Packet) -> Vec<Alert> {
        let mut fired: Vec<Alert> = Vec::new();
        let src = pkt.src_ip;

        // ── Blacklist check ───────────────────────────────────
        if self.blacklist.contains(&src) {
            fired.push(Alert::new(
                AlertKind::BlacklistedIp, src,
                "Source IP is blacklisted",
                self.config.ips_mode,
            ));
            self.commit_alerts(&fired);
            return fired;
        }

        // ── Retrieve / create source record ──────────────────
        let rec = self.sources.entry(src).or_insert_with(SourceRecord::new);
        rec.maybe_reset(self.config.window);

        // Already IPS-blocked?
        if rec.is_blocked() {
            fired.push(Alert::new(
                AlertKind::BlacklistedIp, src,
                "Source temporarily blocked by IPS",
                true,
            ));
            self.commit_alerts(&fired);
            return fired;
        }

        // ── Update counters ───────────────────────────────────
        rec.pkt_count += 1;
        if !rec.ports_seen.contains(&pkt.dst_port) {
            rec.ports_seen.push(pkt.dst_port);
        }
        match pkt.protocol {
            Protocol::Tcp  => rec.syn_count  += 1,
            Protocol::Udp  => rec.udp_count  += 1,
            Protocol::Icmp => rec.icmp_count += 1,
            Protocol::Any  => {}
        }

        // ── Port scan detection ───────────────────────────────
        if rec.ports_seen.len() >= self.config.port_scan_threshold
            && pkt.direction == Direction::Inbound
        {
            fired.push(Alert::new(
                AlertKind::PortScan, src,
                &format!("{} distinct ports probed in {:?}", rec.ports_seen.len(), self.config.window),
                self.config.ips_mode,
            ));
        }

        // ── SYN flood detection ───────────────────────────────
        if pkt.protocol == Protocol::Tcp
            && rec.syn_count >= self.config.flood_pps_threshold
            && pkt.direction == Direction::Inbound
        {
            fired.push(Alert::new(
                AlertKind::SynFlood, src,
                &format!("{} SYN packets in {:?}", rec.syn_count, self.config.window),
                self.config.ips_mode,
            ));
        }

        // ── UDP flood detection ───────────────────────────────
        if pkt.protocol == Protocol::Udp
            && rec.udp_count >= self.config.flood_pps_threshold
            && pkt.direction == Direction::Inbound
        {
            fired.push(Alert::new(
                AlertKind::UdpFlood, src,
                &format!("{} UDP packets in {:?}", rec.udp_count, self.config.window),
                self.config.ips_mode,
            ));
        }

        // ── ICMP flood detection ──────────────────────────────
        if pkt.protocol == Protocol::Icmp
            && rec.icmp_count >= self.config.flood_pps_threshold
            && pkt.direction == Direction::Inbound
        {
            fired.push(Alert::new(
                AlertKind::IcmpFlood, src,
                &format!("{} ICMP packets in {:?}", rec.icmp_count, self.config.window),
                self.config.ips_mode,
            ));
        }

        // ── Oversized payload detection ───────────────────────
        if pkt.payload_len > self.config.max_payload_bytes {
            fired.push(Alert::new(
                AlertKind::OversizedPayload, src,
                &format!("payload {} bytes exceeds limit {}", pkt.payload_len, self.config.max_payload_bytes),
                self.config.ips_mode,
            ));
        }

        // ── IPS: apply temporary block if any alert fired ─────
        if self.config.ips_mode && !fired.is_empty() {
            let rec2 = self.sources.get_mut(&src).unwrap();
            rec2.blocked_until = Some(Instant::now() + self.config.block_duration);
        }

        self.commit_alerts(&fired);
        fired
    }

    /// Mark a packet as rejected (for brute-force tracking).
    pub fn record_reject(&mut self, src: Ipv4Addr) -> Option<Alert> {
        let rec = self.sources.entry(src).or_insert_with(SourceRecord::new);
        rec.maybe_reset(self.config.window);
        rec.reject_count += 1;

        if rec.reject_count >= self.config.brute_force_threshold {
            let alert = Alert::new(
                AlertKind::BruteForce, src,
                &format!("{} rejected packets in {:?}", rec.reject_count, self.config.window),
                self.config.ips_mode,
            );
            self.total_alerts += 1;
            self.alerts.push(alert.clone());
            return Some(alert);
        }
        None
    }

    fn commit_alerts(&mut self, alerts: &[Alert]) {
        self.total_alerts += alerts.len() as u64;
        self.alerts.extend_from_slice(alerts);
        
        if let Some(tx) = &self.alert_tx {
            for a in alerts {
                // Non-blocking try_send for real-time engine loop
                let _ = tx.try_send(a.clone());
            }
        }
    }

    pub fn alerts(&self) -> &[Alert] {
        &self.alerts
    }

    pub fn total_alerts(&self) -> u64 {
        self.total_alerts
    }

    pub fn config(&self) -> &IdsConfig {
        &self.config
    }

    pub fn config_mut(&mut self) -> &mut IdsConfig {
        &mut self.config
    }

    /// Drain and return all buffered alerts (clears the internal list).
    pub fn drain_alerts(&mut self) -> Vec<Alert> {
        std::mem::take(&mut self.alerts)
    }
}

// ─────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use crate::modules::packet::{Packet, Protocol, Direction};

    fn cfg_low_threshold() -> IdsConfig {
        IdsConfig {
            window: Duration::from_secs(60),
            port_scan_threshold: 5,
            flood_pps_threshold: 10,
            brute_force_threshold: 3,
            max_payload_bytes: 1000,
            block_duration: Duration::from_secs(60),
            ips_mode: false,
        }
    }

    fn pkt(src: Ipv4Addr, dst_port: u16, proto: Protocol, dir: Direction, payload: usize) -> Packet {
        Packet::new(src, Ipv4Addr::new(10,0,0,1), 12345, dst_port, proto, dir, payload)
    }

    #[test]
    fn test_port_scan_detection() {
        let mut ids = IdsEngine::new(cfg_low_threshold());
        let attacker = Ipv4Addr::new(1, 2, 3, 4);
        for port in 20..26u16 {
            ids.inspect(&pkt(attacker, port, Protocol::Tcp, Direction::Inbound, 0));
        }
        assert!(ids.alerts().iter().any(|a| a.kind == AlertKind::PortScan));
    }

    #[test]
    fn test_syn_flood_detection() {
        let mut ids = IdsEngine::new(cfg_low_threshold());
        let attacker = Ipv4Addr::new(5, 5, 5, 5);
        for _ in 0..12 {
            ids.inspect(&pkt(attacker, 80, Protocol::Tcp, Direction::Inbound, 0));
        }
        assert!(ids.alerts().iter().any(|a| a.kind == AlertKind::SynFlood));
    }

    #[test]
    fn test_udp_flood_detection() {
        let mut ids = IdsEngine::new(cfg_low_threshold());
        let attacker = Ipv4Addr::new(6, 6, 6, 6);
        for _ in 0..12 {
            ids.inspect(&pkt(attacker, 53, Protocol::Udp, Direction::Inbound, 0));
        }
        assert!(ids.alerts().iter().any(|a| a.kind == AlertKind::UdpFlood));
    }

    #[test]
    fn test_icmp_flood_detection() {
        let mut ids = IdsEngine::new(cfg_low_threshold());
        let attacker = Ipv4Addr::new(7, 7, 7, 7);
        for _ in 0..12 {
            ids.inspect(&pkt(attacker, 0, Protocol::Icmp, Direction::Inbound, 0));
        }
        assert!(ids.alerts().iter().any(|a| a.kind == AlertKind::IcmpFlood));
    }

    #[test]
    fn test_oversized_payload() {
        let mut ids = IdsEngine::new(cfg_low_threshold());
        let src = Ipv4Addr::new(9, 9, 9, 9);
        let alerts = ids.inspect(&pkt(src, 80, Protocol::Tcp, Direction::Inbound, 2000));
        assert!(alerts.iter().any(|a| a.kind == AlertKind::OversizedPayload));
    }

    #[test]
    fn test_brute_force_detection() {
        let mut ids = IdsEngine::new(cfg_low_threshold());
        let src = Ipv4Addr::new(11, 11, 11, 11);
        ids.record_reject(src);
        ids.record_reject(src);
        let result = ids.record_reject(src);
        assert!(result.is_some());
        assert_eq!(result.unwrap().kind, AlertKind::BruteForce);
    }

    #[test]
    fn test_blacklist_immediately_alerts() {
        let mut ids = IdsEngine::new(cfg_low_threshold());
        let evil = Ipv4Addr::new(10, 10, 10, 10);
        ids.blacklist(evil);
        let alerts = ids.inspect(&pkt(evil, 22, Protocol::Tcp, Direction::Inbound, 0));
        assert!(alerts.iter().any(|a| a.kind == AlertKind::BlacklistedIp));
    }

    #[test]
    fn test_unblacklist() {
        let mut ids = IdsEngine::new(cfg_low_threshold());
        let ip = Ipv4Addr::new(55, 55, 55, 55);
        ids.blacklist(ip);
        assert!(ids.unblacklist(&ip));
        // Now no blacklist alert
        let alerts = ids.inspect(&pkt(ip, 80, Protocol::Tcp, Direction::Inbound, 0));
        assert!(!alerts.iter().any(|a| a.kind == AlertKind::BlacklistedIp));
    }

    #[test]
    fn test_ips_mode_blocks_after_alert() {
        let mut cfg = cfg_low_threshold();
        cfg.ips_mode = true;
        let mut ids = IdsEngine::new(cfg);
        let attacker = Ipv4Addr::new(20, 20, 20, 20);
        // Trigger port scan
        for port in 80..86u16 {
            ids.inspect(&pkt(attacker, port, Protocol::Tcp, Direction::Inbound, 0));
        }
        // Next packet should be auto-blocked
        let alerts = ids.inspect(&pkt(attacker, 443, Protocol::Tcp, Direction::Inbound, 0));
        assert!(alerts.iter().any(|a| a.block));
    }

    #[test]
    fn test_clean_source_no_alerts() {
        let mut ids = IdsEngine::new(cfg_low_threshold());
        let legit = Ipv4Addr::new(192, 168, 1, 5);
        let alerts = ids.inspect(&pkt(legit, 443, Protocol::Tcp, Direction::Outbound, 128));
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_drain_alerts() {
        let mut ids = IdsEngine::new(cfg_low_threshold());
        let src = Ipv4Addr::new(30, 30, 30, 30);
        ids.inspect(&pkt(src, 80, Protocol::Tcp, Direction::Inbound, 99999));
        let drained = ids.drain_alerts();
        assert!(!drained.is_empty());
        assert!(ids.alerts().is_empty());
    }
}
