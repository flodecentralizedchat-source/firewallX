// firewallx/tests/dpi_ids_vpn_test.rs
// Integration tests: DPI · IDS/IPS · VPN Gateway

use std::net::Ipv4Addr;
use std::time::Duration;

use firewallx::{
    FirewallEngine, Packet, Protocol, Direction,
    Rule, Action, RuleSet,
    DpiEngine, Signature, Severity, SigCategory, AppProtocol,
    IdsEngine, IdsConfig, AlertKind,
    VpnGateway, PeerConfig, CipherSuite, AuthMethod, TunnelState,
};
use firewallx::modules::engine::{Decision, EngineConfig};
use firewallx::modules::vpn::VpnError;

// ─────────────────────────────────────────────────────────────
// DPI Integration
// ─────────────────────────────────────────────────────────────

#[test]
fn dpi_blocks_sql_injection_through_engine() {
    let mut rs = RuleSet::new();
    rs.add(Rule::new(1, "Allow HTTP", Action::Allow, None, None, Some(80), Protocol::Tcp, Direction::Inbound, None));
    let mut engine = FirewallEngine::new(rs);

    let mut pkt = Packet::new(
        Ipv4Addr::new(1,2,3,4), Ipv4Addr::new(10,0,0,1),
        54321, 80, Protocol::Tcp, Direction::Inbound, 64, None
    );
    let payload = b"POST /login HTTP/1.1\r\n\r\nuser=' OR '1'='1";
    assert_eq!(engine.process_with_payload(&mut pkt, payload), Decision::DpiBlock);
    assert_eq!(engine.stats().dpi_blocked, 1);
}

#[test]
fn dpi_blocks_windows_pe_upload() {
    let mut rs = RuleSet::new();
    rs.add(Rule::new(1, "Allow all inbound", Action::Allow, None, None, None, Protocol::Tcp, Direction::Inbound, None));
    let mut engine = FirewallEngine::new(rs);
    let mut pkt = Packet::new(Ipv4Addr::new(2,2,2,2), Ipv4Addr::new(10,0,0,1), 9000, 80, Protocol::Tcp, Direction::Inbound, 100, None);
    let mut payload = b"MZ\x90\x00".to_vec();
    payload.extend_from_slice(&[0u8; 60]);
    assert_eq!(engine.process_with_payload(&mut pkt, &payload), Decision::DpiBlock);
}

#[test]
fn dpi_allows_clean_tls_payload() {
    let mut rs = RuleSet::new();
    rs.add(Rule::new(1, "Allow HTTPS", Action::Allow, None, None, Some(443), Protocol::Tcp, Direction::Outbound, None));
    let mut engine = FirewallEngine::new(rs);
    let mut pkt = Packet::new(Ipv4Addr::new(10,0,0,1), Ipv4Addr::new(1,1,1,1), 49000, 443, Protocol::Tcp, Direction::Outbound, 100, None);
    let payload = b"\x16\x03\x01\x00\xf4\x01\x00\x00\xf0\x03\x03";
    assert_eq!(engine.process_with_payload(&mut pkt, payload), Decision::Allow);
}

#[test]
fn dpi_custom_signature_fires() {
    let mut dpi = DpiEngine::new();
    dpi.add(Signature::new(9001, "Internal secret token", b"INTERNAL_TOKEN_XYZ", 0, Severity::Critical, SigCategory::Policy));
    let payload = b"Authorization: Bearer INTERNAL_TOKEN_XYZ\r\n";
    let result = dpi.inspect(payload);
    assert!(result.matches.iter().any(|m| m.sig_id == 9001));
    assert!(result.blocked);
}

#[test]
fn dpi_protocol_detection_smtp() {
    let mut dpi = DpiEngine::new();
    let result = dpi.inspect(b"EHLO mail.example.com\r\n");
    assert_eq!(result.app_protocol, AppProtocol::Smtp);
}

#[test]
fn dpi_protocol_detection_ftp() {
    let mut dpi = DpiEngine::new();
    let result = dpi.inspect(b"220 FTP Server ready\r\n");
    assert_eq!(result.app_protocol, AppProtocol::Ftp);
}

#[test]
fn dpi_medium_severity_not_blocked_by_default() {
    let mut dpi = DpiEngine::new();
    // XSS is Medium — default block_on = [High, Critical]
    let result = dpi.inspect(b"<script>alert(1)</script>");
    assert!(!result.blocked);
    assert!(!result.matches.is_empty());
}

#[test]
fn dpi_stats_accumulate_per_category() {
    let mut dpi = DpiEngine::new();
    dpi.inspect(b"' OR '1'='1");    // Exploit
    dpi.inspect(b"\x7fELF\x00\x00"); // Malware
    let stats = dpi.stats();
    assert!(*stats.get("Exploit").unwrap_or(&0) >= 1);
    assert!(*stats.get("Malware").unwrap_or(&0) >= 1);
}

#[test]
fn dpi_suricata_integration() {
    use firewallx::modules::suricata::SuricataParser;
    
    let mut dpi = DpiEngine::new();
    
    let snort_rule = r#"
        alert tcp any any -> any any (msg:"MALWARE-CNC Win.Trojan.X"; content:"|2E|php|3F|id|3D|"; classtype:trojan-activity; sid:9000001; rev:1;)
    "#;

    let signatures = SuricataParser::parse_string(snort_rule);
    dpi.extend_signatures(signatures);

    let payload = b"GET /login.php?id=admin HTTP/1.1";
    let result = dpi.inspect(payload);
    
    assert!(result.matches.iter().any(|m| m.sig_id == 9000001));
    assert_eq!(result.matches.iter().find(|m| m.sig_id == 9000001).unwrap().name, "MALWARE-CNC Win.Trojan.X");
    // Since trojan-activity maps to Critical, and default block_on includes Critical, this should be blocked.
    assert!(result.blocked);
}

// ─────────────────────────────────────────────────────────────
// IDS/IPS Integration
// ─────────────────────────────────────────────────────────────

fn ids_cfg() -> IdsConfig {
    IdsConfig {
        window: Duration::from_secs(60),
        port_scan_threshold: 5,
        flood_pps_threshold: 8,
        brute_force_threshold: 3,
        max_payload_bytes: 500,
        block_duration: Duration::from_secs(60),
        ips_mode: false,
    }
}

fn make_pkt(src: Ipv4Addr, dport: u16, proto: Protocol, payload: usize) -> Packet {
    Packet::new(src, Ipv4Addr::new(10,0,0,1), 10000, dport, proto, Direction::Inbound, payload, None)
}

#[test]
fn ids_detects_port_scan_5_ports() {
    let mut ids = IdsEngine::new(ids_cfg());
    let src = Ipv4Addr::new(10, 10, 10, 1);
    for port in [22u16, 80, 443, 8080, 3306] {
        ids.inspect(&make_pkt(src, port, Protocol::Tcp, 0));
    }
    assert!(ids.alerts().iter().any(|a| a.kind == AlertKind::PortScan));
}

#[test]
fn ids_no_alert_below_threshold() {
    let mut ids = IdsEngine::new(ids_cfg());
    let src = Ipv4Addr::new(10, 10, 10, 2);
    for port in [22u16, 80, 443] {
        ids.inspect(&make_pkt(src, port, Protocol::Tcp, 0));
    }
    assert!(!ids.alerts().iter().any(|a| a.kind == AlertKind::PortScan));
}

#[test]
fn ids_detects_syn_flood() {
    let mut ids = IdsEngine::new(ids_cfg());
    let src = Ipv4Addr::new(50, 50, 50, 50);
    for _ in 0..10 {
        ids.inspect(&make_pkt(src, 80, Protocol::Tcp, 0));
    }
    assert!(ids.alerts().iter().any(|a| a.kind == AlertKind::SynFlood));
}

#[test]
fn ids_detects_brute_force_ssh() {
    let mut ids = IdsEngine::new(ids_cfg());
    let src = Ipv4Addr::new(20, 20, 20, 20);
    ids.record_reject(src);
    ids.record_reject(src);
    let alert = ids.record_reject(src);
    assert!(alert.is_some());
    assert_eq!(alert.unwrap().kind, AlertKind::BruteForce);
}

#[test]
fn ids_ips_mode_blocks_after_scan() {
    let mut cfg = ids_cfg();
    cfg.ips_mode = true;
    let mut ids = IdsEngine::new(cfg);
    let src = Ipv4Addr::new(99, 99, 99, 99);
    for port in [22u16, 80, 443, 8080, 3306] {
        ids.inspect(&make_pkt(src, port, Protocol::Tcp, 0));
    }
    // Next packet: should be blocked (IPS mode)
    let alerts = ids.inspect(&make_pkt(src, 5432, Protocol::Tcp, 0));
    assert!(alerts.iter().any(|a| a.block));
}

#[test]
fn ids_engine_integrates_with_firewall_engine() {
    let mut cfg = IdsConfig::default();
    cfg.ips_mode = true;
    cfg.port_scan_threshold = 5;
    cfg.window = Duration::from_secs(60);

    let mut rs = RuleSet::new();
    rs.add(Rule::new(1, "Allow all", Action::Allow, None, None, None, Protocol::Tcp, Direction::Inbound, None));
    let mut engine = FirewallEngine::with_config(rs, EngineConfig::default(), cfg);

    let attacker = Ipv4Addr::new(77, 77, 77, 77);
    // Probe 5 different ports → should trigger scan
    for port in [22u16, 80, 443, 8080, 3306] {
        let mut p = Packet::new(attacker, Ipv4Addr::new(10,0,0,1), 1000, port, Protocol::Tcp, Direction::Inbound, 0, None);
        engine.process(&mut p);
    }
    // Next packet should be IPS-blocked
    let mut p = Packet::new(attacker, Ipv4Addr::new(10,0,0,1), 1000, 5432, Protocol::Tcp, Direction::Inbound, 0, None);
    assert_eq!(engine.process(&mut p), Decision::IpsBlock);
}

#[test]
fn ids_oversized_payload_detected() {
    let mut ids = IdsEngine::new(ids_cfg()); // max_payload = 500
    let src = Ipv4Addr::new(33, 33, 33, 33);
    let alerts = ids.inspect(&make_pkt(src, 80, Protocol::Tcp, 1000));
    assert!(alerts.iter().any(|a| a.kind == AlertKind::OversizedPayload));
}

// ─────────────────────────────────────────────────────────────
// Blocklist / Threat Intel Integration
// ─────────────────────────────────────────────────────────────

#[test]
fn threat_intel_userspace_blocking() {
    let mut rs = RuleSet::new();
    rs.add(Rule::new(1, "Allow all", Action::Allow, None, None, None, Protocol::Any, Direction::Inbound, None));
    
    let mut engine = FirewallEngine::new(rs);
    let malicious_ip = Ipv4Addr::new(203, 0, 113, 99);
    
    // Inject pseudo-fetched blocklist IPs directly into the engine's active_blocks
    let mut malicious_ips = std::collections::HashSet::new();
    malicious_ips.insert(malicious_ip);
    engine.active_blocks = malicious_ips;

    // Traffic from malicious IP should be dropped immediately at Step -1
    let mut pkt_bad = Packet::new(malicious_ip, Ipv4Addr::new(10,0,0,1), 1000, 80, Protocol::Tcp, Direction::Inbound, 0, None);
    assert_eq!(engine.process(&mut pkt_bad), Decision::Drop);
    
    // Traffic from benign IP should be allowed
    let benign_ip = Ipv4Addr::new(8, 8, 8, 8);
    let mut pkt_good = Packet::new(benign_ip, Ipv4Addr::new(10,0,0,1), 1000, 80, Protocol::Tcp, Direction::Inbound, 0, None);
    assert_eq!(engine.process(&mut pkt_good), Decision::Allow);
}

// ─────────────────────────────────────────────────────────────
// Rate Limiter & QoS Integration
// ─────────────────────────────────────────────────────────────

#[test]
fn test_engine_rate_limiting() {
    use firewallx::modules::rate_limiter::RateLimiter;
    use std::time::Duration;

    let mut engine = FirewallEngine::new(RuleSet::new());
    engine.rate_limiter = Some(RateLimiter::new(100, Duration::from_secs(1)));
    
    let attacker = Ipv4Addr::new(99, 99, 99, 99);
    
    // First 100 packets should be allowed (hit default deny since no rules, but for rate limiting we check the counter)
    for _ in 0..100 {
        let mut pkt = make_pkt(attacker, 80, Protocol::Tcp, 0);
        // We expect it to pass RateLimiter, then hit StateTable or RuleSet. Since rule set is empty -> Drop
        assert_eq!(engine.process(&mut pkt), Decision::Drop);
    }
    
    // Packet 101 should be explicitly RateLimited and returned as Drop from Step 0.3
    let mut pkt = make_pkt(attacker, 80, Protocol::Tcp, 0);
    assert_eq!(engine.process(&mut pkt), Decision::Drop);
    assert_eq!(engine.stats().rate_limited, 1);
}

#[test]
fn test_engine_qos_under_load() {
    use firewallx::modules::qos::QosManager;
    use firewallx::modules::packet::QosPriority;

    let mut engine = FirewallEngine::new(RuleSet::new());
    engine.qos_manager = Some(QosManager::new(100_000)); // 100 KB/s
    
    let src = Ipv4Addr::new(10, 0, 0, 5);
    
    // Push 95KB of normal traffic to saturate (threshold is 90KB)
    let mut heavy_pkt = make_pkt(src, 80, Protocol::Tcp, 95_000);
    heavy_pkt.qos = QosPriority::Normal;
    engine.process(&mut heavy_pkt);
    
    // Now the engine is saturated. Standard HTTP traffic should be dropped by QoS.
    let mut normal_pkt = make_pkt(src, 80, Protocol::Tcp, 10_000);
    assert_eq!(engine.process(&mut normal_pkt), Decision::Drop);
    assert_eq!(engine.stats().qos_dropped, 1);
    
    // High-priority SSH traffic (port 22) should bypass QoS drops.
    let mut ssh_pkt = make_pkt(src, 22, Protocol::Tcp, 10_000);
    // Note: It bypasses QoS, then hits default deny -> Drop, but stats.qos_dropped remains 1
    assert_eq!(engine.process(&mut ssh_pkt), Decision::Drop);
    assert_eq!(engine.stats().qos_dropped, 1);
}

// ─────────────────────────────────────────────────────────────
// VPN Gateway & WireGuard Integration
// ─────────────────────────────────────────────────────────────

#[test]
fn test_wireguard_gateway_initialization() {
    use firewallx::modules::wireguard::WgMessageType;

    // Simulate an inbound WireGuard packet
    let payload = [0x01, 0x00, 0x00, 0x00, 0xFF, 0xEE];
    assert_eq!(WgMessageType::from_udp_payload(&payload), WgMessageType::Initiation);
}
    let peer_ip = Ipv4Addr::new(203, 0, 113, 10);
    let mut gw = VpnGateway::new();
    gw.add_peer(
        PeerConfig::new(peer_ip, CipherSuite::Aes256Gcm, AuthMethod::PreSharedKey)
            .with_psk("test_psk_123")
            .with_network("172.16.0.0/12".parse().unwrap())
    );
    (gw, peer_ip)
}

#[test]
fn vpn_full_tunnel_lifecycle() {
    let (mut gw, peer) = make_gateway();
    let tid = gw.initiate(peer).unwrap();
    assert!(gw.session(tid).is_some());
    gw.complete_handshake(tid, Some("test_psk_123")).unwrap();
    assert_eq!(gw.session(tid).unwrap().state, TunnelState::Established);
    gw.close(tid).unwrap();
    assert!(gw.session(tid).is_none());
}

#[test]
fn vpn_wrong_psk_rejected() {
    let (mut gw, peer) = make_gateway();
    let tid = gw.initiate(peer).unwrap();
    let result = gw.complete_handshake(tid, Some("bad_psk"));
    assert_eq!(result, Err(VpnError::AuthFailed(peer)));
}

#[test]
fn vpn_no_duplicate_tunnels() {
    let (mut gw, peer) = make_gateway();
    gw.initiate(peer).unwrap();
    assert_eq!(gw.initiate(peer), Err(VpnError::TunnelAlreadyExists(peer)));
}

#[test]
fn vpn_traffic_accounting_outbound() {
    let (mut gw, peer) = make_gateway();
    let tid = gw.initiate(peer).unwrap();
    gw.complete_handshake(tid, Some("test_psk_123")).unwrap();

    for _ in 0..5 {
        gw.route_outbound(Ipv4Addr::new(172, 16, 1, 1), 200).unwrap();
    }
    let s = gw.session(tid).unwrap();
    assert_eq!(s.packets_out, 5);
    assert_eq!(s.bytes_out,  1000);
}

#[test]
fn vpn_traffic_accounting_inbound() {
    let (mut gw, peer) = make_gateway();
    let tid = gw.initiate(peer).unwrap();
    gw.complete_handshake(tid, Some("test_psk_123")).unwrap();
    gw.route_inbound(peer, 4096).unwrap();
    gw.route_inbound(peer, 2048).unwrap();
    let s = gw.session(tid).unwrap();
    assert_eq!(s.packets_in, 2);
    assert_eq!(s.bytes_in,  6144);
}

#[test]
fn vpn_unestablished_tunnel_cannot_route() {
    let (mut gw, peer) = make_gateway();
    let _tid = gw.initiate(peer).unwrap();
    // Handshake NOT completed
    let result = gw.route_outbound(Ipv4Addr::new(172, 16, 0, 1), 100);
    assert!(result.is_err());
}

#[test]
fn vpn_rekey_produces_new_session_key() {
    let (mut gw, peer) = make_gateway();
    let tid = gw.initiate(peer).unwrap();
    gw.complete_handshake(tid, Some("test_psk_123")).unwrap();
    let old_key = gw.session(tid).unwrap().session_key.clone();
    gw.rekey(tid).unwrap();
    assert_ne!(old_key, gw.session(tid).unwrap().session_key);
}

#[test]
fn vpn_chacha20_peer_establishes() {
    let peer_ip = Ipv4Addr::new(10, 0, 99, 1);
    let mut gw = VpnGateway::new();
    gw.add_peer(
        PeerConfig::new(peer_ip, CipherSuite::ChaCha20Poly1305, AuthMethod::PreSharedKey)
            .with_psk("chacha_key")
            .with_network("192.168.99.0/24".parse().unwrap())
    );
    let tid = gw.initiate(peer_ip).unwrap();
    gw.complete_handshake(tid, Some("chacha_key")).unwrap();
    assert_eq!(gw.session(tid).unwrap().state, TunnelState::Established);
}

#[test]
fn vpn_remove_peer_cleans_up_session() {
    let (mut gw, peer) = make_gateway();
    let tid = gw.initiate(peer).unwrap();
    gw.complete_handshake(tid, Some("test_psk_123")).unwrap();
    gw.remove_peer(&peer);
    assert!(gw.session(tid).is_none());
    assert_eq!(gw.peer_count(), 0);
}

#[test]
fn vpn_routing_to_out_of_range_dst_fails() {
    let (mut gw, peer) = make_gateway();
    let tid = gw.initiate(peer).unwrap();
    gw.complete_handshake(tid, Some("test_psk_123")).unwrap();
    // 10.0.0.1 is NOT in 172.16.0.0/12
    let result = gw.route_outbound(Ipv4Addr::new(10, 0, 0, 1), 64);
    assert!(result.is_err());
}
