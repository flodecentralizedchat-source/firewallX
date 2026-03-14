# FirewallX

**FirewallX** is a modern, fast, and feature-rich Rust-based network utility combining a stateful firewall, Deep Packet Inspection (DPI), Intrusion Detection and Prevention (IDS/IPS), and VPN Gateway capabilities into a cohesive programmable engine.

## Features

- **Stateful Firewall Engine**: Track connections and evaluate traffic against configurable rule sets (Allow/Drop).
- **Deep Packet Inspection (DPI)**: Payload inspection engine to block common exploits such as XSS, Path Traversal, and suspicious executable headers.
- **Intrusion Detection/Prevention (IDS/IPS)**: Behavioral detection of Port Scans, Flood attacks, and Brute-force attempts with automatic blocking strategies.
- **VPN Gateway**: Secure tunnel lifecycle management with PSK authentication, cryptography (e.g., AES-256-GCM, ChaCha20-Poly1305), and automatic rekeying.
- **NAT & Logging**: Integrated Network Address Translation and rich event logging capabilities.

## Module Structure

- `engine`: Main firewall, state tracking, and rule evaluation.
- `dpi`: Deep Packet Inspection using signature matching for protocols like HTTP, SSH, and specific exploit payloads.
- `ids`: Analyzes traffic patterns to detect and mitigate malicious behaviors.
- `vpn`: Establishes secure tunnels, handles handshakes, traffic routing, and cryptographic sessions.
- `packet`, `rule`, `state`, `logger`, `nat`, `error`: Core utilities for network packet representation and state transition.

## Getting Started

### Prerequisites
- [Rust](https://rustup.rs/) (1.70+ recommended)

### Integration Example

FirewallX can be used as a backend library for custom networking appliances or as a standalone demonstration engine. Here is a basic code example combining Firewall Rules, IDS, and DPI.

```rust
use std::time::Duration;
use firewallx::{
    FirewallEngine, Packet, Protocol, Direction,
    Rule, Action, RuleSet, IdsConfig
};
use firewallx::modules::engine::EngineConfig;

fn main() {
    let mut rules = RuleSet::new();
    rules.add(Rule::new(1, "Allow SSH", Action::Allow, None, None, Some(22), Protocol::Tcp, Direction::Inbound));
    rules.add(Rule::new(999, "Default Drop", Action::Drop, None, None, None, Protocol::Any, Direction::Inbound));

    let ids_cfg = IdsConfig {
        ips_mode: true,
        port_scan_threshold: 6,
        flood_pps_threshold: 20,
        brute_force_threshold: 3,
        window: Duration::from_secs(30),
        max_payload_bytes: 65_000,
        block_duration: Duration::from_secs(120),
    };

    let mut engine = FirewallEngine::with_config(rules, EngineConfig::default(), ids_cfg);

    // Provide a sample HTTP packet and payload to trigger deep-packet inspection
    let pkt = Packet::new(...);
    let decision = engine.process_with_payload(&pkt, b"GET /login?user=' OR '1'='1&pass=x HTTP/1.1\r\n");
    println!("Action: {:?}", decision);
}
```

### Running the Demo

The `main.rs` file included in this repository serves as a comprehensive demo of FirewallX's capabilities. 
To run the demo locally, move into the project base directory and start the engine:

```bash
RUST_LOG=info cargo run --release
```

To run the test suite for all modules (including DPI and VPN specs):

```bash
cargo test
```

## Architecture

FirewallX expects packets to be parsed and passed as `Packet` structs. The data pipeline execution flow is broadly:

1. **Rule Evaluation**: Evaluates incoming packets against local whitelist/blacklist rules.
2. **IDS/IPS Analysis**: Records packet metadata to detect behavioral anomalies (e.g., port exhaustion). Drops the connection if the source is flagged.
3. **DPI Inspection**: When application-layer payloads are provided, DPI scans against internal threat signatures.
4. **State Tracking**: Valid connections are added to the state table to accelerate future packets in the flow without redundant checks.

## Contributing

Contributions are heavily encouraged! If you're looking to help out, we're especially interested in:
- New DPI signatures
- More intricate protocol support (such as QUIC, WireGuard capabilities)
- Performance optimizations and memory scaling
- Expanded test coverage

Please submit a PR or open an issue regarding major architectural changes.

## License

This project is open-source and available under the terms of the **MIT License**.
