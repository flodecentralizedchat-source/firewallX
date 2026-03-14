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

FirewallX is pre-packaged as a standalone Debian application (`.deb`). You do not need to compile the code or write a custom `main.rs`. Once installed, you can configure the firewall directly from the command line:

```bash
# Block all incoming SSH traffic instantly
sudo firewallx rule add --name "Block SSH" --action drop --port 22 --protocol tcp --direction inbound

# View the active programmatic configuration
sudo firewallx rule list
```

### Running the Engine

You can start the engine in the foreground to watch traffic alerts in real-time. It will automatically load the configured eBPF program into the kernel if you are on a compatible Linux environment:

```bash
sudo firewallx start
```

### Running the eBPF Demo (Docker)

If you are on macOS or Windows and want to test the blazing-fast eBPF kernel drops, we have provided a Docker setup that runs the engine in a privileged Linux container. Ensure Docker Desktop is running, then execute:

```bash
docker compose up --build
```

Once running, you can connect to the container and run `nmap localhost` to trigger the IDS and watch the kernel instantly drop your subsequent traffic!

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
