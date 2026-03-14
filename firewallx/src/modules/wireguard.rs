// firewallx/src/modules/wireguard.rs
// Native WireGuard Configuration Parser and Packet Identifier

use crate::modules::vpn::{PeerConfig, AuthMethod, CipherSuite, VpnError, VpnResult};
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use std::net::Ipv4Addr;
use ipnet::Ipv4Net;

/// The 4 fundamental packet types in the WireGuard UDP protocol.
#[derive(Debug, PartialEq, Eq)]
pub enum WgMessageType {
    /// Handshake Initiation (Type 1)
    Initiation,
    /// Handshake Response (Type 2)
    Response,
    /// Cookie Reply (Type 3)
    CookieReply,
    /// Transport Data (Type 4)
    TransportData,
    /// Unrecognized / Not WireGuard
    Unknown,
}

impl WgMessageType {
    /// Attempts to identify a WireGuard packet by reading the first 32 bits (4 bytes)
    /// of the UDP payload. WireGuard uniquely prefixes its payloads with a specific Type byte 
    /// and 3 padding zeroes (reserved).
    pub fn from_udp_payload(payload: &[u8]) -> Self {
        if payload.len() < 4 {
            return WgMessageType::Unknown;
        }

        // WireGuard Message Type is byte 0, followed by 3 reserved padding zeroes.
        if payload[1] != 0 || payload[2] != 0 || payload[3] != 0 {
            return WgMessageType::Unknown; // Reserved padding check failed
        }

        match payload[0] {
            1 => WgMessageType::Initiation,
            2 => WgMessageType::Response,
            3 => WgMessageType::CookieReply,
            4 => WgMessageType::TransportData,
            _ => WgMessageType::Unknown,
        }
    }
}

/// Parses a standard `wg0.conf` INI file and extracts usable `PeerConfig`s.
pub struct WgConfigParser;

impl WgConfigParser {
    /// Parse a given `wg0.conf` file. Returns a list of `PeerConfig` objects
    /// that are instantly importable into the FirewallX `VpnGateway`.
    pub fn parse_file<P: AsRef<Path>>(path: P) -> VpnResult<Vec<PeerConfig>> {
        let file = File::open(path).map_err(|_| VpnError::TunnelNotEstablished(0))?;
        let reader = io::BufReader::new(file);

        let mut peers = Vec::new();
        let mut current_block = String::new();

        // Variables for the current [Peer] block being parsed
        let mut endpoint: Option<Ipv4Addr> = None;
        let mut public_key: Option<String> = None;
        let mut allowed_ips: Vec<Ipv4Net> = Vec::new();

        for line in reader.lines() {
            let line = line.unwrap_or_default();
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Block transitions
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                let block_name = &trimmed[1..trimmed.len() - 1];

                // If we were building a peer, finish and push it
                if current_block == "Peer" {
                    if let Some(ip) = endpoint {
                        // All WireGuard tunnels mandate ChaCha20-Poly1305.
                        // We map the PublicKey as the PreSharedKey credential for simplicity of the model.
                        let mut config = PeerConfig::new(ip, CipherSuite::ChaCha20Poly1305, AuthMethod::PreSharedKey);
                        if let Some(key) = &public_key {
                            config = config.with_psk(key);
                        }
                        for net in allowed_ips.drain(..) {
                            config = config.with_network(net);
                        }
                        peers.push(config);
                    }
                }

                current_block = block_name.to_string();
                
                // Reset peer temp variables
                endpoint = None;
                public_key = None;
                continue;
            }

            // Property splitting (e.g., Endpoint = 10.0.0.1:51820)
            if current_block == "Peer" {
                if let Some((k, v)) = trimmed.split_once('=') {
                    let key = k.trim().to_lowercase();
                    let val = v.trim();

                    match key.as_str() {
                        "endpoint" => {
                            // Extract IP, strip port
                            let ip_str = val.split(':').next().unwrap_or(val);
                            if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                                endpoint = Some(ip);
                            }
                        }
                        "publickey" => {
                            public_key = Some(val.to_string());
                        }
                        "allowedips" => {
                            let networks = val.split(',');
                            for net in networks {
                                if let Ok(parsed_net) = net.trim().parse::<Ipv4Net>() {
                                    allowed_ips.push(parsed_net);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        // Flush the final peer block if we hit EOF
        if current_block == "Peer" {
            if let Some(ip) = endpoint {
                let mut config = PeerConfig::new(ip, CipherSuite::ChaCha20Poly1305, AuthMethod::PreSharedKey);
                if let Some(key) = &public_key {
                    config = config.with_psk(key);
                }
                for net in allowed_ips.drain(..) {
                    config = config.with_network(net);
                }
                peers.push(config);
            }
        }

        Ok(peers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_wireguard_message_type_parsing() {
        // [1, 0, 0, 0] = Initiation
        let init_buf = [0x01, 0x00, 0x00, 0x00, 0x55, 0x66];
        assert_eq!(WgMessageType::from_udp_payload(&init_buf), WgMessageType::Initiation);

        // [4, 0, 0, 0] = Transport Data
        let transport_buf = [0x04, 0x00, 0x00, 0x00, 0xAA, 0xBB];
        assert_eq!(WgMessageType::from_udp_payload(&transport_buf), WgMessageType::TransportData);

        // Corrupted padding
        let broken_padding = [0x01, 0x00, 0xFF, 0x00];
        assert_eq!(WgMessageType::from_udp_payload(&broken_padding), WgMessageType::Unknown);
    }

    #[test]
    fn test_wireguard_config_parser() {
        let conf_content = r#"
[Interface]
PrivateKey = yAnz5TF+lXXJte14tij9mQGqT8ZzXyA+sMwU=
Address = 10.0.0.1/24
ListenPort = 51820

[Peer]
PublicKey = p1...
Endpoint = 192.168.1.10:51820
AllowedIPs = 10.0.0.2/32, 172.16.0.0/12

[Peer]
PublicKey = p2...
Endpoint = 192.168.1.11
AllowedIPs = 10.0.0.3/32
        "#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(conf_content.as_bytes()).unwrap();

        let peers = WgConfigParser::parse_file(file.path()).expect("Valid wg0.conf expected");
        assert_eq!(peers.len(), 2);

        // Verify Peer 1
        assert_eq!(peers[0].peer_ip, Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(peers[0].cipher, CipherSuite::ChaCha20Poly1305);
        assert_eq!(peers[0].psk.as_deref(), Some("p1..."));
        assert_eq!(peers[0].allowed_networks.len(), 2);

        // Verify Peer 2
        assert_eq!(peers[1].peer_ip, Ipv4Addr::new(192, 168, 1, 11));
        assert_eq!(peers[1].allowed_networks.len(), 1);
    }
}
