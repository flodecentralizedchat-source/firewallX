// firewallx/src/modules/vpn.rs
// VPN Gateway
//
// Manages encrypted tunnel sessions between the firewall and remote peers.
// Supports a simplified IKE-like handshake model and per-tunnel traffic accounting.
//
// NOTE: This module models the VPN gateway *control plane* (session lifecycle,
// key management, routing). Actual crypto (AES-GCM, ChaCha20-Poly1305) would
// be layered on top using the `ring` or `rustls` crates in a production build.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────
// Cipher suites and authentication methods
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CipherSuite {
    Aes256Gcm,
    ChaCha20Poly1305,
    Aes128Gcm,
}

impl std::fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CipherSuite::Aes256Gcm         => write!(f, "AES-256-GCM"),
            CipherSuite::ChaCha20Poly1305  => write!(f, "ChaCha20-Poly1305"),
            CipherSuite::Aes128Gcm         => write!(f, "AES-128-GCM"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMethod {
    PreSharedKey,
    Certificate,
    EapMsChapV2,
}

// ─────────────────────────────────────────────────────────────
// Tunnel lifecycle
// ─────────────────────────────────────────────────────────────

/// State machine for a VPN tunnel session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelState {
    /// Initial handshake in progress.
    Negotiating,
    /// Keys exchanged, tunnel is active.
    Established,
    /// Rekeying — old keys still valid until new ones confirmed.
    Rekeying,
    /// Graceful close initiated.
    Closing,
    /// Tunnel has been torn down.
    Closed,
}

/// A VPN peer configuration entry.
#[derive(Debug, Clone)]
pub struct PeerConfig {
    pub peer_ip: Ipv4Addr,
    /// Subnets reachable through this peer.
    pub allowed_networks: Vec<ipnet::Ipv4Net>,
    pub cipher: CipherSuite,
    pub auth: AuthMethod,
    /// Shared secret (PSK mode).  In production: store as SecretKey, not String.
    pub psk: Option<String>,
    /// Maximum tunnel lifetime before mandatory re-key.
    pub lifetime: Duration,
}

impl PeerConfig {
    pub fn new(peer_ip: Ipv4Addr, cipher: CipherSuite, auth: AuthMethod) -> Self {
        Self {
            peer_ip,
            allowed_networks: Vec::new(),
            cipher,
            auth,
            psk: None,
            lifetime: Duration::from_secs(3600),
        }
    }

    pub fn with_psk(mut self, psk: &str) -> Self {
        self.psk = Some(psk.to_owned());
        self
    }

    pub fn with_network(mut self, net: ipnet::Ipv4Net) -> Self {
        self.allowed_networks.push(net);
        self
    }
}

// ─────────────────────────────────────────────────────────────
// Active tunnel session
// ─────────────────────────────────────────────────────────────

/// An active (or negotiating) VPN tunnel session.
#[derive(Debug)]
pub struct TunnelSession {
    pub id: u64,
    pub peer_ip: Ipv4Addr,
    /// Simulated session key material (hex string in this model).
    pub session_key: String,
    pub cipher: CipherSuite,
    pub state: TunnelState,
    pub established_at: Option<Instant>,
    pub last_activity: Instant,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    /// Lifetime duration before mandatory re-key.
    pub lifetime: Duration,
}

impl TunnelSession {
    fn new(id: u64, peer_ip: Ipv4Addr, cipher: CipherSuite, lifetime: Duration) -> Self {
        Self {
            id,
            peer_ip,
            session_key: format!("{:016x}{:016x}", id ^ 0xDEADBEEFCAFEBABE, id.wrapping_mul(0x9E3779B97F4A7C15)),
            cipher,
            state: TunnelState::Negotiating,
            established_at: None,
            last_activity: Instant::now(),
            bytes_in: 0,
            bytes_out: 0,
            packets_in: 0,
            packets_out: 0,
            lifetime,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.established_at
            .map(|t| t.elapsed() >= self.lifetime)
            .unwrap_or(false)
    }

    pub fn is_idle(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() >= timeout
    }

    fn record_inbound(&mut self, bytes: u64) {
        self.bytes_in += bytes;
        self.packets_in += 1;
        self.last_activity = Instant::now();
    }

    fn record_outbound(&mut self, bytes: u64) {
        self.bytes_out += bytes;
        self.packets_out += 1;
        self.last_activity = Instant::now();
    }
}

// ─────────────────────────────────────────────────────────────
// VPN Gateway
// ─────────────────────────────────────────────────────────────

/// Errors produced by the VPN gateway.
#[derive(Debug, PartialEq, Eq)]
pub enum VpnError {
    UnknownPeer(Ipv4Addr),
    TunnelNotEstablished(u64),
    AuthFailed(Ipv4Addr),
    NoPeerConfig(Ipv4Addr),
    TunnelAlreadyExists(Ipv4Addr),
}

impl std::fmt::Display for VpnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub type VpnResult<T> = Result<T, VpnError>;

/// The VPN gateway manages peer configurations and active tunnel sessions.
pub struct VpnGateway {
    peers: HashMap<Ipv4Addr, PeerConfig>,
    /// Active sessions keyed by tunnel id.
    sessions: HashMap<u64, TunnelSession>,
    /// Reverse map: peer_ip → tunnel id (at most one active tunnel per peer).
    peer_to_session: HashMap<Ipv4Addr, u64>,
    next_id: u64,
    idle_timeout: Duration,
}

impl VpnGateway {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            sessions: HashMap::new(),
            peer_to_session: HashMap::new(),
            next_id: 1,
            idle_timeout: Duration::from_secs(300),
        }
    }

    // ── Peer management ──────────────────────────────────────

    /// Register a peer configuration.
    pub fn add_peer(&mut self, config: PeerConfig) {
        self.peers.insert(config.peer_ip, config);
    }

    /// Remove a peer (and forcibly close any active tunnel).
    pub fn remove_peer(&mut self, ip: &Ipv4Addr) -> bool {
        if let Some(tid) = self.peer_to_session.remove(ip) {
            self.sessions.remove(&tid);
        }
        self.peers.remove(ip).is_some()
    }

    // ── Tunnel lifecycle ─────────────────────────────────────

    /// Initiate a tunnel negotiation with a registered peer.
    pub fn initiate(&mut self, peer_ip: Ipv4Addr) -> VpnResult<u64> {
        if self.peer_to_session.contains_key(&peer_ip) {
            return Err(VpnError::TunnelAlreadyExists(peer_ip));
        }
        let config = self.peers.get(&peer_ip)
            .ok_or(VpnError::NoPeerConfig(peer_ip))?;

        let id = self.next_id;
        self.next_id += 1;
        let session = TunnelSession::new(id, peer_ip, config.cipher.clone(), config.lifetime);
        self.sessions.insert(id, session);
        self.peer_to_session.insert(peer_ip, id);
        Ok(id)
    }

    /// Simulate completing the IKE handshake — transition to Established.
    pub fn complete_handshake(&mut self, tunnel_id: u64, provided_psk: Option<&str>) -> VpnResult<()> {
        let session = self.sessions.get_mut(&tunnel_id)
            .ok_or(VpnError::TunnelNotEstablished(tunnel_id))?;

        // PSK authentication check
        let peer_ip = session.peer_ip;
        if let Some(config) = self.peers.get(&peer_ip) {
            if config.auth == AuthMethod::PreSharedKey {
                let expected = config.psk.as_deref().unwrap_or("");
                let provided  = provided_psk.unwrap_or("");
                if expected != provided {
                    return Err(VpnError::AuthFailed(peer_ip));
                }
            }
        }

        let session = self.sessions.get_mut(&tunnel_id).unwrap();
        session.state = TunnelState::Established;
        session.established_at = Some(Instant::now());
        Ok(())
    }

    /// Initiate a re-key on an established tunnel.
    pub fn rekey(&mut self, tunnel_id: u64) -> VpnResult<()> {
        let session = self.sessions.get_mut(&tunnel_id)
            .ok_or(VpnError::TunnelNotEstablished(tunnel_id))?;
        if session.state != TunnelState::Established {
            return Err(VpnError::TunnelNotEstablished(tunnel_id));
        }
        session.state = TunnelState::Rekeying;
        // Simulate new key material
        session.session_key = format!("{:016x}{:016x}", tunnel_id ^ 0xBAADF00D, Instant::now().elapsed().as_nanos() as u64);
        session.state = TunnelState::Established;
        session.established_at = Some(Instant::now());
        Ok(())
    }

    /// Close a tunnel gracefully.
    pub fn close(&mut self, tunnel_id: u64) -> VpnResult<()> {
        let session = self.sessions.get_mut(&tunnel_id)
            .ok_or(VpnError::TunnelNotEstablished(tunnel_id))?;
        let peer = session.peer_ip;
        session.state = TunnelState::Closed;
        self.sessions.remove(&tunnel_id);
        self.peer_to_session.remove(&peer);
        Ok(())
    }

    // ── Traffic routing ──────────────────────────────────────

    /// Route a packet through the appropriate tunnel.
    /// Returns the tunnel id if the packet was accepted.
    pub fn route_outbound(&mut self, dst_ip: Ipv4Addr, payload_len: u64) -> VpnResult<u64> {
        // Find a peer whose allowed_networks covers dst_ip
        let peer_ip = self.peers.iter().find(|(_, cfg)| {
            cfg.allowed_networks.iter().any(|net| net.contains(&dst_ip))
        }).map(|(ip, _)| *ip)
            .ok_or(VpnError::UnknownPeer(dst_ip))?;

        let tid = *self.peer_to_session.get(&peer_ip)
            .ok_or(VpnError::TunnelNotEstablished(0))?;

        let session = self.sessions.get_mut(&tid)
            .ok_or(VpnError::TunnelNotEstablished(tid))?;

        if session.state != TunnelState::Established {
            return Err(VpnError::TunnelNotEstablished(tid));
        }
        session.record_outbound(payload_len);
        Ok(tid)
    }

    /// Receive decapsulated inbound traffic from a peer.
    pub fn route_inbound(&mut self, peer_ip: Ipv4Addr, payload_len: u64) -> VpnResult<u64> {
        let tid = *self.peer_to_session.get(&peer_ip)
            .ok_or(VpnError::UnknownPeer(peer_ip))?;
        let session = self.sessions.get_mut(&tid)
            .ok_or(VpnError::TunnelNotEstablished(tid))?;
        if session.state != TunnelState::Established {
            return Err(VpnError::TunnelNotEstablished(tid));
        }
        session.record_inbound(payload_len);
        Ok(tid)
    }

    // ── Maintenance ──────────────────────────────────────────

    /// Expire tunnels that have exceeded their lifetime or idle timeout.
    /// Returns the ids of removed tunnels.
    pub fn expire_tunnels(&mut self) -> Vec<u64> {
        let idle = self.idle_timeout;
        let expired: Vec<u64> = self.sessions.values()
            .filter(|s| s.is_expired() || s.is_idle(idle))
            .map(|s| s.id)
            .collect();
        for id in &expired {
            if let Some(s) = self.sessions.remove(id) {
                self.peer_to_session.remove(&s.peer_ip);
            }
        }
        expired
    }

    // ── Accessors ────────────────────────────────────────────

    pub fn session(&self, id: u64) -> Option<&TunnelSession> {
        self.sessions.get(&id)
    }

    pub fn session_for_peer(&self, peer: &Ipv4Addr) -> Option<&TunnelSession> {
        self.peer_to_session.get(peer).and_then(|id| self.sessions.get(id))
    }

    pub fn active_tunnel_count(&self) -> usize {
        self.sessions.values()
            .filter(|s| s.state == TunnelState::Established)
            .count()
    }

    pub fn total_tunnel_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn active_sessions(&self) -> Vec<&TunnelSession> {
        self.sessions.values().collect()
    }
}

impl Default for VpnGateway {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn peer(ip: Ipv4Addr) -> PeerConfig {
        PeerConfig::new(ip, CipherSuite::Aes256Gcm, AuthMethod::PreSharedKey)
            .with_psk("s3cr3t")
            .with_network("10.10.0.0/16".parse().unwrap())
    }

    fn setup_gw() -> (VpnGateway, Ipv4Addr, u64) {
        let peer_ip = Ipv4Addr::new(203, 0, 113, 10);
        let mut gw = VpnGateway::new();
        gw.add_peer(peer(peer_ip));
        let tid = gw.initiate(peer_ip).unwrap();
        gw.complete_handshake(tid, Some("s3cr3t")).unwrap();
        (gw, peer_ip, tid)
    }

    #[test]
    fn test_successful_tunnel_establishment() {
        let (gw, peer_ip, tid) = setup_gw();
        let s = gw.session(tid).unwrap();
        assert_eq!(s.state, TunnelState::Established);
        assert_eq!(s.peer_ip, peer_ip);
    }

    #[test]
    fn test_wrong_psk_fails() {
        let peer_ip = Ipv4Addr::new(203, 0, 113, 20);
        let mut gw = VpnGateway::new();
        gw.add_peer(peer(peer_ip));
        let tid = gw.initiate(peer_ip).unwrap();
        let result = gw.complete_handshake(tid, Some("wrong_psk"));
        assert_eq!(result, Err(VpnError::AuthFailed(peer_ip)));
    }

    #[test]
    fn test_duplicate_initiation_fails() {
        let (mut gw, peer_ip, _) = setup_gw();
        let result = gw.initiate(peer_ip);
        assert_eq!(result, Err(VpnError::TunnelAlreadyExists(peer_ip)));
    }

    #[test]
    fn test_route_outbound_traffic_accounting() {
        let (mut gw, _, tid) = setup_gw();
        gw.route_outbound(Ipv4Addr::new(10, 10, 1, 5), 512).unwrap();
        gw.route_outbound(Ipv4Addr::new(10, 10, 2, 9), 256).unwrap();
        let s = gw.session(tid).unwrap();
        assert_eq!(s.bytes_out,   768);
        assert_eq!(s.packets_out, 2);
    }

    #[test]
    fn test_route_inbound_traffic_accounting() {
        let (mut gw, peer_ip, tid) = setup_gw();
        gw.route_inbound(peer_ip, 1024).unwrap();
        let s = gw.session(tid).unwrap();
        assert_eq!(s.bytes_in,   1024);
        assert_eq!(s.packets_in, 1);
    }

    #[test]
    fn test_route_to_unknown_dst_fails() {
        let (mut gw, _, _) = setup_gw();
        // 192.168.x.x is NOT in the peer's allowed_networks (10.10.0.0/16)
        let result = gw.route_outbound(Ipv4Addr::new(192, 168, 1, 1), 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_rekey() {
        let (mut gw, _, tid) = setup_gw();
        let old_key = gw.session(tid).unwrap().session_key.clone();
        gw.rekey(tid).unwrap();
        let new_key = gw.session(tid).unwrap().session_key.clone();
        assert_ne!(old_key, new_key, "rekey should produce new key material");
    }

    #[test]
    fn test_close_tunnel() {
        let (mut gw, peer_ip, tid) = setup_gw();
        gw.close(tid).unwrap();
        assert!(gw.session(tid).is_none());
        assert!(gw.session_for_peer(&peer_ip).is_none());
        assert_eq!(gw.active_tunnel_count(), 0);
    }

    #[test]
    fn test_remove_peer_closes_tunnel() {
        let (mut gw, peer_ip, tid) = setup_gw();
        assert!(gw.remove_peer(&peer_ip));
        assert!(gw.session(tid).is_none());
        assert_eq!(gw.peer_count(), 0);
    }

    #[test]
    fn test_multiple_peers() {
        let mut gw = VpnGateway::new();
        for i in 1u8..=3 {
            let pip = Ipv4Addr::new(203, 0, 113, i);
            let mut p = PeerConfig::new(pip, CipherSuite::ChaCha20Poly1305, AuthMethod::PreSharedKey)
                .with_psk("key");
            p.allowed_networks.push(format!("10.{}.0.0/16", i).parse().unwrap());
            gw.add_peer(p);
            let tid = gw.initiate(pip).unwrap();
            gw.complete_handshake(tid, Some("key")).unwrap();
        }
        assert_eq!(gw.active_tunnel_count(), 3);
    }

    #[test]
    fn test_negotiating_tunnel_cannot_route() {
        let peer_ip = Ipv4Addr::new(203, 0, 113, 50);
        let mut gw = VpnGateway::new();
        gw.add_peer(
            PeerConfig::new(peer_ip, CipherSuite::Aes256Gcm, AuthMethod::PreSharedKey)
                .with_psk("x")
                .with_network("172.16.0.0/12".parse().unwrap())
        );
        let _ = gw.initiate(peer_ip).unwrap();
        // Handshake NOT completed → tunnel is still Negotiating
        let result = gw.route_outbound(Ipv4Addr::new(172, 16, 1, 1), 64);
        assert!(result.is_err());
    }
}
