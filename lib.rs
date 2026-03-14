// firewallx/src/lib.rs
// Public library interface for FirewallX

pub mod modules;

pub use modules::engine::FirewallEngine;
pub use modules::packet::{Packet, Protocol, Direction};
pub use modules::rule::{Rule, Action, RuleSet};
pub use modules::state::StateTable;
pub use modules::logger::FirewallLogger;
pub use modules::nat::NatTable;
pub use modules::dpi::{DpiEngine, DpiResult, AppProtocol, Signature, Severity, SigCategory};
pub use modules::ids::{IdsEngine, IdsConfig, Alert, AlertKind};
pub use modules::vpn::{VpnGateway, PeerConfig, CipherSuite, AuthMethod, TunnelState};
pub use modules::error::FirewallError;
