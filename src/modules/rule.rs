use crate::modules::packet::{Packet, Protocol, Direction};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Allow,
    Drop,
    Reject,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: u32,
    pub name: String,
    pub action: Action,
    pub src_ip: Option<Ipv4Addr>,
    pub dst_ip: Option<Ipv4Addr>,
    pub dst_port: Option<u16>,
    pub protocol: Protocol,
    pub direction: Direction,
}

impl Rule {
    pub fn new(
        id: u32,
        name: &str,
        action: Action,
        src_ip: Option<Ipv4Addr>,
        dst_ip: Option<Ipv4Addr>,
        dst_port: Option<u16>,
        protocol: Protocol,
        direction: Direction,
    ) -> Self {
        Self {
            id,
            name: name.to_string(),
            action,
            src_ip,
            dst_ip,
            dst_port,
            protocol,
            direction,
        }
    }

    pub fn matches(&self, pkt: &Packet) -> bool {
        if self.direction != pkt.direction {
            return false;
        }
        if self.protocol != Protocol::Any && self.protocol != pkt.protocol {
            return false;
        }
        if let Some(dp) = self.dst_port {
            if dp != pkt.dst_port {
                return false;
            }
        }
        if let Some(sip) = self.src_ip {
            if sip != pkt.src_ip {
                return false;
            }
        }
        if let Some(dip) = self.dst_ip {
            if dip != pkt.dst_ip {
                return false;
            }
        }
        true
    }
}

pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add(&mut self, rule: Rule) {
        self.rules.push(rule);
    }

    pub fn evaluate(&self, pkt: &Packet) -> Option<&Rule> {
        self.rules.iter().find(|r| r.matches(pkt))
    }
}

impl Default for RuleSet {
    fn default() -> Self {
        Self::new()
    }
}
