use crate::modules::packet::Packet;
use crate::modules::rule::Rule;

pub struct FirewallLogger;

impl FirewallLogger {
    pub fn new() -> Self {
        Self
    }

    pub fn log_allow(&self, pkt: &Packet, reason: &str) {
        log::info!("ALLOW {} -> {} : {} ({})", pkt.src_ip, pkt.dst_ip, pkt.dst_port, reason);
    }

    pub fn log_rule_hit(&self, pkt: &Packet, rule: &Rule) {
        log::info!("RULE HIT [{}] {} -> {} : {} - {:?}", rule.id, pkt.src_ip, pkt.dst_ip, pkt.dst_port, rule.action);
    }

    pub fn log_default_deny(&self, pkt: &Packet) {
        log::warn!("DEFAULT DENY {} -> {} : {}", pkt.src_ip, pkt.dst_ip, pkt.dst_port);
    }
}

impl Default for FirewallLogger {
    fn default() -> Self {
        Self::new()
    }
}
