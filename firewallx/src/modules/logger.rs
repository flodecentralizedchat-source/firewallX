use crate::modules::packet::Packet;
use crate::modules::rule::Rule;

pub struct FirewallLogger;

impl FirewallLogger {
    pub fn new() -> Self {
        Self
    }

    pub fn log_allow(&self, pkt: &Packet, reason: &str) {
        tracing::info!(
            src_ip = %pkt.src_ip,
            dst_ip = %pkt.dst_ip,
            dst_port = pkt.dst_port,
            protocol = %pkt.protocol,
            action = "ALLOW",
            reason = reason,
            "Packet allowed"
        );
    }

    pub fn log_rule_hit(&self, pkt: &Packet, rule: &Rule) {
        tracing::info!(
            rule_id = rule.id,
            src_ip = %pkt.src_ip,
            dst_ip = %pkt.dst_ip,
            dst_port = pkt.dst_port,
            protocol = %pkt.protocol,
            action = ?rule.action,
            "Rule matched"
        );
    }

    pub fn log_default_deny(&self, pkt: &Packet) {
        tracing::warn!(
            src_ip = %pkt.src_ip,
            dst_ip = %pkt.dst_ip,
            dst_port = pkt.dst_port,
            protocol = %pkt.protocol,
            action = "DEFAULT_DENY",
            "Packet implicitly denied"
        );
    }
}

impl Default for FirewallLogger {
    fn default() -> Self {
        Self::new()
    }
}
