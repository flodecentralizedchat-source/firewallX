use crate::modules::packet::Packet;
use std::collections::HashSet;
use std::net::Ipv4Addr;

pub struct StateTable {
    max_entries: usize,
    connections: HashSet<(Ipv4Addr, Ipv4Addr, u16, u16)>,
}

impl StateTable {
    pub fn new(max_entries: usize) -> Self {
        Self {
            max_entries,
            connections: HashSet::new(),
        }
    }

    pub fn lookup(&self, pkt: &Packet) -> bool {
        self.connections.contains(&(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port))
            || self.connections.contains(&(pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port))
    }

    pub fn insert(&mut self, pkt: &Packet) {
        if self.connections.len() < self.max_entries {
            self.connections.insert((pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port));
        }
    }

    pub fn len(&self) -> usize {
        self.connections.len()
    }
}
