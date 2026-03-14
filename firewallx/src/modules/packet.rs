use std::net::Ipv4Addr;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Any,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QosPriority {
    Normal,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct Packet {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub direction: Direction,
    pub payload_len: usize,
    pub country: Option<String>,
    pub qos: QosPriority,
}

impl Packet {
    pub fn new(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        protocol: Protocol,
        direction: Direction,
        payload_len: usize,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            direction,
            payload_len,
            country: None,
            qos: QosPriority::Normal,
        }
    }
}
