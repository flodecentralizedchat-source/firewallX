#![no_std]

/// The IPv4 Blocklist struct used as keys in the eBPF HashMap.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct BlockedIp {
    pub ip: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BlockedIp {}
