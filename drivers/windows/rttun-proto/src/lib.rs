//! Shared contract between the Windows service and the Rttun UMDF driver.
//!
//! This crate has no Windows SDK dependency. It decides which bytes may enter
//! the tunnel and how a bounded ring reports a full queue. The driver and the
//! service must agree on these rules; neither may invent a second packet format.

/// Adapter name. Routes, DNS and the interface table identify the tunnel by
/// this alias, never by a driver vendor string.
pub const ADAPTER_NAME: &str = "RTrustTunnel";

/// PnP enumerator of our own device. `SwDeviceCreate` publishes it as
/// `SWD\Rttun\<instance>`. Recovery may remove a device only under this
/// enumerator, and only when its NetCfgInstanceId matches the journal.
pub const ENUMERATOR: &str = "SWD\\Rttun";

/// Hardware id published by our INF. Install and removal match this id only.
pub const HARDWARE_ID: &str = "ROOT\\Rttun";

/// Raw IP MTU. The same value is `packet::MTU` in the data plane.
pub const MTU: usize = 1500;

/// Largest raw IP packet the ring will store. Larger writes are rejected.
pub const MAX_PACKET: usize = 65535;

/// Fixed slot count. A full ring drops the new packet; it never grows.
pub const RING_CAPACITY: usize = 256;

/// Driver package files the installer must verify before it installs anything.
pub const PACKAGE_FILES: &[&str] = &["rttun.sys", "rttun.inf", "rttun.cat"];

/// A slot holds one raw IP packet. `len == 0` means the slot is empty.
struct Slot {
    len: u16,
    data: Box<[u8]>,
}

impl Slot {
    fn empty() -> Self {
        Self {
            len: 0,
            data: vec![0; MAX_PACKET].into_boxed_slice(),
        }
    }
}

/// One direction of the adapter. `head` is the next slot a reader takes.
/// `tail` is the next slot a writer fills. Equal means empty. `tail + 1 == head`
/// modulo capacity means full, so one slot stays unused on purpose.
///
/// Slots live on the heap. A 256-slot ring of 64 KiB packets is about 16 MiB
/// and must not be constructed on a service thread stack.
pub struct Ring {
    slots: Box<[Slot]>,
    head: usize,
    tail: usize,
}

impl Ring {
    pub fn new() -> Self {
        Self {
            slots: (0..RING_CAPACITY).map(|_| Slot::empty()).collect(),
            head: 0,
            tail: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    pub fn is_full(&self) -> bool {
        self.next(self.tail) == self.head
    }

    /// Publish one raw IP packet. `WouldBlock` means the ring is full: the
    /// packet is dropped and the ring is unchanged.
    pub fn push(&mut self, packet: &[u8]) -> std::io::Result<()> {
        validate(packet)?;
        if self.is_full() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "adapter ring full",
            ));
        }
        let slot = &mut self.slots[self.tail];
        slot.data[..packet.len()].copy_from_slice(packet);
        slot.len = u16::try_from(packet.len()).expect("validated length fits u16");
        self.tail = self.next(self.tail);
        Ok(())
    }

    /// Take the next packet. `WouldBlock` means the ring is empty; nothing is consumed.
    pub fn pop(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.is_empty() {
            return Err(std::io::ErrorKind::WouldBlock.into());
        }
        let slot = &self.slots[self.head];
        let len = usize::from(slot.len);
        if out.len() < len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "adapter receive buffer shorter than packet",
            ));
        }
        out[..len].copy_from_slice(&slot.data[..len]);
        self.head = self.next(self.head);
        Ok(len)
    }

    fn next(&self, index: usize) -> usize {
        (index + 1) % RING_CAPACITY
    }
}

impl Default for Ring {
    fn default() -> Self {
        Self::new()
    }
}

/// Accept only a raw IPv4 or IPv6 packet. No Ethernet header, no Wintun header,
/// no truncated header that the data plane would have to guess about.
pub fn validate(packet: &[u8]) -> std::io::Result<()> {
    let version = packet.first().map(|b| b >> 4).unwrap_or(0);
    let min = match version {
        4 => 20,
        6 => 40,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "adapter packet is not raw IPv4 or IPv6",
            ));
        }
    };
    if packet.len() < min || packet.len() > MAX_PACKET {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "adapter packet length is outside the raw IP bounds",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(len: usize) -> Vec<u8> {
        let mut packet = vec![0; len];
        packet[0] = 0x45;
        packet
    }

    #[test]
    fn rejects_non_ip_and_short_packets() {
        assert!(validate(&[0x00, 0x45]).is_err());
        assert!(validate(&v4(19)).is_err());
        assert!(validate(&vec![0x60; 39]).is_err());
        assert!(validate(&vec![0x45; MAX_PACKET + 1]).is_err());
        assert!(validate(&v4(20)).is_ok());
        assert!(validate(&vec![0x60; 40]).is_ok());
    }

    #[test]
    fn ring_drops_when_full_and_does_not_grow() {
        let mut ring = Ring::new();
        for i in 0..RING_CAPACITY - 1 {
            ring.push(&v4(20 + (i % 8))).unwrap();
        }
        assert!(ring.is_full());
        let rejected = ring.push(&v4(20));
        assert_eq!(
            rejected.unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert!(ring.is_full());
        assert_eq!(ring.pop(&mut [0; 64]).unwrap(), 20);
        assert!(!ring.is_full());
    }

    #[test]
    fn pop_preserves_packet_bytes_and_boundaries() {
        let mut ring = Ring::new();
        ring.push(&[0x45, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19])
            .unwrap();
        ring.push(&vec![0x60; 40]).unwrap();
        let mut out = [0; 64];
        assert_eq!(ring.pop(&mut out).unwrap(), 20);
        assert_eq!(out[0], 0x45);
        assert_eq!(out[19], 19);
        assert_eq!(ring.pop(&mut out).unwrap(), 40);
        assert!(out[..40].iter().all(|b| *b == 0x60));
        assert_eq!(
            ring.pop(&mut out).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn short_buffer_does_not_consume_the_packet() {
        let mut ring = Ring::new();
        ring.push(&v4(20)).unwrap();
        assert!(ring.pop(&mut [0; 8]).is_err());
        assert!(!ring.is_empty());
        assert_eq!(ring.pop(&mut [0; 20]).unwrap(), 20);
    }
}
