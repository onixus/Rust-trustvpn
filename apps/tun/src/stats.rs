//! Process-wide data-plane counters: plain numbers only, no flow, address,
//! host or profile data. They let the privileged service write a bounded,
//! redacted summary after a (re)connect without reaching into the data plane.
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

#[derive(Default)]
pub struct Counters {
    /// SYNs that created a new local TCP flow.
    pub syn_accepted: AtomicU64,
    /// SYNs dropped because the flow table was full.
    pub syn_refused: AtomicU64,
    /// Handshakes reset by the host (RST after SYN-ACK) and removed.
    pub handshake_reset: AtomicU64,
    /// Handshakes that never completed within the handshake limit.
    pub handshake_timeout: AtomicU64,
    /// Packets discarded from the device backlog before a session started.
    pub backlog_discarded: AtomicU64,
    /// UDP mappings evicted to admit a newer datagram.
    pub udp_evicted: AtomicU64,
}
pub static COUNTERS: Counters = Counters {
    syn_accepted: AtomicU64::new(0),
    syn_refused: AtomicU64::new(0),
    handshake_reset: AtomicU64::new(0),
    handshake_timeout: AtomicU64::new(0),
    backlog_discarded: AtomicU64::new(0),
    udp_evicted: AtomicU64::new(0),
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub syn_accepted: u64,
    pub syn_refused: u64,
    pub handshake_reset: u64,
    pub handshake_timeout: u64,
    pub backlog_discarded: u64,
    pub udp_evicted: u64,
}
pub fn snapshot() -> Snapshot {
    Snapshot {
        syn_accepted: COUNTERS.syn_accepted.load(Relaxed),
        syn_refused: COUNTERS.syn_refused.load(Relaxed),
        handshake_reset: COUNTERS.handshake_reset.load(Relaxed),
        handshake_timeout: COUNTERS.handshake_timeout.load(Relaxed),
        backlog_discarded: COUNTERS.backlog_discarded.load(Relaxed),
        udp_evicted: COUNTERS.udp_evicted.load(Relaxed),
    }
}
impl Snapshot {
    /// Counts accumulated since `base`; counters only grow.
    pub fn since(&self, base: &Snapshot) -> Snapshot {
        Snapshot {
            syn_accepted: self.syn_accepted.wrapping_sub(base.syn_accepted),
            syn_refused: self.syn_refused.wrapping_sub(base.syn_refused),
            handshake_reset: self.handshake_reset.wrapping_sub(base.handshake_reset),
            handshake_timeout: self.handshake_timeout.wrapping_sub(base.handshake_timeout),
            backlog_discarded: self.backlog_discarded.wrapping_sub(base.backlog_discarded),
            udp_evicted: self.udp_evicted.wrapping_sub(base.udp_evicted),
        }
    }
    /// Key/value text with numbers only, for lifecycle logs.
    pub fn render(&self) -> String {
        format!(
            "syn_accepted={} syn_refused={} handshake_reset={} handshake_timeout={} backlog_discarded={} udp_evicted={}",
            self.syn_accepted,
            self.syn_refused,
            self.handshake_reset,
            self.handshake_timeout,
            self.backlog_discarded,
            self.udp_evicted
        )
    }
}
