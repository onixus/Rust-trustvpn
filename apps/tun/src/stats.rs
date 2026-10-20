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
    /// Engine TCP flow counts (`rtrust_engine::flow_counters`).
    pub tcp_opened: u64,
    pub tcp_answered: u64,
    pub tcp_quiet: u64,
    pub tcp_open_failed: u64,
    pub credit_timeout: u64,
}
pub fn snapshot() -> Snapshot {
    let flows = rtrust_engine::flow_counters();
    Snapshot {
        syn_accepted: COUNTERS.syn_accepted.load(Relaxed),
        syn_refused: COUNTERS.syn_refused.load(Relaxed),
        handshake_reset: COUNTERS.handshake_reset.load(Relaxed),
        handshake_timeout: COUNTERS.handshake_timeout.load(Relaxed),
        backlog_discarded: COUNTERS.backlog_discarded.load(Relaxed),
        udp_evicted: COUNTERS.udp_evicted.load(Relaxed),
        tcp_opened: flows.tcp_opened,
        tcp_answered: flows.tcp_answered,
        tcp_quiet: flows.tcp_quiet,
        tcp_open_failed: flows.tcp_open_failed,
        credit_timeout: flows.credit_timeout,
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
            tcp_opened: self.tcp_opened.wrapping_sub(base.tcp_opened),
            tcp_answered: self.tcp_answered.wrapping_sub(base.tcp_answered),
            tcp_quiet: self.tcp_quiet.wrapping_sub(base.tcp_quiet),
            tcp_open_failed: self.tcp_open_failed.wrapping_sub(base.tcp_open_failed),
            credit_timeout: self.credit_timeout.wrapping_sub(base.credit_timeout),
        }
    }
    /// Key/value text with numbers only, for lifecycle logs. New keys go
    /// at the end: readers match the established prefix.
    pub fn render(&self) -> String {
        format!(
            "syn_accepted={} syn_refused={} handshake_reset={} handshake_timeout={} backlog_discarded={} udp_evicted={} tcp_opened={} tcp_answered={} tcp_quiet={} tcp_open_failed={} credit_timeout={}",
            self.syn_accepted,
            self.syn_refused,
            self.handshake_reset,
            self.handshake_timeout,
            self.backlog_discarded,
            self.udp_evicted,
            self.tcp_opened,
            self.tcp_answered,
            self.tcp_quiet,
            self.tcp_open_failed,
            self.credit_timeout
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn render_keeps_the_prefix_and_appends_flow_counts_as_numbers() {
        let delta = Snapshot {
            syn_accepted: 1,
            syn_refused: 2,
            handshake_reset: 3,
            handshake_timeout: 4,
            backlog_discarded: 5,
            udp_evicted: 6,
            tcp_opened: 7,
            tcp_answered: 8,
            tcp_quiet: 9,
            tcp_open_failed: 10,
            credit_timeout: 11,
        }
        .since(&Snapshot::default());
        let line = delta.render();
        assert_eq!(
            line,
            "syn_accepted=1 syn_refused=2 handshake_reset=3 handshake_timeout=4 backlog_discarded=5 udp_evicted=6 tcp_opened=7 tcp_answered=8 tcp_quiet=9 tcp_open_failed=10 credit_timeout=11"
        );
        for token in line.split(' ') {
            let (key, value) = token.split_once('=').unwrap();
            assert!(key.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
            assert!(value.chars().all(|c| c.is_ascii_digit()));
        }
        // Live counters only grow, so a delta from an earlier snapshot never wraps.
        let base = snapshot();
        let now = snapshot().since(&base);
        assert!(now.tcp_opened <= snapshot().tcp_opened);
    }
}
