//! Hysteria "Brutal" congestion control: a fixed send rate compensated for
//! observed loss. Until the server negotiates a rate the regular controller runs.
use quinn::congestion::{Controller, ControllerFactory};
use quinn_proto::RttEstimator;
use std::{
    any::Any,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
const SLOTS: usize = 5;
const MIN_SAMPLES: u64 = 50;
const MIN_ACK_RATE: f64 = 0.8;
/// Shared by the factory and every controller it builds; zero disables Brutal.
#[derive(Clone, Default)]
pub struct Rate(Arc<AtomicU64>);
impl Rate {
    pub fn set(&self, bytes_per_second: u64) {
        self.0.store(bytes_per_second, Ordering::Relaxed)
    }
    fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}
pub struct Factory {
    pub rate: Rate,
    pub fallback: Arc<dyn ControllerFactory + Send + Sync>,
}
impl ControllerFactory for Factory {
    fn build(self: Arc<Self>, now: Instant, mtu: u16) -> Box<dyn Controller> {
        Box::new(Brutal {
            rate: self.rate.clone(),
            fallback: self.fallback.clone().build(now, mtu),
            mtu: mtu as u64,
            rtt: None,
            slots: [Slot::default(); SLOTS],
            start: now,
        })
    }
}
#[derive(Clone, Copy, Default)]
struct Slot {
    second: u64,
    acked: u64,
    lost: u64,
}
struct Brutal {
    rate: Rate,
    fallback: Box<dyn Controller>,
    mtu: u64,
    rtt: Option<Duration>,
    slots: [Slot; SLOTS],
    start: Instant,
}
impl Brutal {
    /// Loss-compensated send rate in bytes/s.
    fn target(&self, now: Instant) -> f64 {
        self.rate.get() as f64 / self.ack_rate(now)
    }
    /// Quinn has no separate pacing rate: it paces at 1.25 windows per smoothed
    /// RTT and caps in-flight bytes at the window. One RTT at the target paces
    /// slightly above it (upstream: two RTTs with its own pacer at the target).
    /// Ten datagrams keep a sub-millisecond RTT from waiting on delayed ACKs.
    fn window_at(&self, now: Instant) -> u64 {
        match self.rtt {
            None => 10240,
            Some(rtt) => ((self.target(now) * rtt.as_secs_f64()) as u64).max(10 * self.mtu),
        }
    }
    fn slot(&mut self, now: Instant) -> &mut Slot {
        let second = now.saturating_duration_since(self.start).as_secs();
        let slot = &mut self.slots[second as usize % SLOTS];
        if slot.second != second {
            *slot = Slot {
                second,
                ..Slot::default()
            };
        }
        slot
    }
    fn acked(&mut self, now: Instant, rtt: Duration) {
        self.rtt = Some(rtt);
        self.slot(now).acked += 1;
    }
    fn lost(&mut self, now: Instant, bytes: u64) {
        let mtu = self.mtu.max(1);
        self.slot(now).lost += bytes.div_ceil(mtu);
    }
    /// Share of packets acknowledged over the last five seconds.
    fn ack_rate(&self, now: Instant) -> f64 {
        let second = now.saturating_duration_since(self.start).as_secs();
        let (acked, lost) = self
            .slots
            .iter()
            .filter(|s| second.saturating_sub(s.second) < SLOTS as u64)
            .fold((0, 0), |(a, l), s| (a + s.acked, l + s.lost));
        if acked + lost < MIN_SAMPLES {
            1.0
        } else {
            (acked as f64 / (acked + lost) as f64).max(MIN_ACK_RATE)
        }
    }
}
impl Controller for Brutal {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.fallback.on_sent(now, bytes, last_packet_number)
    }
    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.acked(now, rtt.get());
        self.fallback.on_ack(now, sent, bytes, app_limited, rtt)
    }
    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.fallback
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked)
    }
    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        self.lost(now, lost_bytes);
        self.fallback
            .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes)
    }
    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu as u64;
        self.fallback.on_mtu_update(new_mtu)
    }
    fn window(&self) -> u64 {
        let rate = self.rate.get();
        if rate == 0 {
            return self.fallback.window();
        }
        self.window_at(Instant::now())
    }
    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Self {
            rate: self.rate.clone(),
            fallback: self.fallback.clone_box(),
            mtu: self.mtu,
            rtt: self.rtt,
            slots: self.slots,
            start: self.start,
        })
    }
    fn initial_window(&self) -> u64 {
        self.fallback.initial_window()
    }
    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}
/// Send rate in bytes/s from the server's `Hysteria-CC-RX` reply and the
/// configured upload; zero keeps the regular controller.
pub fn negotiate(server_rx: Option<&str>, up_bytes: u64) -> u64 {
    match server_rx.map(str::trim) {
        Some("auto") => 0,
        value => {
            let server = value.and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
            if server == 0 || server > up_bytes {
                up_bytes
            } else {
                server
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn negotiation_matches_official_client() {
        assert_eq!(negotiate(Some("auto"), 1000), 0);
        assert_eq!(negotiate(Some("0"), 1000), 1000);
        assert_eq!(negotiate(Some("500"), 1000), 500);
        assert_eq!(negotiate(Some("5000"), 1000), 1000);
        assert_eq!(negotiate(Some("bad"), 1000), 1000);
        assert_eq!(negotiate(None, 0), 0);
        assert_eq!(negotiate(Some("500"), 0), 0);
    }
    #[test]
    fn window_follows_rate_rtt_and_loss() {
        let rate = Rate::default();
        let factory = Arc::new(Factory {
            rate: rate.clone(),
            fallback: Arc::new(quinn::congestion::CubicConfig::default()),
        });
        let now = Instant::now();
        let mut c = *factory
            .build(now, 1200)
            .into_any()
            .downcast::<Brutal>()
            .unwrap();
        let fallback = c.window();
        rate.set(1_000_000);
        assert_eq!(c.window_at(now), 10240);
        // A loopback RTT still allows ten datagrams in flight.
        c.acked(now, Duration::from_micros(200));
        assert_eq!(c.window_at(now), 12_000);
        for _ in 0..100 {
            c.acked(now, Duration::from_millis(100));
        }
        assert_eq!(c.window_at(now), 100_000);
        // 50% loss is compensated only up to the 0.8 floor.
        c.lost(now, 100 * 1200);
        assert_eq!(c.window_at(now), 125_000);
        rate.set(0);
        assert!(c.window() <= fallback);
    }
}
