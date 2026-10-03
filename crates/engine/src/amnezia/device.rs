//! One WireGuard peer: handshakes, key rotation and the timer state machine
//! of the reference implementation, with AmneziaWG's configurable timings.
//! Synchronous and socket-free: datagrams to send accumulate in `out`.
use super::{
    noise::{self, Keypair, REJECT_AFTER_MESSAGES, REKEY_AFTER_MESSAGES, TRANSPORT_HEADER},
    wire::{DEFAULT_WINDOW, Kind, Wire, pick},
};
use crate::{Error, Result};
use rtrust_profile::{
    Profile,
    amnezia::{self, AmneziaWg, Range},
};
use std::{
    collections::VecDeque,
    net::IpAddr,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

/// Packets held while a handshake is in flight; older ones are dropped.
const STAGED: usize = 128;
const COOKIE_LIFETIME: Duration = Duration::from_secs(120);

struct Timing {
    rekey_after: Range,
    rekey_timeout: Range,
    reject_after: Range,
    keepalive: Range,
    attempts: Range,
    persistent: Range,
}
fn seconds(range: Range) -> Duration {
    Duration::from_secs(pick(range).into())
}
fn jitter() -> Duration {
    Duration::from_millis(rand::random_range(0..334))
}
fn due(timer: &mut Option<Instant>, now: Instant) -> bool {
    if timer.is_some_and(|at| at <= now) {
        *timer = None;
        true
    } else {
        false
    }
}

pub struct Device {
    keys: noise::Keys,
    wire: Wire,
    timing: Timing,
    allowed: Vec<ipnet::IpNet>,
    handshake: Option<noise::Initiation>,
    current: Option<Keypair>,
    previous: Option<Keypair>,
    /// Created as responder; becomes current with the first packet under it.
    next: Option<Keypair>,
    cookie: Option<([u8; 16], Instant)>,
    last_timestamp: [u8; 12],
    last_initiation: Option<Instant>,
    attempts: u32,
    max_attempts: u32,
    /// Initiations sent since the last completed handshake. Unlike `attempts`
    /// it is not reset by new traffic, so it can tell that the peer is gone.
    unanswered: u32,
    /// IP packets waiting for a session; an empty one is a keepalive.
    staged: VecDeque<Vec<u8>>,
    /// Largest datagram seen: the bound for random padding and trailers.
    window: usize,
    retransmit: Option<Instant>,
    keepalive: Option<Instant>,
    new_handshake: Option<Instant>,
    zero_keys: Option<Instant>,
    persistent: Option<Instant>,
    need_another_keepalive: bool,
    sent_last_minute: bool,
    established: bool,
    failed: bool,
    out: Vec<Vec<u8>>,
}

impl Device {
    pub fn new(p: &Profile, o: &AmneziaWg) -> Result<Self> {
        let key = |text: &str| amnezia::key(text, "").map_err(|_| Error::Profile);
        let private = Zeroizing::new(key(p.endpoint.password.expose())?);
        let preshared = Zeroizing::new(if o.preshared_key.is_empty() {
            [0; 32]
        } else {
            key(o.preshared_key.expose())?
        });
        let range = |text: &str, default: u32| {
            amnezia::range(text, "")
                .map(|r| if r == (0, 0) { (default, default) } else { r })
                .map_err(|_| Error::Profile)
        };
        let timing = Timing {
            rekey_after: range(&o.rekey_after_time, 120)?,
            rekey_timeout: range(&o.rekey_timeout, 5)?,
            reject_after: range(&o.reject_after_time, 180)?,
            keepalive: range(&o.keepalive_timeout, 10)?,
            attempts: range(&o.max_handshake_attempts, 18)?,
            persistent: range(&o.persistent_keepalive, 0)?,
        };
        Ok(Self {
            keys: noise::Keys::new(*private, key(&o.public_key)?, *preshared)
                .ok_or(Error::Profile)?,
            wire: Wire::new(o)?,
            max_attempts: pick(timing.attempts),
            timing,
            allowed: o
                .allowed_networks()
                .into_iter()
                .filter_map(|(ip, prefix)| ipnet::IpNet::new(ip, prefix).ok())
                .collect(),
            handshake: None,
            current: None,
            previous: None,
            next: None,
            cookie: None,
            last_timestamp: [0; 12],
            last_initiation: None,
            attempts: 0,
            unanswered: 0,
            staged: VecDeque::new(),
            window: DEFAULT_WINDOW,
            retransmit: None,
            keepalive: None,
            new_handshake: None,
            zero_keys: None,
            persistent: None,
            need_another_keepalive: false,
            sent_last_minute: false,
            established: false,
            failed: false,
            out: vec![],
        })
    }
    pub fn established(&self) -> bool {
        self.established
    }
    /// The reference gave up on the handshake and dropped its queue.
    pub fn failed(&self) -> bool {
        self.failed
    }
    pub fn unanswered(&self) -> u32 {
        self.unanswered
    }
    pub fn take_output(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.out)
    }
    pub fn deadline(&self) -> Option<Instant> {
        [
            self.retransmit,
            self.keepalive,
            self.new_handshake,
            self.zero_keys,
            self.persistent,
        ]
        .into_iter()
        .flatten()
        .min()
    }
    /// Keys older than this neither send nor receive.
    fn expire(&self) -> Duration {
        Duration::from_secs(self.timing.reject_after.1.into())
    }
    fn index(&self) -> u32 {
        loop {
            let index = rand::random();
            let taken = [&self.current, &self.previous, &self.next]
                .into_iter()
                .flatten()
                .any(|k| k.local_index == index);
            if !taken {
                return index;
            }
        }
    }
    /// Before a packet with authentication is sent or after one is received.
    fn traversal(&mut self, now: Instant) {
        if self.timing.persistent != (0, 0) {
            self.persistent = Some(now + seconds(self.timing.persistent));
        }
    }
    fn complete(&mut self) {
        self.retransmit = None;
        self.attempts = 0;
        self.unanswered = 0;
        self.max_attempts = pick(self.timing.attempts);
        self.sent_last_minute = false;
        self.established = true;
        self.failed = false;
    }
    fn initiate(&mut self, retry: bool, now: Instant) {
        if !retry {
            self.attempts = 0;
            self.max_attempts = pick(self.timing.attempts);
        }
        let minimum = Duration::from_secs(self.timing.rekey_timeout.0.into());
        if self
            .last_initiation
            .is_some_and(|at| now.duration_since(at) < minimum)
        {
            return;
        }
        let cookie = self
            .cookie
            .filter(|(_, at)| now.duration_since(*at) < COOKIE_LIFETIME)
            .map(|(cookie, _)| cookie);
        let Some((state, message)) = noise::initiation(
            &self.keys,
            self.index(),
            self.wire.header(Kind::Initiation),
            cookie.as_ref(),
        ) else {
            return;
        };
        self.last_initiation = Some(now);
        self.unanswered = self.unanswered.saturating_add(1);
        self.handshake = Some(state);
        self.out.extend(self.wire.preamble());
        self.out
            .push(self.wire.frame(Kind::Initiation, &message, self.window));
        self.traversal(now);
        self.keepalive = None;
        self.retransmit = Some(now + seconds(self.timing.rekey_timeout) + jitter());
    }
    pub fn send_keepalive(&mut self, now: Instant) {
        if self.staged.is_empty() {
            self.staged.push_back(vec![]);
        }
        self.flush(now);
    }
    pub fn send_ip(&mut self, packet: Vec<u8>, now: Instant) {
        if self.staged.len() >= STAGED {
            self.staged.pop_front();
        }
        self.staged.push_back(packet);
        self.flush(now);
    }
    fn flush(&mut self, now: Instant) {
        if self.staged.is_empty() {
            return;
        }
        let expire = self.expire();
        let Some(keypair) = self.current.as_mut().filter(|k| {
            k.counter < REJECT_AFTER_MESSAGES && now.duration_since(k.created) < expire
        }) else {
            self.initiate(false, now);
            return;
        };
        let mut data = false;
        while let Some(mut packet) = self.staged.pop_front() {
            data |= !packet.is_empty();
            let overhead = self.wire.padding(Kind::Transport) + TRANSPORT_HEADER + noise::TAG;
            self.window = self.window.max(overhead + packet.len());
            let padded = packet.len() + self.wire.content_padding(packet.len(), self.window);
            packet.resize(padded, 0);
            let Some((counter, sealed)) = keypair.seal(&packet) else {
                break;
            };
            let mut message = Vec::with_capacity(TRANSPORT_HEADER + sealed.len());
            message.extend(self.wire.header(Kind::Transport).to_le_bytes());
            message.extend(keypair.remote_index.to_le_bytes());
            message.extend(counter.to_le_bytes());
            message.extend(sealed);
            self.out
                .push(self.wire.frame(Kind::Transport, &message, self.window));
        }
        let stale = keypair.counter > REKEY_AFTER_MESSAGES
            || (keypair.initiator
                && now.duration_since(keypair.created) > seconds(self.timing.rekey_after));
        self.traversal(now);
        self.keepalive = None;
        if data && self.new_handshake.is_none() {
            // Nothing back for a keepalive period plus a handshake timeout: rekey.
            self.new_handshake = Some(
                now + Duration::from_secs(self.timing.keepalive.1.into())
                    + seconds(self.timing.rekey_timeout)
                    + jitter(),
            );
        }
        if stale {
            self.initiate(false, now);
        }
    }
    /// Handles one datagram and returns the IP packet it carried, if any.
    pub fn receive(&mut self, datagram: &mut [u8], now: Instant) -> Option<Vec<u8>> {
        let (kind, message) = self.wire.parse(datagram)?;
        match kind {
            Kind::Response => {
                let keypair =
                    noise::consume_response(&self.keys, self.handshake.as_ref()?, message, now)?;
                self.handshake = None;
                self.traversal(now);
                self.new_handshake = None;
                // An unconfirmed responder key outlives the one it replaces.
                self.previous = self.next.take().or(self.current.take());
                self.current = Some(keypair);
                self.zero_keys = Some(now + self.expire() * 3);
                self.complete();
                // Confirms the key to the responder and flushes the queue.
                self.send_keepalive(now);
                None
            }
            Kind::Initiation => {
                let received = noise::consume_initiation(&self.keys, message)?;
                // TAI64N is big-endian: an older or replayed handshake compares lower.
                if received.timestamp <= self.last_timestamp {
                    return None;
                }
                let (message, keypair) = noise::response(
                    &self.keys,
                    &received,
                    self.index(),
                    self.wire.header(Kind::Response),
                    now,
                )?;
                self.last_timestamp = received.timestamp;
                self.traversal(now);
                self.new_handshake = None;
                self.next = Some(keypair);
                self.previous = None;
                self.zero_keys = Some(now + self.expire() * 3);
                self.out
                    .push(self.wire.frame(Kind::Response, &message, self.window));
                self.keepalive = None;
                None
            }
            Kind::Cookie => {
                let cookie = noise::consume_cookie(&self.keys, self.handshake.as_ref()?, message)?;
                self.cookie = Some((cookie, now));
                None
            }
            Kind::Transport => {
                let receiver = u32::from_le_bytes(message[4..8].try_into().unwrap());
                let counter = u64::from_le_bytes(message[8..16].try_into().unwrap());
                let expire = self.expire();
                let confirms = self
                    .next
                    .as_ref()
                    .is_some_and(|k| k.local_index == receiver);
                let keypair = [&mut self.current, &mut self.previous, &mut self.next]
                    .into_iter()
                    .flatten()
                    .find(|k| k.local_index == receiver)
                    .filter(|k| now.duration_since(k.created) < expire)?;
                let mut packet = keypair.open(counter, &message[TRANSPORT_HEADER..])?;
                if confirms {
                    self.previous = self.current.take();
                    self.current = self.next.take();
                    self.complete();
                    self.flush(now);
                }
                self.window = self
                    .window
                    .max(self.wire.padding(Kind::Transport) + TRANSPORT_HEADER + packet.len());
                // The initiator renews a key that is about to be rejected.
                let margin = Duration::from_secs(
                    (self.timing.keepalive.0 + self.timing.rekey_timeout.0).into(),
                );
                if !self.sent_last_minute
                    && self.current.as_ref().is_some_and(|k| {
                        k.initiator
                            && now.duration_since(k.created)
                                > seconds(self.timing.reject_after).saturating_sub(margin)
                    })
                {
                    self.sent_last_minute = true;
                    self.initiate(false, now);
                }
                self.traversal(now);
                self.new_handshake = None;
                // Content padding makes a keepalive a run of zero bytes.
                if packet.first().is_none_or(|b| *b == 0) {
                    return None;
                }
                if self.keepalive.is_none() {
                    self.keepalive = Some(now + seconds(self.timing.keepalive));
                } else {
                    self.need_another_keepalive = true;
                }
                let (length, source): (usize, IpAddr) = match packet[0] >> 4 {
                    4 if packet.len() >= 20 => (
                        u16::from_be_bytes([packet[2], packet[3]]).into(),
                        <[u8; 4]>::try_from(&packet[12..16]).unwrap().into(),
                    ),
                    6 if packet.len() >= 40 => (
                        usize::from(u16::from_be_bytes([packet[4], packet[5]])) + 40,
                        <[u8; 16]>::try_from(&packet[8..24]).unwrap().into(),
                    ),
                    _ => return None,
                };
                if length < 20 || length > packet.len() {
                    return None;
                }
                if !self.allowed.is_empty() && !self.allowed.iter().any(|n| n.contains(&source)) {
                    return None;
                }
                packet.truncate(length);
                Some(packet)
            }
        }
    }
    pub fn timers(&mut self, now: Instant) {
        if due(&mut self.retransmit, now) {
            if self.attempts > self.max_attempts {
                // Give up until there is something to send again.
                self.keepalive = None;
                self.staged.clear();
                self.failed = true;
                if self.zero_keys.is_none() {
                    self.zero_keys = Some(now + self.expire() * 3);
                }
            } else {
                self.attempts += 1;
                self.initiate(true, now);
            }
        }
        if due(&mut self.keepalive, now) {
            self.send_keepalive(now);
            if std::mem::take(&mut self.need_another_keepalive) {
                self.keepalive = Some(now + seconds(self.timing.keepalive));
            }
        }
        if due(&mut self.new_handshake, now) {
            self.initiate(false, now);
        }
        if due(&mut self.zero_keys, now) {
            (self.current, self.previous, self.next) = (None, None, None);
            self.handshake = None;
        }
        if due(&mut self.persistent, now) && self.timing.persistent != (0, 0) {
            self.send_keepalive(now);
        }
    }
}
