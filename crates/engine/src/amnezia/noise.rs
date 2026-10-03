//! WireGuard Noise_IKpsk2 handshake and transport keys. AmneziaWG keeps this
//! cryptography unchanged; only the message type value is configurable.
use blake2::{
    Blake2s256, Blake2sMac, Digest,
    digest::{KeyInit, Mac, consts::U16},
};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305, aead::Aead, aead::Payload};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

pub const INITIATION: usize = 148;
pub const RESPONSE: usize = 92;
pub const COOKIE: usize = 64;
/// Type, receiver index and counter in front of the ciphertext.
pub const TRANSPORT_HEADER: usize = 16;
pub const TAG: usize = 16;
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    for part in parts {
        Digest::update(&mut h, part);
    }
    h.finalize().into()
}
fn mac(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut m = <Blake2sMac<U16> as KeyInit>::new_from_slice(key).expect("key fits BLAKE2s");
    Mac::update(&mut m, data);
    m.finalize().into_bytes().into()
}
fn hmac(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let (mut inner, mut outer) = ([0x36u8; 64], [0x5cu8; 64]);
    for i in 0..32 {
        inner[i] ^= key[i];
        outer[i] ^= key[i];
    }
    let mut h = Blake2s256::new();
    Digest::update(&mut h, inner);
    for part in parts {
        Digest::update(&mut h, part);
    }
    let digest: [u8; 32] = h.finalize().into();
    let result = hash(&[&outer, &digest]);
    inner.zeroize();
    outer.zeroize();
    result
}
/// HKDF with BLAKE2s: `N` chained 32-byte outputs.
fn kdf<const N: usize>(key: &[u8; 32], input: &[u8]) -> [[u8; 32]; N] {
    let mut secret = hmac(key, &[input]);
    let mut out = [[0u8; 32]; N];
    let mut last = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let previous: &[u8] = if i == 0 { &[] } else { &last };
        last = hmac(&secret, &[previous, &[i as u8 + 1]]);
        *slot = last;
    }
    secret.zeroize();
    out
}
fn nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    n
}
fn seal(key: &[u8; 32], counter: u64, msg: &[u8], aad: &[u8]) -> Vec<u8> {
    <ChaCha20Poly1305 as KeyInit>::new(key.into())
        .encrypt(&nonce(counter).into(), Payload { msg, aad })
        .expect("ChaCha20-Poly1305 cannot fail on in-memory buffers")
}
fn open(key: &[u8; 32], counter: u64, msg: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    <ChaCha20Poly1305 as KeyInit>::new(key.into())
        .decrypt(&nonce(counter).into(), Payload { msg, aad })
        .ok()
}
/// X25519 that rejects the all-zero output of a low-order point.
fn dh(secret: &StaticSecret, public: &[u8; 32]) -> Option<[u8; 32]> {
    let shared = secret.diffie_hellman(&PublicKey::from(*public));
    shared.was_contributory().then(|| shared.to_bytes())
}
fn timestamp() -> [u8; 12] {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let mut t = [0u8; 12];
    // TAI64N: big-endian, so byte order is time order.
    t[..8].copy_from_slice(&(0x4000_0000_0000_000a + now.as_secs()).to_be_bytes());
    t[8..].copy_from_slice(&now.subsec_nanos().to_be_bytes());
    t
}

pub struct Keys {
    private: StaticSecret,
    pub public: [u8; 32],
    pub peer: [u8; 32],
    preshared: [u8; 32],
    static_static: [u8; 32],
    /// MAC1 keys for messages we send and messages we receive.
    mac1_peer: [u8; 32],
    mac1_own: [u8; 32],
    cookie_peer: [u8; 32],
    initial_chain: [u8; 32],
    initial_hash: [u8; 32],
}
impl Drop for Keys {
    fn drop(&mut self) {
        self.preshared.zeroize();
        self.static_static.zeroize();
    }
}
impl Keys {
    pub fn new(private: [u8; 32], peer: [u8; 32], preshared: [u8; 32]) -> Option<Self> {
        let private = StaticSecret::from(private);
        let public = PublicKey::from(&private).to_bytes();
        let chain = hash(&[b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"]);
        Some(Self {
            static_static: dh(&private, &peer)?,
            private,
            public,
            peer,
            preshared,
            mac1_peer: hash(&[b"mac1----", &peer]),
            mac1_own: hash(&[b"mac1----", &public]),
            cookie_peer: hash(&[b"cookie--", &peer]),
            initial_hash: hash(&[&chain, b"WireGuard v1 zx2c4 Jason@zx2c4.com"]),
            initial_chain: chain,
        })
    }
}

/// An initiation waiting for its response.
pub struct Initiation {
    pub index: u32,
    ephemeral: StaticSecret,
    chain: [u8; 32],
    hash: [u8; 32],
    /// MAC1 of the sent message: the associated data of a cookie reply.
    mac1: [u8; 16],
}
impl Drop for Initiation {
    fn drop(&mut self) {
        self.chain.zeroize();
    }
}

pub struct Keypair {
    send: ChaCha20Poly1305,
    receive: ChaCha20Poly1305,
    pub local_index: u32,
    pub remote_index: u32,
    pub counter: u64,
    pub replay: Replay,
    pub created: Instant,
    pub initiator: bool,
}
impl Keypair {
    fn new(chain: &[u8; 32], local: u32, remote: u32, initiator: bool, created: Instant) -> Self {
        let [mut first, mut second] = kdf::<2>(chain, &[]);
        let (send, receive) = if initiator {
            (&first, &second)
        } else {
            (&second, &first)
        };
        let pair = Self {
            send: <ChaCha20Poly1305 as KeyInit>::new(send.into()),
            receive: <ChaCha20Poly1305 as KeyInit>::new(receive.into()),
            local_index: local,
            remote_index: remote,
            counter: 0,
            replay: Replay::default(),
            created,
            initiator,
        };
        first.zeroize();
        second.zeroize();
        pair
    }
    /// Encrypts with the next counter; `None` once the counter is exhausted.
    pub fn seal(&mut self, plain: &[u8]) -> Option<(u64, Vec<u8>)> {
        if self.counter >= REJECT_AFTER_MESSAGES {
            return None;
        }
        let counter = self.counter;
        self.counter += 1;
        let data = self.send.encrypt(&nonce(counter).into(), plain).ok()?;
        Some((counter, data))
    }
    /// Authenticates first; the replay window only moves for genuine packets.
    pub fn open(&mut self, counter: u64, data: &[u8]) -> Option<Vec<u8>> {
        let plain = self.receive.decrypt(&nonce(counter).into(), data).ok()?;
        self.replay.accept(counter).then_some(plain)
    }
}

/// Sliding anti-replay window (RFC 6479) over 2048 counters.
#[derive(Default)]
pub struct Replay {
    last: u64,
    started: bool,
    bitmap: [u64; Self::WORDS],
}
impl Replay {
    const WORDS: usize = 32;
    const WINDOW: u64 = (Self::WORDS as u64 - 1) * 64;
    pub fn accept(&mut self, counter: u64) -> bool {
        if counter >= REJECT_AFTER_MESSAGES {
            return false;
        }
        let (top, word) = (self.last / 64, counter / 64);
        if counter > self.last || !self.started {
            for i in 1..=(word - top).min(Self::WORDS as u64) {
                self.bitmap[((top + i) % Self::WORDS as u64) as usize] = 0;
            }
            self.last = counter;
            self.started = true;
        } else if self.last - counter > Self::WINDOW {
            return false;
        }
        let bit = 1u64 << (counter % 64);
        let slot = &mut self.bitmap[(word % Self::WORDS as u64) as usize];
        if *slot & bit != 0 {
            return false;
        }
        *slot |= bit;
        true
    }
}

fn add_macs(keys: &Keys, message: &mut [u8], cookie: Option<&[u8; 16]>) -> [u8; 16] {
    let (mac1_at, mac2_at) = (message.len() - 32, message.len() - 16);
    let mac1 = mac(&keys.mac1_peer, &message[..mac1_at]);
    message[mac1_at..mac2_at].copy_from_slice(&mac1);
    if let Some(cookie) = cookie {
        let mac2 = mac(cookie, &message[..mac2_at]);
        message[mac2_at..].copy_from_slice(&mac2);
    }
    mac1
}
/// MAC1 proves the sender knows our public key; checked before any DH.
fn check_mac1(keys: &Keys, message: &[u8]) -> bool {
    let at = message.len() - 32;
    mac(&keys.mac1_own, &message[..at]) == message[at..at + 16]
}

pub fn initiation(
    keys: &Keys,
    index: u32,
    kind: u32,
    cookie: Option<&[u8; 16]>,
) -> Option<(Initiation, [u8; INITIATION])> {
    let ephemeral = StaticSecret::from(rand::random::<[u8; 32]>());
    let public = PublicKey::from(&ephemeral).to_bytes();
    let mut m = [0u8; INITIATION];
    m[..4].copy_from_slice(&kind.to_le_bytes());
    m[4..8].copy_from_slice(&index.to_le_bytes());
    m[8..40].copy_from_slice(&public);
    let mut h = hash(&[&keys.initial_hash, &keys.peer]);
    let [chain] = kdf::<1>(&keys.initial_chain, &public);
    h = hash(&[&h, &public]);
    let [chain, key] = kdf::<2>(&chain, &dh(&ephemeral, &keys.peer)?);
    let sealed = seal(&key, 0, &keys.public, &h);
    m[40..88].copy_from_slice(&sealed);
    h = hash(&[&h, &sealed]);
    let [chain, key] = kdf::<2>(&chain, &keys.static_static);
    let sealed = seal(&key, 0, &timestamp(), &h);
    m[88..116].copy_from_slice(&sealed);
    h = hash(&[&h, &sealed]);
    let mac1 = add_macs(keys, &mut m, cookie);
    Some((
        Initiation {
            index,
            ephemeral,
            chain,
            hash: h,
            mac1,
        },
        m,
    ))
}

/// Initiator side: the response completes the handshake.
pub fn consume_response(
    keys: &Keys,
    state: &Initiation,
    m: &[u8],
    now: Instant,
) -> Option<Keypair> {
    if m.len() != RESPONSE || !check_mac1(keys, m) {
        return None;
    }
    let remote = u32::from_le_bytes(m[4..8].try_into().unwrap());
    if u32::from_le_bytes(m[8..12].try_into().unwrap()) != state.index {
        return None;
    }
    let ephemeral: [u8; 32] = m[12..44].try_into().unwrap();
    let [chain] = kdf::<1>(&state.chain, &ephemeral);
    let h = hash(&[&state.hash, &ephemeral]);
    let [chain] = kdf::<1>(&chain, &dh(&state.ephemeral, &ephemeral)?);
    let [chain] = kdf::<1>(&chain, &dh(&keys.private, &ephemeral)?);
    let [chain, tau, key] = kdf::<3>(&chain, &keys.preshared);
    let h = hash(&[&h, &tau]);
    open(&key, 0, &m[44..60], &h)?;
    Some(Keypair::new(&chain, state.index, remote, true, now))
}

/// A verified initiation from the configured peer.
pub struct Received {
    index: u32,
    ephemeral: [u8; 32],
    chain: [u8; 32],
    hash: [u8; 32],
    /// Strictly increasing per peer; the caller rejects replays.
    pub timestamp: [u8; 12],
}
pub fn consume_initiation(keys: &Keys, m: &[u8]) -> Option<Received> {
    if m.len() != INITIATION || !check_mac1(keys, m) {
        return None;
    }
    let ephemeral: [u8; 32] = m[8..40].try_into().unwrap();
    let mut h = hash(&[&keys.initial_hash, &keys.public]);
    let [chain] = kdf::<1>(&keys.initial_chain, &ephemeral);
    h = hash(&[&h, &ephemeral]);
    let [chain, key] = kdf::<2>(&chain, &dh(&keys.private, &ephemeral)?);
    if open(&key, 0, &m[40..88], &h)? != keys.peer {
        return None;
    }
    h = hash(&[&h, &m[40..88]]);
    let [chain, key] = kdf::<2>(&chain, &keys.static_static);
    let timestamp = open(&key, 0, &m[88..116], &h)?.try_into().ok()?;
    h = hash(&[&h, &m[88..116]]);
    Some(Received {
        index: u32::from_le_bytes(m[4..8].try_into().unwrap()),
        ephemeral,
        chain,
        hash: h,
        timestamp,
    })
}
pub fn response(
    keys: &Keys,
    received: &Received,
    index: u32,
    kind: u32,
    now: Instant,
) -> Option<([u8; RESPONSE], Keypair)> {
    let ephemeral = StaticSecret::from(rand::random::<[u8; 32]>());
    let public = PublicKey::from(&ephemeral).to_bytes();
    let mut m = [0u8; RESPONSE];
    m[..4].copy_from_slice(&kind.to_le_bytes());
    m[4..8].copy_from_slice(&index.to_le_bytes());
    m[8..12].copy_from_slice(&received.index.to_le_bytes());
    m[12..44].copy_from_slice(&public);
    let [chain] = kdf::<1>(&received.chain, &public);
    let h = hash(&[&received.hash, &public]);
    let [chain] = kdf::<1>(&chain, &dh(&ephemeral, &received.ephemeral)?);
    let [chain] = kdf::<1>(&chain, &dh(&ephemeral, &keys.peer)?);
    let [chain, tau, key] = kdf::<3>(&chain, &keys.preshared);
    let h = hash(&[&h, &tau]);
    m[44..60].copy_from_slice(&seal(&key, 0, &[], &h));
    add_macs(keys, &mut m, None);
    Some((m, Keypair::new(&chain, index, received.index, false, now)))
}

/// Decrypts the cookie a loaded server returned for our last initiation.
pub fn consume_cookie(keys: &Keys, state: &Initiation, m: &[u8]) -> Option<[u8; 16]> {
    if m.len() != COOKIE || u32::from_le_bytes(m[4..8].try_into().unwrap()) != state.index {
        return None;
    }
    <XChaCha20Poly1305 as KeyInit>::new((&keys.cookie_peer).into())
        .decrypt(
            m[8..32].into(),
            Payload {
                msg: &m[32..],
                aad: &state.mac1,
            },
        )
        .ok()?
        .try_into()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pair() -> (Keys, Keys) {
        let (a, b) = ([7u8; 32], [9u8; 32]);
        let public = |k: [u8; 32]| PublicKey::from(&StaticSecret::from(k)).to_bytes();
        (
            Keys::new(a, public(b), [3; 32]).unwrap(),
            Keys::new(b, public(a), [3; 32]).unwrap(),
        )
    }
    #[test]
    fn handshake_derives_matching_transport_keys() {
        let (client, server) = pair();
        let (state, first) = initiation(&client, 11, 0xdead_beef, None).unwrap();
        let received = consume_initiation(&server, &first).unwrap();
        let (second, mut responder) = response(&server, &received, 22, 77, Instant::now()).unwrap();
        let mut initiator = consume_response(&client, &state, &second, Instant::now()).unwrap();
        assert_eq!((initiator.local_index, initiator.remote_index), (11, 22));
        let (counter, data) = initiator.seal(b"ping").unwrap();
        assert_eq!(responder.open(counter, &data).unwrap(), b"ping");
        assert!(responder.open(counter, &data).is_none(), "replay");
        let (counter, data) = responder.seal(b"").unwrap();
        assert_eq!(data.len(), TAG);
        assert!(initiator.open(counter, &data).unwrap().is_empty());
    }
    #[test]
    fn tampering_wrong_keys_and_low_order_points_are_rejected() {
        let (client, server) = pair();
        let (state, first) = initiation(&client, 1, 1, None).unwrap();
        for at in [0, 10, 50, 100, 120] {
            let mut bad = first;
            bad[at] ^= 1;
            assert!(consume_initiation(&server, &bad).is_none(), "byte {at}");
        }
        // A third party that only knows the server's public key.
        let stranger = Keys::new([5; 32], server.public, [3; 32]).unwrap();
        let (_, foreign) = initiation(&stranger, 1, 1, None).unwrap();
        assert!(consume_initiation(&server, &foreign).is_none());
        let wrong_psk = Keys::new([9; 32], client.public, [4; 32]).unwrap();
        let received = consume_initiation(&wrong_psk, &first).unwrap();
        let (second, _) = response(&wrong_psk, &received, 2, 2, Instant::now()).unwrap();
        assert!(consume_response(&client, &state, &second, Instant::now()).is_none());
        assert!(Keys::new([7; 32], [0; 32], [0; 32]).is_none());
    }
    #[test]
    fn replay_window_accepts_reordering_once() {
        let mut r = Replay::default();
        assert!(r.accept(0) && !r.accept(0));
        assert!(r.accept(5) && r.accept(3) && !r.accept(3));
        assert!(r.accept(5000) && r.accept(5000 - Replay::WINDOW));
        assert!(!r.accept(5000 - Replay::WINDOW - 1) && !r.accept(5));
        assert!(r.accept(1 << 40) && !r.accept(5000));
        assert!(!r.accept(REJECT_AFTER_MESSAGES));
    }
}
