use super::{device::Device, *};
use base64::Engine;
use x25519_dalek::{PublicKey, StaticSecret};

const AWG3: &str = "Jc = 3\nJmin = 20\nJmax = 60\nS1 = 15\nS2 = 20\nS3 = 12\nS4 = 16\nH1 = 100-200\nH2 = 300-310\nH3 = 400-500\nH4 = 600-700\nI1 = <b 0xc0ff><r 16><t>\nHeaderProtectionKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\nContentPaddingAddition = 8-40\nRandomTrailers = on\n";

fn b64(bytes: [u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
fn device(private: [u8; 32], peer: [u8; 32], address: &str, allowed: &str, extra: &str) -> Device {
    let public = PublicKey::from(&StaticSecret::from(peer)).to_bytes();
    let text = format!(
        "[Interface]\nPrivateKey = {}\nAddress = {address}\n{extra}[Peer]\nPublicKey = {}\nPresharedKey = {}\nAllowedIPs = {allowed}\nEndpoint = 127.0.0.1:51820\n",
        b64(private),
        b64(public),
        b64([3; 32]),
    );
    let profile = Profile::import(&text).unwrap();
    Device::new(&profile, profile.amneziawg.as_ref().unwrap()).unwrap()
}
fn pair(extra: &str) -> (Device, Device) {
    (
        device([7; 32], [9; 32], "10.8.1.2/32", "0.0.0.0/0", extra),
        device([9; 32], [7; 32], "10.8.1.1/32", "10.8.1.2/32", extra),
    )
}
/// Delivers everything `from` queued and returns the IP packets `to` accepted.
fn deliver(from: &mut Device, to: &mut Device, now: Instant) -> Vec<Vec<u8>> {
    from.take_output()
        .into_iter()
        .filter_map(|mut datagram| to.receive(&mut datagram, now))
        .collect()
}
fn packet(source: [u8; 4], len: usize) -> Vec<u8> {
    let mut p = vec![0x5a; len];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    p[12..16].copy_from_slice(&source);
    p
}
fn establish(client: &mut Device, server: &mut Device, now: Instant) {
    client.send_keepalive(now);
    assert!(deliver(client, server, now).is_empty());
    assert!(deliver(server, client, now).is_empty());
    assert!(client.established() && !server.established());
    // The first transport packet confirms the key to the responder.
    assert!(deliver(client, server, now).is_empty());
    assert!(server.established());
}

#[test]
fn plain_wireguard_layout_is_unchanged_without_options() {
    let (mut client, mut server) = pair("");
    let now = Instant::now();
    client.send_keepalive(now);
    let out = client.take_output();
    assert_eq!(out.len(), 1);
    assert_eq!((out[0].len(), &out[0][..4]), (148, &[1u8, 0, 0, 0][..]));
    assert!(server.receive(&mut out[0].clone(), now).is_none());
    let response = server.take_output();
    assert_eq!(
        (response[0].len(), &response[0][..4]),
        (92, &[2u8, 0, 0, 0][..])
    );
    assert!(client.receive(&mut response[0].clone(), now).is_none());
    let keepalive = client.take_output();
    assert_eq!(
        (keepalive[0].len(), &keepalive[0][..4]),
        (32, &[4u8, 0, 0, 0][..])
    );
    // A replayed initiation must not produce a second response.
    assert!(server.receive(&mut out[0].clone(), now).is_none());
    assert!(server.take_output().is_empty());
}

#[test]
fn obfuscated_handshake_and_data_in_both_directions() {
    for extra in ["", AWG3] {
        let (mut client, mut server) = pair(extra);
        let now = Instant::now();
        client.send_keepalive(now);
        let first = client.take_output();
        // Signature packet, junk, then the initiation.
        assert_eq!(first.len(), if extra.is_empty() { 1 } else { 5 });
        for mut datagram in first {
            assert!(server.receive(&mut datagram, now).is_none());
        }
        assert!(deliver(&mut server, &mut client, now).is_empty());
        assert!(deliver(&mut client, &mut server, now).is_empty());
        assert!(client.established() && server.established());
        for len in [20, 21, 100, 1279, 1280] {
            let up = packet([10, 8, 1, 2], len);
            client.send_ip(up.clone(), now);
            assert_eq!(deliver(&mut client, &mut server, now), [up]);
            let down = packet([192, 0, 2, 1], len);
            server.send_ip(down.clone(), now);
            assert_eq!(deliver(&mut server, &mut client, now), [down]);
        }
        // Source addresses outside AllowedIPs are dropped after decryption.
        client.send_ip(packet([10, 8, 1, 3], 40), now);
        assert!(deliver(&mut client, &mut server, now).is_empty());
        // Replayed transport datagrams are dropped.
        client.send_ip(packet([10, 8, 1, 2], 40), now);
        let sent = client.take_output();
        assert!(server.receive(&mut sent[0].clone(), now).is_some());
        assert!(server.receive(&mut sent[0].clone(), now).is_none());
    }
}

#[test]
fn mismatched_obfuscation_never_reaches_the_handshake() {
    for other in [
        AWG3.replace("AAEC", "BAEC"),
        AWG3.replace("S1 = 15", "S1 = 14"),
        AWG3.replace("H1 = 100-200", "H1 = 201-250"),
        String::new(),
    ] {
        let (mut client, _) = pair(AWG3);
        let (_, mut server) = pair(&other);
        let now = Instant::now();
        client.send_keepalive(now);
        assert!(deliver(&mut client, &mut server, now).is_empty());
        assert!(server.take_output().is_empty(), "{other}");
    }
}

#[test]
fn handshake_retransmits_and_gives_up_after_the_configured_attempts() {
    let (mut client, _) = pair("RekeyTimeout = 2\nMaxHandshakeAttempts = 2\n");
    let start = Instant::now();
    client.send_keepalive(start);
    assert_eq!(client.take_output().len(), 1);
    let mut sent = 0;
    for second in 1..30 {
        let now = start + Duration::from_secs(second);
        assert!(
            client
                .deadline()
                .is_none_or(|at| at > now - Duration::from_secs(1))
        );
        client.timers(now);
        sent += client.take_output().len();
    }
    // The reference retries while attempts <= maximum: three retransmissions.
    assert_eq!(sent, 3);
    assert!(client.failed() && !client.established());
    // New traffic starts over.
    client.send_ip(packet([10, 8, 1, 2], 40), start + Duration::from_secs(60));
    assert_eq!(client.take_output().len(), 1);
}

#[test]
fn keys_rotate_and_expire_on_the_configured_timers() {
    let (mut client, mut server) = pair(AWG3);
    let start = Instant::now();
    establish(&mut client, &mut server, start);
    let up = packet([10, 8, 1, 2], 100);
    // Past REKEY_AFTER_TIME the initiator renews while the old key still works.
    let now = start + Duration::from_secs(121);
    client.send_ip(up.clone(), now);
    assert_eq!(
        deliver(&mut client, &mut server, now),
        std::slice::from_ref(&up)
    );
    assert!(deliver(&mut server, &mut client, now).is_empty());
    assert!(deliver(&mut client, &mut server, now).is_empty());
    client.send_ip(up.clone(), now);
    assert_eq!(
        deliver(&mut client, &mut server, now),
        std::slice::from_ref(&up)
    );
    // Without traffic the key expires and sending needs a fresh handshake.
    let now = now + Duration::from_secs(181);
    client.send_ip(up.clone(), now);
    assert!(deliver(&mut client, &mut server, now).is_empty());
    assert!(deliver(&mut server, &mut client, now).is_empty());
    assert_eq!(deliver(&mut client, &mut server, now), [up]);
}

#[test]
fn passive_keepalive_answers_received_data() {
    let (mut client, mut server) = pair("");
    let start = Instant::now();
    establish(&mut client, &mut server, start);
    server.send_ip(packet([192, 0, 2, 1], 60), start);
    assert_eq!(deliver(&mut server, &mut client, start).len(), 1);
    let now = start + Duration::from_secs(11);
    client.timers(now);
    let out = client.take_output();
    assert_eq!((out.len(), out[0].len()), (1, 32));
    // The server heard back in time and does not start a new handshake.
    assert!(server.receive(&mut out[0].clone(), now).is_none());
    server.timers(start + Duration::from_secs(16));
    assert!(server.take_output().is_empty());
}
