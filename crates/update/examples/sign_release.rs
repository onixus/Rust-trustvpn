//! Offline release signing. Never put key bytes in arguments or CI reports.
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::signature::{Ed25519KeyPair, KeyPair};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 3 {
        return Err("usage: sign_release KEY.pk8 MANIFEST.json OUTPUT.json".into());
    }
    let key = zeroize::Zeroizing::new(std::fs::read(&args[0])?);
    let pair =
        Ed25519KeyPair::from_pkcs8_maybe_unchecked(&key).map_err(|_| "Invalid Ed25519 key")?;
    if pair.public_key().as_ref() != include_bytes!("../src/root.pub") {
        return Err("Key differs from pinned update root".into());
    }
    let payload = std::fs::read(&args[1])?;
    let m: rtrust_update::Manifest = serde_json::from_slice(&payload)?;
    let envelope = serde_json::to_vec(&rtrust_update::Envelope {
        payload: STANDARD.encode(&payload),
        signature: STANDARD.encode(pair.sign(&payload).as_ref()),
    })?;
    rtrust_update::verify(&envelope, &m.target, rtrust_update::now()?, 0)?;
    std::fs::write(&args[2], envelope)?;
    println!("Signed release {} for {}", m.sequence, m.target);
    Ok(())
}
