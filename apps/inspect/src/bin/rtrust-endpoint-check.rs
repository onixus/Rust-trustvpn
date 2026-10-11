//! Private server-side auth receipt. Stdin carries a canonical profile; every
//! address must be loopback, TLS remains verified, and no destination is relayed.
use std::{
    io::{Read, Write},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[tokio::main]
async fn main() {
    let started = Instant::now();
    let outcome = check().await;
    let value = serde_json::json!({"schema":1,"outcome":outcome,"elapsed_ms":started.elapsed().as_millis(),"scope":"loopback_endpoint_authenticated_check"});
    let _ = std::io::stdout().write_all(value.to_string().as_bytes());
}
async fn check() -> &'static str {
    let mut bytes = Zeroizing::new(Vec::new());
    if std::io::stdin()
        .take((rtrust_profile::MAX_INPUT + 1) as u64)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() > rtrust_profile::MAX_INPUT
    {
        return "invalid";
    }
    let Ok(input) = std::str::from_utf8(&bytes) else {
        return "invalid";
    };
    let Ok(profile) = rtrust_profile::Profile::import(input) else {
        return "invalid";
    };
    if profile.protocol != rtrust_profile::Protocol::TrustTunnel
        || !matches!(
            profile.endpoint.upstream_protocol.as_str(),
            "http2" | "http3"
        )
        || profile.endpoint.addresses.is_empty()
        || profile.endpoint.addresses.iter().any(|address| {
            address
                .parse::<std::net::SocketAddr>()
                .map_or(true, |address| !address.ip().is_loopback())
        })
    {
        return "unsupported";
    }
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        // The supervisor has just spawned its replacement listener. Retry only
        // connection establishment briefly; never retry an authentication denial.
        let mut attempts = 0;
        let session = loop {
            match rtrust_engine::Session::connect(&profile).await {
                Ok(session) => break session,
                Err(error)
                    if matches!(error, rtrust_engine::Error::Authentication) || attempts == 4 =>
                {
                    return Err(error);
                }
                Err(_) => {
                    attempts += 1;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        };
        session.health().await
    })
    .await;
    match result {
        Ok(Ok(())) => "authenticated",
        Ok(Err(rtrust_engine::Error::Authentication)) => "rejected",
        _ => "unavailable",
    }
}
