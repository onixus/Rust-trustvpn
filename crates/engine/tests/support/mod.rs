use std::sync::Arc;

/// A fresh synthetic localhost certificate and matching server configuration.
/// Callers select their transport's ALPN and trust this certificate in the profile.
pub fn localhost_tls() -> (rustls::ServerConfig, String) {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
    let tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certified.cert.der().clone()], key.into())
        .unwrap();
    (tls, certified.cert.pem())
}
