//! Explicitly opted-in interoperability test; profile contents are never logged.
use rtrust_engine::{Session, dns};
use rtrust_profile::Profile;
#[tokio::test]
#[ignore = "requires RTRUST_DNS_TEST_PROFILE pointing to a private authorized profile"]
async fn dot_and_doh_through_real_vpn_with_certificate_rejection() {
    let path = std::env::var_os("RTRUST_DNS_TEST_PROFILE").expect("private profile path required");
    let raw = zeroize::Zeroizing::new(std::fs::read_to_string(path).unwrap());
    let mut profile = Profile::import(&raw).unwrap();
    profile.endpoint.upstream_protocol = "http2".into();
    let session = Session::connect(&profile).await.unwrap();
    let query = [
        0x52, 0x54, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111,
        109, 0, 0, 1, 0, 1,
    ];
    for url in ["tls://1.1.1.1", "https://cloudflare-dns.com/dns-query"] {
        let answer = dns::Resolver::parse(url)
            .unwrap()
            .exchange(&session, &query)
            .await
            .unwrap();
        assert_eq!(&answer[..2], &query[..2]);
        assert_eq!(answer[3] & 15, 0);
        assert!(u16::from_be_bytes([answer[6], answer[7]]) > 0);
    }
    let rejected = dns::Resolver::parse("https://wrong.host.badssl.com/dns-query")
        .unwrap()
        .exchange(&session, &query)
        .await;
    assert!(matches!(rejected, Err(rtrust_engine::Error::Tls)));
}
