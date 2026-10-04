use rtrust_profile::{Format, MAX_INPUT, Profile};
const ENDPOINT: &str = "hostname='vpn.example'\naddresses=['192.0.2.10:8443','[2001:db8::1]:443']\nusername='user'\npassword='CANARY-DO-NOT-LOG'\nname='Ноутбук'\ndns_upstreams=['tls://1.1.1.1']\n";
#[test]
fn all_formats_preserve_endpoint() {
    let p = Profile::import(ENDPOINT).unwrap();
    for f in Format::ALL {
        let e = p.export(f).unwrap();
        let parsed = Profile::import(&e.content).unwrap();
        assert_eq!(parsed.endpoint, p.endpoint, "{f}");
    }
}
#[test]
fn cli_preserves_policies_and_unknown_options() {
    let raw = format!(
        "killswitch_enabled=true\nvpn_mode='selective'\nexclusions=['*.example.org']\n[listener.tun]\nmtu_size=1280\n[endpoint]\n{ENDPOINT}"
    );
    let p = Profile::import(&raw).unwrap();
    let export = p.export(Format::CliToml).unwrap();
    let parsed = Profile::import(&export.content).unwrap();
    assert_eq!(
        parsed.original_cli.as_ref().unwrap()["exclusions"][0].as_str(),
        Some("*.example.org")
    );
    assert!(!p.export(Format::Link).unwrap().losses.is_empty());
}
#[test]
fn errors_and_debug_do_not_echo_credentials() {
    let p = Profile::import(ENDPOINT).unwrap();
    assert!(!format!("{p:?}").contains("CANARY"));
    let invalid = ENDPOINT.replace("8443", "CANARY-DO-NOT-LOG");
    assert!(
        !Profile::import(&invalid)
            .unwrap_err()
            .to_string()
            .contains("CANARY")
    );
    assert!(
        !Profile::import("password = 'CANARY\n")
            .unwrap_err()
            .to_string()
            .contains("CANARY")
    );
}
#[test]
fn unsafe_options_preserved_for_capability_checks() {
    let raw = format!(
        "{ENDPOINT}skip_verification=true\nanti_dpi=true\nclient_random_prefix='aabb/ffff'\n"
    );
    let p = Profile::import(&raw).unwrap();
    let q = Profile::import(&p.export(Format::Link).unwrap().content).unwrap();
    assert!(q.endpoint.skip_verification);
    assert!(q.endpoint.anti_dpi);
    assert_eq!(q.endpoint.client_random_prefix, "aabb/ffff");
}
#[test]
fn ambiguity_limits_and_future_version() {
    assert!(Profile::import(&format!("{ENDPOINT}\n[endpoint]\n{ENDPOINT}")).is_err());
    assert!(Profile::import(&"x".repeat(MAX_INPUT + 1)).is_err());
    let p = Profile::import(ENDPOINT).unwrap();
    let raw = p
        .export(Format::Json)
        .unwrap()
        .content
        .replace("\"schema_version\": 1", "\"schema_version\": 2");
    assert!(Profile::import(&raw).is_err());
}
#[test]
fn legacy_json_ipv6() {
    let p=Profile::import(r#"{"label":"IPv6","address":"2001:db8::1","port":"443","domain":"vpn.example","sni":"","protocol":"HTTP2","username":"user","password":"pass"}"#).unwrap();
    assert_eq!(p.endpoint.addresses, vec!["[2001:db8::1]:443"]);
}

#[test]
fn legacy_embedded_link_conflicts_are_rejected() {
    let p = Profile::import(
        "hostname='vpn.example'\naddresses=['192.0.2.1:443']\nusername='user'\npassword='pass'\n",
    )
    .unwrap();
    let link = p.export(Format::Link).unwrap();
    let mut legacy = serde_json::json!({"address":"192.0.2.1", "port":443, "domain":"vpn.example", "sni":"vpn.example", "protocol":"http2", "username":"user", "password":"pass", "deeplink":link.content});
    assert!(Profile::import(&legacy.to_string()).is_ok());
    for (field, value) in [
        ("domain", "different.example"),
        ("sni", "different.example"),
        ("protocol", "http3"),
    ] {
        let original = legacy[field].clone();
        legacy[field] = value.into();
        assert!(Profile::import(&legacy.to_string()).is_err(), "{field}");
        legacy[field] = original;
    }
}

#[test]
fn udp_transport_follows_the_profile_transport() {
    let mut profile =
        Profile::import(include_str!("../../../examples/demo.endpoint.toml")).unwrap();
    profile.endpoint.upstream_protocol = "http2".into();
    assert!(!profile.udp_transport());
    profile.endpoint.upstream_protocol = "http3".into();
    assert!(profile.udp_transport());
    profile.protocol = rtrust_profile::Protocol::Hysteria2;
    assert!(profile.udp_transport());
    profile.protocol = rtrust_profile::Protocol::AmneziaWg;
    assert!(profile.udp_transport());
}
