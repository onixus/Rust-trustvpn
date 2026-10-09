//! User-initiated, read-only destination diagnostics. No transport is created.
//! Results are per destination, never global VPN/guard verification.
use crate::connection::Session;
use rtrust_control::observations::{Snapshot, now_ms};
use rtrust_profile::routing::{Context, Decision, Reason};
use serde::Serialize;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::net::SocketAddr;
use std::{net::IpAddr, time::Duration};
#[cfg(any(target_os = "macos", target_os = "linux", test))]
use tokio::io::AsyncReadExt;

#[cfg(any(target_os = "macos", target_os = "linux", test))]
const OUTPUT_LIMIT: u64 = 8192;
const ADDRESS_LIMIT: usize = 8;
const TOTAL: Duration = Duration::from_secs(15);
#[cfg(any(target_os = "macos", target_os = "linux", test))]
const STEP: Duration = Duration::from_secs(3);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Fact {
    NotChecked,
    Passed,
    Failed,
    Timeout,
    Unsupported,
    SessionChanged,
    RouteMismatch,
    TlsFailed,
    ConnectionFailed,
}
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub schema: u32,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
    pub lifecycle: Snapshot,
    pub policy: Option<Decision>,
    pub dns: Fact,
    pub answer_count: usize,
    pub route: Fact,
    pub https: Fact,
    pub http_status: Option<u16>,
    pub ipv6: bool,
    /// HTTPS response does not certify application functionality or general Internet.
    pub scope: &'static str,
}
impl Report {
    fn new(snapshot: Snapshot) -> Self {
        Self {
            schema: 1,
            started_at_ms: now_ms(),
            finished_at_ms: 0,
            lifecycle: snapshot,
            policy: None,
            dns: Fact::NotChecked,
            answer_count: 0,
            route: Fact::NotChecked,
            https: Fact::NotChecked,
            http_status: None,
            ipv6: false,
            scope: "one_destination_system_path_no_global_protection_claim",
        }
    }
    /// Safe default export. Contains no target, addresses, URL, headers or raw errors.
    pub fn redacted_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("typed report")
    }
    pub fn summary(&self) -> String {
        fn label(f: Fact) -> &'static str {
            match f {
                Fact::NotChecked => "не проверено",
                Fact::Passed => "проверено",
                Fact::Failed => "сбой",
                Fact::Timeout => "время истекло (причина неизвестна)",
                Fact::Unsupported => "не поддерживается",
                Fact::SessionChanged => "сеанс изменился; повторите проверку",
                Fact::RouteMismatch => "маршрут вне интерфейса VPN; HTTPS не отправлен",
                Fact::TlsFailed => "ошибка проверки TLS",
                Fact::ConnectionFailed => "соединение не установлено (причина неизвестна)",
            }
        }
        format!(
            "Проверка {}–{} · DNS: {} · маршрут: {} · HTTPS: {}{} · состояние защиты не подтверждается этой проверкой.",
            self.started_at_ms,
            self.finished_at_ms,
            label(self.dns),
            label(self.route),
            label(self.https),
            self.http_status
                .map(|s| format!(" · HTTP {s} (не доказывает работу функции сайта)"))
                .unwrap_or_default()
        )
    }
}
#[derive(Clone, Debug)]
pub struct Target {
    host: String,
}
impl Target {
    /// Host or numeric address only. No URL, userinfo, query, path or arbitrary port.
    pub fn parse(input: &str) -> Result<Self, &'static str> {
        if input != input.trim() || input.is_empty() || input.len() > 253 {
            return Err("Введите hostname или IP без URL и порта");
        }
        if input.parse::<IpAddr>().is_ok() {
            return Ok(Self { host: input.into() });
        }
        if input.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        }) {
            return Err("Введите hostname или IP без URL и порта");
        }
        Ok(Self {
            host: input.to_ascii_lowercase(),
        })
    }
    #[cfg(any(target_os = "macos", target_os = "linux", test))]
    fn https_url(&self) -> String {
        if self.host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("https://[{}]/", self.host)
        } else {
            format!("https://{}/", self.host)
        }
    }
}

trait Backend {
    async fn resolve(&self, target: &Target) -> Result<Vec<IpAddr>, Fact>;
    async fn route(&self, ip: IpAddr) -> Result<bool, Fact>;
    async fn https(&self, target: &Target, ip: IpAddr) -> Result<u16, Fact>;
    fn lifecycle(&self) -> Snapshot;
    fn active(&self) -> bool;
    fn policy(&self, _ip: IpAddr) -> Decision {
        Decision::unknown(Context::default(), Reason::SystemPathUnobserved)
    }
}
struct System {
    session: Session,
    selection: Option<rtrust_control::Selection>,
    context: Context,
}
impl System {
    fn unchanged(&self, initial: &Snapshot) -> bool {
        let current = self.session.observations();
        self.active() && current.generation == initial.generation
    }
}
impl Backend for System {
    fn policy(&self, ip: IpAddr) -> Decision {
        #[cfg(target_os = "linux")]
        let endpoints: Option<&[std::net::Ipv4Addr]> = Some(&[]);
        #[cfg(not(target_os = "linux"))]
        let endpoints: Option<&[std::net::Ipv4Addr]> = None;
        self.selection
            .as_ref()
            .and_then(|s| s.explain(ip, endpoints, None, self.context.clone()).ok())
            .unwrap_or_else(|| {
                Decision::unknown(self.context.clone(), Reason::SystemPathUnobserved)
            })
    }
    fn lifecycle(&self) -> Snapshot {
        self.session.observations()
    }
    fn active(&self) -> bool {
        self.session.is_tun()
            && matches!(
                self.session.observations().transport.outcome,
                rtrust_control::observations::Outcome::Configured
                    | rtrust_control::observations::Outcome::Passed
            )
    }
    async fn resolve(&self, target: &Target) -> Result<Vec<IpAddr>, Fact> {
        if let Ok(ip) = target.host.parse() {
            return Ok(vec![ip]);
        }
        #[cfg(target_os = "macos")]
        let bytes = command(
            "/usr/bin/dscacheutil",
            &["-q", "host", "-a", "name", &target.host],
        )
        .await?;
        #[cfg(target_os = "linux")]
        let bytes = command("/usr/bin/getent", &["ahosts", &target.host]).await?;
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            parse_answers(&bytes)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            Err(Fact::Unsupported)
        }
    }
    async fn route(&self, ip: IpAddr) -> Result<bool, Fact> {
        #[cfg(target_os = "macos")]
        {
            let family = if ip.is_ipv6() { "-inet6" } else { "-inet" };
            let bytes = command("/sbin/route", &["-n", "get", family, &ip.to_string()]).await?;
            mac_route(&bytes)
        }
        #[cfg(target_os = "linux")]
        {
            // Explicit effective UID matches the service's uidrange policy rule.
            let uid = unsafe { libc::geteuid() }.to_string();
            let bytes = command(
                "/usr/sbin/ip",
                &[
                    "-j",
                    "route",
                    "get",
                    &ip.to_string(),
                    "ipproto",
                    "tcp",
                    "dport",
                    "443",
                    "uid",
                    &uid,
                ],
            )
            .await?;
            linux_route(&bytes)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = ip;
            Err(Fact::Unsupported)
        }
    }
    async fn https(&self, target: &Target, ip: IpAddr) -> Result<u16, Fact> {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            if !self.active() {
                return Err(Fact::SessionChanged);
            }
            #[cfg(target_os = "macos")]
            let device = "utun5254";
            #[cfg(target_os = "linux")]
            let device = "rtrust0";
            let client = https_builder(target, SocketAddr::new(ip, 443), device)
                .build()
                .map_err(|_| Fact::Unsupported)?;
            // HEAD /, no body consumption, no redirects/retries/fallback endpoint.
            let response = client
                .head(target.https_url())
                .send()
                .await
                .map_err(classify_http_error)?;
            Ok(response.status().as_u16())
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = (target, ip);
            Err(Fact::Unsupported)
        }
    }
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn https_builder(target: &Target, address: SocketAddr, device: &str) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .no_proxy()
        .interface(device)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .connect_timeout(STEP)
        .resolve(&target.host, address)
        .pool_max_idle_per_host(0)
        .http1_only()
}
#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn classify_http_error(error: reqwest::Error) -> Fact {
    fn tls_cause(error: &(dyn std::error::Error + 'static), remaining: u8) -> bool {
        if remaining == 0 {
            return false;
        }
        if error.downcast_ref::<rustls::Error>().is_some() {
            return true;
        }
        // std::io::Error::source can skip its boxed error. Inspect get_ref too.
        if let Some(io) = error.downcast_ref::<std::io::Error>()
            && let Some(inner) = io.get_ref()
            && tls_cause(inner, remaining - 1)
        {
            return true;
        }
        error
            .source()
            .is_some_and(|inner| tls_cause(inner, remaining - 1))
    }
    if tls_cause(&error, 12) {
        Fact::TlsFailed
    } else if error.is_timeout() {
        Fact::Timeout
    } else {
        Fact::ConnectionFailed
    }
}
/// A dropped diagnostic future kills its resolver/route subprocess. Stdout is bounded.
#[cfg(any(target_os = "macos", target_os = "linux", test))]
async fn command(executable: &str, args: &[&str]) -> Result<Vec<u8>, Fact> {
    let child = tokio::process::Command::new(executable)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| Fact::Unsupported)?;
    tokio::time::timeout(STEP, read_child(child))
        .await
        .map_err(|_| Fact::Timeout)?
}
#[cfg(any(target_os = "macos", target_os = "linux", test))]
async fn read_child(mut child: tokio::process::Child) -> Result<Vec<u8>, Fact> {
    let mut bytes = Vec::new();
    child
        .stdout
        .take()
        .ok_or(Fact::Failed)?
        .take(OUTPUT_LIMIT + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| Fact::Failed)?;
    if bytes.len() as u64 > OUTPUT_LIMIT {
        return Err(Fact::Failed);
    }
    if !child.wait().await.map_err(|_| Fact::Failed)?.success() {
        return Err(Fact::Failed);
    }
    Ok(bytes)
}
#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn parse_answers(bytes: &[u8]) -> Result<Vec<IpAddr>, Fact> {
    let text = std::str::from_utf8(bytes).map_err(|_| Fact::Failed)?;
    let mut answers = Vec::new();
    for line in text.lines() {
        #[cfg(target_os = "macos")]
        let word = line
            .strip_prefix("ip_address:")
            .or_else(|| line.strip_prefix("ipv6_address:"))
            .map(str::trim);
        #[cfg(not(target_os = "macos"))]
        let word = line.split_whitespace().next();
        if let Some(ip) = word.and_then(|w| w.parse().ok()) {
            if !answers.contains(&ip) {
                answers.push(ip);
            }
            if answers.len() > ADDRESS_LIMIT {
                return Err(Fact::Failed);
            }
        }
    }
    if answers.is_empty() {
        Err(Fact::Failed)
    } else {
        Ok(answers)
    }
}
#[cfg(any(target_os = "macos", test))]
fn mac_route(bytes: &[u8]) -> Result<bool, Fact> {
    let text = std::str::from_utf8(bytes).map_err(|_| Fact::Failed)?;
    let interfaces: Vec<_> = text
        .lines()
        .filter_map(|l| l.trim().strip_prefix("interface:").map(str::trim))
        .collect();
    if interfaces.len() != 1 {
        return Err(Fact::Failed);
    }
    Ok(interfaces[0] == "utun5254")
}
#[cfg(any(target_os = "linux", test))]
fn linux_route(bytes: &[u8]) -> Result<bool, Fact> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| Fact::Failed)?;
    let rows = value
        .as_array()
        .filter(|r| r.len() == 1)
        .ok_or(Fact::Failed)?;
    let device = rows[0]
        .get("dev")
        .and_then(|v| v.as_str())
        .ok_or(Fact::Failed)?;
    Ok(device == "rtrust0")
}
async fn diagnose(backend: &impl Backend, target: &Target, report: &mut Report) {
    if !backend.active() {
        report.route = Fact::SessionChanged;
        return;
    }
    let initial = backend.lifecycle();
    let ips = match backend.resolve(target).await {
        Ok(ips) if !ips.is_empty() && ips.len() <= ADDRESS_LIMIT => ips,
        Ok(_) => {
            report.dns = Fact::Failed;
            return;
        }
        Err(e) => {
            report.dns = e;
            return;
        }
    };
    report.dns = if target.host.parse::<IpAddr>().is_ok() {
        Fact::NotChecked
    } else {
        Fact::Passed
    };
    report.answer_count = ips.len();
    // One selected address, no retry to other addresses or a direct comparison.
    let ip = ips[0];
    report.ipv6 = ip.is_ipv6();
    let mut decision = backend.policy(ip);
    // Server revisions are opaque input. Export only a fingerprint, never raw text.
    if let Some(revision) = decision.context.revision.take() {
        use sha2::Digest;
        decision.context.revision = Some(format!(
            "sha256:{:x}",
            sha2::Sha256::digest(revision.as_bytes())
        ));
    }
    report.policy = Some(decision);
    if !backend.active() || backend.lifecycle().generation != initial.generation {
        report.route = Fact::SessionChanged;
        return;
    }
    match backend.route(ip).await {
        Ok(true) => report.route = Fact::Passed,
        Ok(false) => {
            report.route = Fact::RouteMismatch;
            return;
        }
        Err(e) => {
            report.route = e;
            return;
        }
    }
    if !backend.active() || backend.lifecycle().generation != initial.generation {
        report.https = Fact::SessionChanged;
        return;
    }
    match backend.https(target, ip).await {
        Ok(status) => {
            report.https = Fact::Passed;
            report.http_status = Some(status);
        }
        Err(e) => report.https = e,
    }
    if !backend.active() || backend.lifecycle().generation != initial.generation {
        report.https = Fact::SessionChanged;
        report.http_status = None;
    }
}
pub async fn run(
    target: Target,
    session: Session,
    selection: Option<rtrust_control::Selection>,
    context: Context,
) -> Report {
    let system = System {
        session,
        selection,
        context,
    };
    let mut report = Report::new(system.lifecycle());
    let initial = report.lifecycle.clone();
    if tokio::time::timeout(TOTAL, diagnose(&system, &target, &mut report))
        .await
        .is_err()
    {
        if report.route == Fact::Passed {
            report.https = Fact::Timeout;
        } else if report.dns == Fact::Passed || target.host.parse::<IpAddr>().is_ok() {
            report.route = Fact::Timeout;
        } else {
            report.dns = Fact::Timeout;
        }
    }
    if !system.unchanged(&initial) {
        report.https = Fact::SessionChanged;
        report.http_status = None;
    }
    report.finished_at_ms = now_ms();
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Fake {
        route: Result<bool, Fact>,
        dns: Result<Vec<IpAddr>, Fact>,
        https: Result<u16, Fact>,
        calls: AtomicUsize,
        change: bool,
    }
    impl Backend for Fake {
        fn lifecycle(&self) -> Snapshot {
            let mut s = Snapshot::unknown(rtrust_control::observations::Mode::Full);
            if self.change && self.calls.load(Ordering::SeqCst) > 0 {
                s.generation = 1;
            }
            s
        }
        fn active(&self) -> bool {
            true
        }
        fn policy(&self, _: IpAddr) -> Decision {
            Decision::unknown(
                Context {
                    source: rtrust_profile::routing::Source::ManagedUnknown,
                    revision: Some("opaque-secret-revision-canary?token=secret".into()),
                },
                Reason::SystemPathUnobserved,
            )
        }
        async fn resolve(&self, _: &Target) -> Result<Vec<IpAddr>, Fact> {
            self.dns.clone()
        }
        async fn route(&self, _: IpAddr) -> Result<bool, Fact> {
            self.route
        }
        async fn https(&self, _: &Target, _: IpAddr) -> Result<u16, Fact> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.https
        }
    }
    fn fake(route: Result<bool, Fact>) -> Fake {
        Fake {
            route,
            dns: Ok(vec!["203.0.113.9".parse().unwrap()]),
            https: Ok(503),
            calls: AtomicUsize::new(0),
            change: false,
        }
    }
    #[tokio::test]
    async fn unresolved_or_outside_route_never_sends_https() {
        for result in [Ok(false), Err(Fact::Unsupported), Err(Fact::Timeout)] {
            let f = fake(result);
            let mut r = Report::new(f.lifecycle());
            diagnose(&f, &Target::parse("service.example").unwrap(), &mut r).await;
            assert_eq!(f.calls.load(Ordering::SeqCst), 0);
            assert_eq!(r.https, Fact::NotChecked);
        }
        let mut f = fake(Ok(true));
        f.dns = Err(Fact::Failed);
        let mut r = Report::new(f.lifecycle());
        diagnose(&f, &Target::parse("service.example").unwrap(), &mut r).await;
        assert_eq!(r.dns, Fact::Failed);
        assert_eq!(f.calls.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn http_errors_are_reachability_not_application_or_internet_health() {
        let f = fake(Ok(true));
        let mut r = Report::new(f.lifecycle());
        diagnose(&f, &Target::parse("secret-host.example").unwrap(), &mut r).await;
        assert_eq!(r.https, Fact::Passed);
        assert_eq!(r.http_status, Some(503));
        assert!(!r.lifecycle.verified());
        let json = r.redacted_json();
        assert!(!json.contains("opaque-secret") && !json.contains("canary"));
        for forbidden in ["secret-host", "203.0.113", "password", "token", "https://"] {
            assert!(!json.contains(forbidden));
        }
    }
    #[tokio::test]
    async fn results_from_a_changed_session_are_rejected() {
        let mut f = fake(Ok(true));
        f.change = true;
        let mut r = Report::new(f.lifecycle());
        diagnose(&f, &Target::parse("service.example").unwrap(), &mut r).await;
        assert_eq!(r.https, Fact::SessionChanged);
        assert_eq!(r.http_status, None);
    }
    #[test]
    fn target_cannot_introduce_credentials_query_or_command_options() {
        for input in [
            "https://a/?token=secret",
            "a:80",
            "a/path",
            "a@b",
            "-q",
            " a",
            "a\n",
            "a..b",
            "a;touch",
            "a%20b",
        ] {
            assert!(Target::parse(input).is_err(), "{input}");
        }
        assert_eq!(
            Target::parse("2001:db8::1").unwrap().https_url(),
            "https://[2001:db8::1]/"
        );
    }
    #[test]
    fn kernel_route_identity_is_exact_and_ambiguous_output_is_rejected() {
        assert_eq!(mac_route(b"interface: utun5254\n"), Ok(true));
        assert_eq!(mac_route(b"interface: utun5255\n"), Ok(false));
        assert_eq!(
            mac_route(b"interface: utun5254\ninterface: en0\n"),
            Err(Fact::Failed)
        );
        assert_eq!(linux_route(br#"[{"dev":"rtrust0"}]"#), Ok(true));
        assert_eq!(linux_route(br#"[{"dev":"eth0"}]"#), Ok(false));
        assert_eq!(
            linux_route(br#"[{"dev":"rtrust0"},{"dev":"eth0"}]"#),
            Err(Fact::Failed)
        );
    }
    #[tokio::test]
    async fn command_output_is_bounded_and_failure_is_redacted() {
        assert_eq!(
            command("/definitely/missing", &[]).await,
            Err(Fact::Unsupported)
        );
        #[cfg(unix)]
        assert_eq!(
            command("/usr/bin/yes", &["sensitive-canary"]).await,
            Err(Fact::Failed)
        );
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[tokio::test]
    async fn bound_https_checks_certificate_and_never_follows_redirect() {
        use std::sync::Arc;
        use tokio::io::AsyncWriteExt;
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let key =
            rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certified.cert.der().clone()], key.into())
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let count = requests.clone();
        let server = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                if let Ok(mut tls) = acceptor.accept(socket).await {
                    let mut bytes = [0; 1024];
                    let n = tls.read(&mut bytes).await.unwrap();
                    assert!(bytes[..n].starts_with(b"HEAD / HTTP/1.1\r\n"));
                    count.fetch_add(1, Ordering::SeqCst);
                    tls.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/secret?token=canary\r\nContent-Length: 999999999\r\nConnection: close\r\n\r\n").await.unwrap();
                }
            }
        });
        #[cfg(target_os = "macos")]
        let device = "lo0";
        #[cfg(target_os = "linux")]
        let device = "lo";
        let target = Target::parse("localhost").unwrap();
        let url = format!("https://localhost:{}/", address.port());
        let untrusted = https_builder(&target, address, device)
            .build()
            .unwrap()
            .head(&url)
            .send()
            .await
            .unwrap_err();
        assert_eq!(classify_http_error(untrusted), Fact::TlsFailed);
        assert_eq!(requests.load(Ordering::SeqCst), 0);
        let response = https_builder(&target, address, device)
            .add_root_certificate(reqwest::Certificate::from_der(certified.cert.der()).unwrap())
            .build()
            .unwrap()
            .head(&url)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 302);
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        drop(response);
        server.abort();
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[tokio::test]
    async fn missing_bound_interface_cannot_fallback_to_another_route() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let target = Target::parse("localhost").unwrap();
        assert!(
            https_builder(&target, address, "rt-no-such-if")
                .build()
                .unwrap()
                .head(format!("https://localhost:{}/", address.port()))
                .send()
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(25), listener.accept())
                .await
                .is_err()
        );
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn cancellation_kills_the_inflight_system_command() {
        let child = tokio::process::Command::new("/bin/sleep")
            .arg("30")
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let pid = child.id().unwrap().to_string();
        let task = tokio::spawn(read_child(child));
        tokio::task::yield_now().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if !tokio::process::Command::new("/bin/kill")
                    .args(["-0", &pid])
                    .stderr(std::process::Stdio::null())
                    .status()
                    .await
                    .unwrap()
                    .success()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("cancelled child must not remain running");
    }
}
