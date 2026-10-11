//! Local TLS protocol fixtures; these do not validate live endpoint enforcement.
use super::*;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Step {
    path: &'static str,
    status: u16,
    body: Value,
    stalled: Option<tokio::sync::oneshot::Sender<()>>,
}
fn step(path: &'static str, body: Value) -> Step {
    Step {
        path,
        status: 200,
        body,
        stalled: None,
    }
}
struct Fixture {
    client: Client,
    observed: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn fixture(steps: Vec<Step>) -> Fixture {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = Client::with_certificate(
        &format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        ),
        Some(cert.cert.pem().as_bytes()),
    )
    .unwrap();
    let observed = Arc::new(Mutex::new(Vec::new()));
    let recorded = observed.clone();
    let task = tokio::spawn(async move {
        for step in steps {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let mut bytes = Zeroizing::new(Vec::new());
            let header_end = loop {
                let mut chunk = [0; 1024];
                let count = tls.read(&mut chunk).await.unwrap();
                assert_ne!(count, 0);
                bytes.extend_from_slice(&chunk[..count]);
                if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                    break end + 4;
                }
                assert!(bytes.len() < 16 * 1024);
            };
            let headers = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
            let request = headers.lines().next().unwrap();
            assert_eq!(request.split_whitespace().nth(1), Some(step.path));
            if step.path != "/portal/v2/enroll" {
                assert!(
                    headers
                        .to_ascii_lowercase()
                        .contains(&format!("authorization: bearer {}", "x".repeat(43)))
                );
            }
            let length: usize = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
                .unwrap_or(0);
            while bytes.len() < header_end + length {
                let mut chunk = [0; 1024];
                let count = tls.read(&mut chunk).await.unwrap();
                assert_ne!(count, 0);
                bytes.extend_from_slice(&chunk[..count]);
            }
            if step.path.ends_with("/export") {
                let body: Value =
                    serde_json::from_slice(&bytes[header_end..header_end + length]).unwrap();
                assert_eq!(body["revision"], "1");
                assert_eq!(body["include_secrets"], true);
            }
            recorded.lock().unwrap().push(step.path.into());
            if let Some(stalled) = step.stalled {
                stalled
                    .send(())
                    .expect("timeout test must await stalled export");
                // Keep this response blocked until Fixture::drop aborts the server.
                std::future::pending::<()>().await;
            }
            let body = step.body.to_string();
            let response = format!(
                "HTTP/1.1 {} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                step.status,
                body.len(),
                body
            );
            // A canceled client may close the socket before a delayed response.
            let _ = tls.write_all(response.as_bytes()).await;
            let _ = tls.shutdown().await;
        }
    });
    Fixture {
        client,
        observed,
        task,
    }
}
fn profile_list(revision: &str) -> Value {
    json!({"profiles":[{"id":"managed-1","revision":revision,"summary":{"name":"fixture","hostname":"vpn.example"},"origin":"portal_managed"}]})
}
fn snapshot_steps() -> Vec<Step> {
    let profile = Profile::import("hostname='vpn.example'\naddresses=['192.0.2.10:443']\nusername='device'\npassword='FIXTURE-SECRET'\n").unwrap();
    vec![
        step(
            "/portal/v2/capabilities",
            json!({"version":2,"formats":["profile_json"],"enrollment":["one_time_code"],"max_profile_bytes":MAX_INPUT,"routing":1}),
        ),
        step("/portal/v2/profiles", profile_list("1")),
        step("/portal/v2/routing", json!({"policy":null})),
        step(
            "/portal/v2/profiles/managed-1/export",
            json!({"content":profile.export(Format::Json).unwrap().content}),
        ),
        step("/portal/v2/profiles", profile_list("1")),
        step("/portal/v2/routing", json!({"policy":null})),
    ]
}
fn authorized(client: &Client) -> Client {
    let mut client = client.clone();
    client.token = Zeroizing::new("x".repeat(43));
    client
}
#[tokio::test]
async fn enrollment_then_complete_snapshot_uses_origin_bound_token() {
    let mut steps = snapshot_steps();
    steps.insert(
        0,
        step(
            "/portal/v2/enroll",
            json!({"token":"x".repeat(43),"device_id":7,"expires_in":3600}),
        ),
    );
    let fixture = fixture(steps).await;
    let client = fixture
        .client
        .clone()
        .enroll(&"a".repeat(32), "Fixture")
        .await
        .unwrap();
    assert_eq!(client.device_id(), Some(7));
    assert!(client.expires_at().is_some());
    let snapshot = client.snapshot().await.unwrap();
    assert_eq!(snapshot.profiles.len(), 1);
    assert_eq!(
        snapshot.profiles[0].1.endpoint.password.expose(),
        "FIXTURE-SECRET"
    );
    assert_eq!(snapshot.routing, RoutingState::Available(None));
    assert_eq!(fixture.observed.lock().unwrap().len(), 7);
    assert!(!format!("{client:?}").contains(&"x".repeat(43)));
}
#[tokio::test]
async fn rotation_during_snapshot_rejects_the_entire_download() {
    let mut steps = snapshot_steps();
    steps[4].body = profile_list("2");
    let fixture = fixture(steps).await;
    let error = authorized(&fixture.client).snapshot().await.err().unwrap();
    assert!(error.contains("изменились"));
    assert!(!error.contains("FIXTURE-SECRET"));
    assert_eq!(fixture.observed.lock().unwrap().len(), 5);
}
#[tokio::test]
async fn route_change_during_snapshot_rejects_the_entire_download() {
    let mut steps = snapshot_steps();
    steps[5].body = json!({"policy":{"group":"Office","revision":"2","include":["0.0.0.0/0"],"exclude":[],"exclude_lan":true}});
    let fixture = fixture(steps).await;
    assert!(
        authorized(&fixture.client)
            .snapshot()
            .await
            .err()
            .unwrap()
            .contains("изменились")
    );
    assert_eq!(fixture.observed.lock().unwrap().len(), 6);
}
#[tokio::test]
async fn access_denied_during_export_does_not_return_partial_profiles_or_server_error() {
    let mut steps = snapshot_steps();
    steps[3].status = 401;
    steps[3].body = json!({"secret":"SERVER-ERROR-SECRET"});
    let fixture = fixture(steps).await;
    let error = authorized(&fixture.client).snapshot().await.err().unwrap();
    assert!(error.contains("истёк или доступ устройства отозван"));
    assert!(!error.contains("SERVER-ERROR-SECRET"));
    assert_eq!(fixture.observed.lock().unwrap().len(), 4);
}
#[tokio::test]
async fn caller_timeout_cancels_snapshot_before_any_batch_is_returned() {
    let mut steps = snapshot_steps();
    let (stalled, reached_export) = tokio::sync::oneshot::channel();
    steps[3].stalled = Some(stalled);
    let fixture = fixture(steps).await;
    let client = authorized(&fixture.client);
    let snapshot = client.snapshot();
    tokio::pin!(snapshot);
    // Poll the real snapshot through TLS setup and earlier API requests. The
    // short cancellation deadline starts only once the fixture blocks export.
    tokio::select! {
        _ = &mut snapshot => panic!("snapshot completed before the fixture stalled export"),
        reached = reached_export => reached.expect("fixture must receive the export request"),
    }
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(250), &mut snapshot)
            .await
            .is_err()
    );
    assert_eq!(fixture.observed.lock().unwrap().len(), 4);
}
