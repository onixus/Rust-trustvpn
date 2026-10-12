//! Origin-bound profile exchange. Secrets never appear in errors or Debug output.
use ipnet::Ipv4Net;
use reqwest::{Client as Http, Method, StatusCode, Url};
use rtrust_profile::{Format, MAX_INPUT, Profile};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use zeroize::Zeroizing;
const LIMIT: usize = 8 * MAX_INPUT;

/// A QR contains a short-lived enrollment code, never persistent credentials.
/// The selected HTTPS origin is an independent trust input; QR cannot replace it.
fn enrollment_code(
    input: &str,
    expected_origin: &Url,
    unix_seconds: u64,
) -> Result<Zeroizing<String>, String> {
    if !input.trim_start().starts_with('{') {
        return Ok(Zeroizing::new(input.trim().to_owned()));
    }
    #[derive(Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
    #[serde(deny_unknown_fields)]
    struct Invitation {
        kind: String,
        version: u64,
        origin: String,
        code: String,
        expires_at: u64,
    }
    let invalid = || "Некорректное, просроченное или чужое приглашение панели".to_string();
    if input.len() > 4096 {
        return Err(invalid());
    }
    let mut invitation: Invitation = serde_json::from_str(input).map_err(|_| invalid())?;
    let origin = Client::new(&invitation.origin)
        .map_err(|_| invalid())?
        .origin;
    if invitation.kind != "rtrust_enrollment"
        || invitation.version != 1
        || origin != *expected_origin
        || invitation.expires_at <= unix_seconds
        || invitation.expires_at - unix_seconds > 300
    {
        return Err(invalid());
    }
    Ok(Zeroizing::new(std::mem::take(&mut invitation.code)))
}

#[cfg(test)]
mod invitation_tests {
    use super::*;
    #[test]
    fn qr_cannot_change_origin_extend_expiry_or_add_credentials() {
        let expected = Url::parse("https://panel.example/").unwrap();
        let code = "synthetic-one-time-code-123456";
        let good = json!({"kind":"rtrust_enrollment","version":1,"origin":"https://panel.example","code":code,"expires_at":180});
        assert_eq!(
            enrollment_code(&good.to_string(), &expected, 100)
                .unwrap()
                .as_str(),
            code
        );
        for (key, value) in [
            ("origin", json!("https://foreign.example")),
            ("origin", json!("https://panel.example/path")),
            ("origin", json!("http://panel.example")),
            ("expires_at", json!(100)),
            ("expires_at", json!(401)),
            ("version", json!(2)),
            ("password", json!("synthetic-secret-canary")),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            let error = enrollment_code(&bad.to_string(), &expected, 100).unwrap_err();
            assert!(!error.contains(code));
            assert!(!error.contains("synthetic-secret-canary"));
        }
    }
    #[tokio::test]
    async fn expired_qr_is_rejected_before_contacting_portal() {
        let client = Client::new("https://127.0.0.1:1").unwrap();
        let expired = json!({"kind":"rtrust_enrollment","version":1,"origin":"https://127.0.0.1:1","code":"synthetic-one-time-code-123456","expires_at":1});
        assert!(
            client
                .enroll(&expired.to_string(), "test")
                .await
                .unwrap_err()
                .contains("приглашение")
        );
    }
}
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct Summary {
    pub name: String,
    pub hostname: String,
}
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct RemoteProfile {
    pub id: String,
    pub revision: String,
    pub summary: Summary,
    pub origin: String,
}
#[derive(Clone, Deserialize)]
pub struct Preview {
    pub preview_id: String,
    pub summary: Summary,
}
/// Server-assigned split-tunnel policy for the desktop TUN mode.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingPolicy {
    pub group: String,
    /// Opaque; changes whenever the group policy or the device's group changes.
    pub revision: String,
    pub include: Vec<Ipv4Net>,
    pub exclude: Vec<Ipv4Net>,
    pub exclude_lan: bool,
}
/// An older API is distinct from an explicit removal of the device's group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoutingState {
    Unsupported,
    Available(Option<RoutingPolicy>),
}
#[derive(Deserialize)]
struct Routing {
    // Explicit deserializer: a missing `policy` key is an error, `null` is "no group".
    #[serde(deserialize_with = "Option::deserialize")]
    policy: Option<RoutingPolicy>,
}
fn routing_policy(routing: Routing) -> Result<Option<RoutingPolicy>, String> {
    let Some(policy) = routing.policy else {
        return Ok(None);
    };
    let invalid = || "Некорректная политика маршрутов панели".to_string();
    if !(1..=80).contains(&policy.group.chars().count())
        || policy.group.chars().any(char::is_control)
        || !(1..=64).contains(&policy.revision.len())
        || !policy.revision.bytes().all(|b| b.is_ascii_graphic())
        || !(1..=16).contains(&policy.include.len())
        || policy.exclude.len() > 64
        || policy
            .include
            .iter()
            .chain(&policy.exclude)
            .any(|net| net.trunc() != *net)
    {
        return Err(invalid());
    }
    Ok(Some(policy))
}
#[derive(Clone)]
pub struct Client {
    http: Http,
    origin: Url,
    token: Zeroizing<String>,
    expires_at: Option<u64>,
    device_id: Option<u64>,
}
impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PortalClient([REDACTED])")
    }
}
#[derive(Deserialize)]
struct Capabilities {
    version: u64,
    formats: Vec<String>,
    enrollment: Vec<String>,
    max_profile_bytes: u64,
    #[serde(default)]
    routing: Option<u64>,
    #[serde(default)]
    snapshot: Option<u64>,
    #[serde(default)]
    offline_freshness: Option<u64>,
}
impl Capabilities {
    fn validate(&self) -> Result<(), String> {
        if self.version != 2
            || !self.formats.iter().any(|v| v == "profile_json")
            || !self.enrollment.iter().any(|v| v == "one_time_code")
            || self.max_profile_bytes == 0
            || self.routing.is_some_and(|v| v != 1)
            || self.snapshot.is_some_and(|v| v != 1)
        {
            return Err("Панель не поддерживает совместимый контракт профилей v2".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceAccess {
    pub schema: u32,
    pub session_policy: String,
    pub profiles: Vec<DeviceCredential>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceCredential {
    pub id: String,
    pub generation: u64,
    pub desired: String,
    pub state: String,
    pub legacy_shared_access: String,
    pub receipt: Option<CredentialReceipt>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialReceipt {
    pub checked_at: u64,
    pub generation: u64,
    pub verifier_sha256: String,
    pub endpoint_generation: u64,
    pub checks: Vec<CredentialCheck>,
    pub scope: String,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialCheck {
    pub protocol: String,
    pub outcome: String,
    pub elapsed_ms: Option<u64>,
}
impl DeviceAccess {
    fn validate(&self) -> Result<(), String> {
        let invalid = || "Некорректное состояние управляемого доступа".to_owned();
        if self.schema != 1
            || self.session_policy != "restart_all_endpoint_sessions"
            || self.profiles.len() > 200
        {
            return Err(invalid());
        }
        let mut ids = std::collections::HashSet::new();
        for profile in &self.profiles {
            identifier(&profile.id)?;
            if !ids.insert(&profile.id)
                || profile.generation == 0
                || !matches!(profile.desired.as_str(), "active" | "revoked")
                || !matches!(
                    profile.state.as_str(),
                    "requested" | "pending" | "applied" | "failed"
                )
                || !matches!(
                    profile.legacy_shared_access.as_str(),
                    "unmanaged" | "not_issued_by_this_flow"
                )
            {
                return Err(invalid());
            }
            if let Some(receipt) = &profile.receipt {
                if receipt.generation != profile.generation
                    || receipt.checked_at == 0
                    || receipt.verifier_sha256.len() != 64
                    || !receipt
                        .verifier_sha256
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit())
                    || receipt.checks.len() > 4
                    || receipt.scope != "managed_credentials_only_legacy_shared_access_unmanaged"
                {
                    return Err(invalid());
                }
                for check in &receipt.checks {
                    if !matches!(check.protocol.as_str(), "http2" | "http3")
                        || !matches!(
                            check.outcome.as_str(),
                            "authenticated" | "rejected" | "unavailable"
                        )
                    {
                        return Err(invalid());
                    }
                }
            }
            if profile.state == "applied" {
                let receipt = profile.receipt.as_ref().ok_or_else(invalid)?;
                for protocol in ["http2", "http3"] {
                    let checks: Vec<_> = receipt
                        .checks
                        .iter()
                        .filter(|c| c.protocol == protocol)
                        .collect();
                    let expected = if profile.desired == "revoked" {
                        "rejected"
                    } else {
                        "authenticated"
                    };
                    let exact = if profile.desired == "revoked" {
                        checks.len() == 1 && checks[0].outcome == "rejected"
                    } else {
                        (checks.len() == 1 && checks[0].outcome == "authenticated")
                            || (checks.len() == 2
                                && checks
                                    .iter()
                                    .filter(|c| c.outcome == "authenticated")
                                    .count()
                                    == 1
                                && checks.iter().filter(|c| c.outcome == "rejected").count() == 1)
                    };
                    if !exact
                        || checks.is_empty()
                        || checks.len() > 2
                        || !checks.iter().any(|c| c.outcome == expected)
                        || checks.iter().any(|c| c.outcome == "unavailable")
                        || (profile.desired == "revoked"
                            && checks.iter().any(|c| c.outcome != "rejected"))
                    {
                        return Err(invalid());
                    }
                }
            }
        }
        Ok(())
    }
}
/// Downloaded secrets are deliberately excluded from Debug and serialization.
pub struct Snapshot {
    pub profiles: Vec<(RemoteProfile, Profile)>,
    pub routing: RoutingState,
    pub freshness: Option<rtrust_control::freshness::Lease>,
}
/// Error bodies are read only to classify a 409; they are never shown or logged.
const CONFLICT_BODY_LIMIT: usize = 512;
const TOO_MANY_PROFILES: &str = "На портале назначено больше 64 профилей для этого устройства. \
Синхронизация остановлена, локальные профили сохранены. Снимите лишние профили с устройства на портале.";
const PROFILE_LIMIT_REACHED: &str = "Достигнут лимит 64 профиля на устройство";
const PROFILE_CHANGED: &str = "Профиль изменился. Обновите список и повторите просмотр.";

/// Maps the server's exact `detail` of a 409 to a user message. Anything else,
/// including oversized or malformed bodies, keeps the revision-conflict text.
fn conflict_message(body: &[u8]) -> &'static str {
    #[derive(Deserialize)]
    struct Detail {
        detail: String,
    }
    match serde_json::from_slice::<Detail>(body).map(|d| d.detail) {
        Ok(d) if d == "Too many profiles for client sync" => TOO_MANY_PROFILES,
        Ok(d) if d == "Device profile limit reached (64)" => PROFILE_LIMIT_REACHED,
        _ => PROFILE_CHANGED,
    }
}

/// Reads at most `limit` bytes; an oversized body yields an empty buffer.
async fn bounded_body(response: &mut reqwest::Response, limit: usize) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::new());
    if response.content_length().is_some_and(|n| n > limit as u64) {
        return bytes;
    }
    while let Ok(Some(chunk)) = response.chunk().await {
        if bytes.len() + chunk.len() > limit {
            bytes.clear();
            break;
        }
        bytes.extend_from_slice(&chunk);
    }
    bytes
}

fn same_revisions(before: &[RemoteProfile], after: &[RemoteProfile]) -> bool {
    before.len() == after.len()
        && before
            .iter()
            .all(|item| after.iter().any(|other| other == item))
}
fn now() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "Системное время недоступно".into())
}
fn valid_token(token: &str) -> bool {
    (40..=128).contains(&token.len())
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn token_deadline(requested_at: u64, expires_in: Option<u64>) -> Result<Option<u64>, String> {
    expires_in
        .map(|ttl| {
            if ttl == 0 {
                return Err("Некорректный срок токена панели".into());
            }
            requested_at
                .checked_add(ttl)
                .ok_or_else(|| "Некорректный срок токена панели".into())
        })
        .transpose()
}
fn origin(value: &str) -> Result<Url, String> {
    let url = Url::parse(value.trim()).map_err(|_| "Некорректный адрес панели")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err("Нужен HTTPS-адрес панели без пути, логина и параметров".into());
    }
    Ok(url)
}
fn identifier(value: &str) -> Result<&str, String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err("Некорректный идентификатор профиля".into());
    }
    Ok(value)
}
impl Client {
    /// Only portal API expiry is known. Endpoint credentials have independent lifetimes.
    pub fn access_expired(&self, unix_seconds: u64) -> bool {
        self.expires_at
            .is_some_and(|deadline| unix_seconds >= deadline)
    }
    pub fn expires_at(&self) -> Option<u64> {
        self.expires_at
    }
    pub fn device_id(&self) -> Option<u64> {
        self.device_id
    }
    pub fn address(&self) -> &str {
        self.origin.as_str()
    }
    pub fn remember(&self) -> Result<(), String> {
        let bytes = Zeroizing::new(
            serde_json::to_vec(&json!({"origin":self.origin.as_str(),"token":self.token.as_str(),"expires_at":self.expires_at,"device_id":self.device_id}))
                .map_err(|_| "Ошибка сохранения привязки")?,
        );
        keyring::Entry::new("org.rtrusttunnel.desktop", "portal-device-v2")
            .and_then(|e| e.set_secret(&bytes))
            .map_err(|_| "Не удалось сохранить привязку в системном хранилище паролей".into())
    }
    pub fn restore() -> Result<Self, String> {
        let bytes = Zeroizing::new(
            keyring::Entry::new("org.rtrusttunnel.desktop", "portal-device-v2")
                .and_then(|e| e.get_secret())
                .map_err(|_| "Сохранённая привязка недоступна. Введите новый код панели.")?,
        );
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Saved {
            origin: String,
            token: String,
            #[serde(default)]
            expires_at: Option<u64>,
            #[serde(default)]
            device_id: Option<u64>,
        }
        let saved: Saved =
            serde_json::from_slice(&bytes).map_err(|_| "Повреждена сохранённая привязка")?;
        let token = Zeroizing::new(saved.token);
        let mut client = Self::new(&saved.origin)?;
        if !valid_token(&token) || saved.device_id == Some(0) {
            return Err("Повреждена сохранённая привязка".into());
        }
        client.token = token;
        client.expires_at = saved.expires_at;
        client.device_id = saved.device_id;
        Ok(client)
    }
    pub fn forget() -> Result<(), String> {
        match keyring::Entry::new("org.rtrusttunnel.desktop", "portal-device-v2")
            .and_then(|e| e.delete_credential())
        {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err("Не удалось удалить сохранённую привязку".into()),
        }
    }

    pub fn new(address: &str) -> Result<Self, String> {
        Self::with_certificate(address, None)
    }
    /// Optional additional CA is used by isolated TLS integration tests.
    pub fn with_certificate(address: &str, certificate: Option<&[u8]>) -> Result<Self, String> {
        let mut builder = Http::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(25));
        if let Some(pem) = certificate {
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(pem)
                    .map_err(|_| "Некорректный сертификат панели")?,
            );
        }
        Ok(Self {
            http: builder.build().map_err(|_| "HTTPS недоступен")?,
            origin: origin(address)?,
            token: Zeroizing::new(String::new()),
            expires_at: None,
            device_id: None,
        })
    }
    async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<T, String> {
        self.exchange(method, path, body, false)
            .await?
            .ok_or_else(|| "Панель отклонила запрос.".into())
    }
    /// `missing_ok` maps 404 to `None` for endpoints older servers do not have.
    async fn exchange<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        missing_ok: bool,
    ) -> Result<Option<T>, String> {
        if !self.token.is_empty() && self.access_expired(now()?) {
            return Err("Срок токена панели истёк. Привяжите устройство заново.".into());
        }
        let url = self
            .origin
            .join(&format!("portal/v2/{path}"))
            .map_err(|_| "Некорректный API адрес")?;
        let mut request = self.http.request(method, url);
        if !self.token.is_empty() {
            request = request.bearer_auth(self.token.as_str());
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let mut response = request
            .send()
            .await
            .map_err(|_| "Панель недоступна или сертификат не прошёл проверку")?;
        if missing_ok && response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if response.status() == StatusCode::CONFLICT {
            return Err(
                conflict_message(&bounded_body(&mut response, CONFLICT_BODY_LIMIT).await).into(),
            );
        }
        if !response.status().is_success() {
            return Err(match response.status().as_u16() {
                401 => "Код истёк или доступ устройства отозван. Привяжите устройство заново.",
                403 => "Недостаточно прав на эту операцию.",
                404 => "Профиль недоступен. Проверьте выданные устройству права.",
                410 => "Предварительный просмотр истёк. Проверьте профиль заново.",
                429 => "Слишком много запросов. Повторите через минуту.",
                _ => "Панель отклонила запрос.",
            }
            .into());
        }
        if response.content_length().is_some_and(|n| n > LIMIT as u64) {
            return Err("Ответ панели слишком большой".into());
        }
        let mut bytes = Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await.map_err(|_| "Ответ панели прерван")?
        {
            if bytes.len() + chunk.len() > LIMIT {
                return Err("Ответ панели слишком большой".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| "Некорректный ответ панели".into())
    }
    /// Explicit renewal while this device token is still valid. An expired or
    /// revoked registration must enroll again; endpoint access is independent.
    pub async fn renew_access(mut self) -> Result<Self, String> {
        if self.token.is_empty() {
            return Err("Сначала привяжите устройство к панели".into());
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Renewed {
            expires_in: u64,
            scope: String,
        }
        let requested_at = now()?;
        let result: Renewed = self
            .request(Method::POST, "token/renew", Some(json!({"consent":true})))
            .await?;
        if result.expires_in == 0
            || result.expires_in > 30 * 86400
            || result.scope != "portal_access_only"
        {
            return Err("Некорректный срок продления доступа панели".into());
        }
        self.expires_at = token_deadline(requested_at, Some(result.expires_in))?;
        if self.access_expired(now()?) {
            return Err("Срок продления доступа панели истёк".into());
        }
        Ok(self)
    }
    pub async fn enroll(mut self, code: &str, name: &str) -> Result<Self, String> {
        let code = enrollment_code(code, &self.origin, now()?)?;
        if !(20..=128).contains(&code.len())
            || !code
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            || name.trim().is_empty()
            || name.len() > 80
            || name.chars().any(char::is_control)
        {
            return Err("Укажите код панели и имя устройства (до 80 байт)".into());
        }
        #[derive(Deserialize)]
        struct Enrolled {
            token: String,
            #[serde(default)]
            device_id: Option<u64>,
            #[serde(default)]
            expires_in: Option<u64>,
        }
        let requested_at = now()?;
        let platform = if cfg!(target_os = "macos") {
            "macos"
        } else if cfg!(target_os = "android") {
            "android"
        } else if cfg!(target_os = "ios") {
            "ios"
        } else if cfg!(target_os = "windows") {
            "windows"
        } else {
            "linux"
        };
        let value: Enrolled = self
            .request(
                Method::POST,
                "enroll",
                Some(json!({"code":code.as_str(),"name":name,"platform":platform})),
            )
            .await?;
        let token = Zeroizing::new(value.token);
        if !valid_token(&token) || value.device_id == Some(0) {
            return Err("Некорректный токен панели".into());
        }
        self.expires_at = token_deadline(requested_at, value.expires_in)?;
        if self
            .expires_at
            .is_some_and(|deadline| deadline <= now().unwrap_or(u64::MAX))
        {
            return Err("Срок токена панели истёк. Привяжите устройство заново.".into());
        }
        self.device_id = value.device_id;
        self.token = token;
        Ok(self)
    }
    /// Control-plane receipt only, dated by the server. It does not prove that
    /// the current system VPN or arbitrary destinations are available.
    pub async fn device_access(&self) -> Result<DeviceAccess, String> {
        let device = self
            .device_id
            .ok_or("Панель не сообщила идентификатор устройства")?;
        let result: Option<DeviceAccess> = self
            .exchange(
                Method::GET,
                &format!("devices/{device}/credentials"),
                None,
                true,
            )
            .await?;
        let access = result.ok_or("Панель не поддерживает состояние managed credentials")?;
        access.validate()?;
        Ok(access)
    }
    pub async fn list(&self) -> Result<Vec<RemoteProfile>, String> {
        #[derive(Deserialize)]
        struct Listed {
            profiles: Vec<RemoteProfile>,
        }
        let result: Listed = self.request(Method::GET, "profiles", None).await?;
        if result.profiles.len() > 200 {
            return Err("Слишком много профилей".into());
        }
        let mut ids = std::collections::HashSet::new();
        for p in &result.profiles {
            if !ids.insert(&p.id) {
                return Err("Повторяющийся идентификатор профиля".into());
            }
            identifier(&p.id)?;
            if p.revision.is_empty()
                || p.revision.len() > 256
                || !p.revision.bytes().all(|b| b.is_ascii_graphic())
                || p.origin.is_empty()
                || p.origin.len() > 80
                || p.origin.chars().any(char::is_control)
                || p.summary.name.len() > 1024
                || p.summary.hostname.len() > 1024
                || p.summary.name.chars().any(char::is_control)
                || p.summary.hostname.chars().any(char::is_control)
            {
                return Err("Некорректная версия профиля".into());
            }
        }
        Ok(result.profiles)
    }
    /// Validate the existing v2 profile contract. This is not an endpoint-revocation capability.
    pub async fn check_capabilities(&self) -> Result<(), String> {
        let capabilities: Capabilities = self.request(Method::GET, "capabilities", None).await?;
        capabilities.validate()
    }
    /// Fetch all data before publishing any local update. Recheck source revisions;
    /// v2 has no server transaction revision, so this detects observed changes only.
    pub async fn snapshot(&self) -> Result<Snapshot, String> {
        let capabilities: Capabilities = self.request(Method::GET, "capabilities", None).await?;
        capabilities.validate()?;
        if capabilities.snapshot == Some(1) {
            if capabilities.offline_freshness.is_some_and(|v| v != 1) {
                return Err("Unsupported freshness contract".into());
            }
            return self
                .atomic_snapshot(capabilities.offline_freshness == Some(1))
                .await;
        }
        let profiles = self.list().await?;
        let routing = self.routing_state().await?;
        let mut downloaded = Vec::with_capacity(profiles.len());
        let mut bytes = 0usize;
        for meta in &profiles {
            let profile = self.download(meta).await?;
            // Export zeroizes its content on drop.
            bytes += profile
                .export(Format::Json)
                .map_err(|_| "Получен недопустимый профиль")?
                .content
                .len();
            if bytes > 4 * MAX_INPUT {
                return Err("Партия профилей слишком большая".into());
            }
            downloaded.push((meta.clone(), profile));
        }
        if !same_revisions(&profiles, &self.list().await?)
            || routing != self.routing_state().await?
        {
            return Err("Данные панели изменились. Повторите синхронизацию.".into());
        }
        Ok(Snapshot {
            profiles: downloaded,
            routing,
            freshness: None,
        })
    }
    async fn atomic_snapshot(&self, freshness_supported: bool) -> Result<Snapshot, String> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Freshness {
            version: u32,
            max_age_seconds: u64,
            token_remaining_seconds: u64,
        }
        #[derive(Deserialize, zeroize::ZeroizeOnDrop)]
        #[serde(deny_unknown_fields)]
        struct Item {
            #[zeroize(skip)]
            metadata: RemoteProfile,
            content: String,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Batch {
            version: u32,
            revision: String,
            profiles: Vec<Item>,
            routing: Routing,
            #[serde(default)]
            freshness: Option<Freshness>,
        }
        let requested_at = rtrust_control::freshness::now();
        let mut consent = json!({"include_secrets":true});
        if freshness_supported {
            consent["freshness_version"] = json!(1);
        }
        let batch: Batch = self
            .request(Method::POST, "snapshot", Some(consent))
            .await?;
        if batch.version != 1
            || batch.revision.len() != 64
            || !batch.revision.bytes().all(|b| b.is_ascii_hexdigit())
            || batch.profiles.len() > 200
        {
            return Err("Некорректная атомарная партия панели".into());
        }
        let routing = RoutingState::Available(routing_policy(batch.routing)?);
        let freshness = match batch.freshness {
            Some(value)
                if freshness_supported
                    && value.version == 1
                    && (60..=86400).contains(&value.max_age_seconds)
                    && (1..=30 * 86400).contains(&value.token_remaining_seconds) =>
            {
                Some(rtrust_control::freshness::Lease {
                    issued_at_ms: requested_at,
                    expires_at_ms: requested_at
                        .checked_add(
                            value.max_age_seconds.min(value.token_remaining_seconds) * 1000,
                        )
                        .ok_or("Invalid freshness lease")?,
                })
            }
            None if !freshness_supported => None,
            _ => return Err("Invalid or missing freshness lease".into()),
        };
        let mut profiles = Vec::with_capacity(batch.profiles.len());
        let mut total = 0usize;
        let mut ids = std::collections::HashSet::new();
        for mut item in batch.profiles {
            let content = Zeroizing::new(std::mem::take(&mut item.content));
            total = total
                .checked_add(content.len())
                .ok_or("Партия профилей слишком большая")?;
            if content.len() > MAX_INPUT
                || total > 4 * MAX_INPUT
                || !ids.insert(item.metadata.id.clone())
            {
                return Err("Партия профилей слишком большая или неоднозначная".into());
            }
            identifier(&item.metadata.id)?;
            if item.metadata.revision.is_empty()
                || item.metadata.revision.len() > 256
                || !item.metadata.revision.bytes().all(|b| b.is_ascii_graphic())
                || item.metadata.origin.is_empty()
                || item.metadata.origin.len() > 80
                || item.metadata.origin.chars().any(char::is_control)
            {
                return Err("Некорректная версия профиля панели".into());
            }
            let profile = Profile::import(&content).map_err(|_| "Получен недопустимый профиль")?;
            profiles.push((item.metadata.clone(), profile));
        }
        if let Some(lease) = &freshness {
            lease.validate_at(rtrust_control::freshness::now())?;
        }
        Ok(Snapshot {
            profiles,
            routing,
            freshness,
        })
    }
    pub async fn download(&self, profile: &RemoteProfile) -> Result<Profile, String> {
        #[derive(Deserialize)]
        struct Export {
            content: String,
        }
        let result: Export = self.request(Method::POST, &format!("profiles/{}/export", identifier(&profile.id)?), Some(json!({"format":"profile_json","revision":profile.revision,"include_secrets":true}))).await?;
        Profile::import(&Zeroizing::new(result.content))
            .map_err(|_| "Получен недопустимый профиль".into())
    }
    pub async fn preview_upload(&self, profile: &Profile) -> Result<Preview, String> {
        let export = profile
            .export(Format::Json)
            .map_err(|_| "Невозможно экспортировать профиль")?;
        self.request(
            Method::POST,
            "profile-imports/preview",
            Some(json!({"content":export.content,"intent":"external_stored"})),
        )
        .await
    }
    pub async fn replace(&self, preview: &Preview, target: &RemoteProfile) -> Result<(), String> {
        if target.origin != "external_stored" || target.id.starts_with("managed-") {
            return Err("Управляемый сервером профиль нельзя заменить".into());
        }
        let _: Value=self.request(Method::POST,
            &format!("profile-imports/{}/commit",identifier(&preview.preview_id)?),
            Some(json!({"action":"replace","target_id":identifier(&target.id)?,"base_revision":target.revision,"consent":true}))).await?;
        Ok(())
    }
    /// Routing policy of this device's group; `None` without a group or on servers without the endpoint.
    pub async fn routing(&self) -> Result<Option<RoutingPolicy>, String> {
        match self.routing_state().await? {
            RoutingState::Available(policy) => Ok(policy),
            RoutingState::Unsupported => Ok(None),
        }
    }
    pub async fn routing_state(&self) -> Result<RoutingState, String> {
        match self.exchange(Method::GET, "routing", None, true).await? {
            Some(routing) => routing_policy(routing).map(RoutingState::Available),
            None => Ok(RoutingState::Unsupported),
        }
    }
    pub async fn commit(&self, preview: &Preview) -> Result<(), String> {
        let _: Value = self
            .request(
                Method::POST,
                &format!(
                    "profile-imports/{}/commit",
                    identifier(&preview.preview_id)?
                ),
                Some(json!({"action":"create","consent":true})),
            )
            .await?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn conflict_detail_selects_limit_messages_and_falls_back() {
        assert_eq!(
            conflict_message(br#"{"detail":"Too many profiles for client sync"}"#),
            TOO_MANY_PROFILES
        );
        assert_eq!(
            conflict_message(br#"{"detail":"Device profile limit reached (64)"}"#),
            PROFILE_LIMIT_REACHED
        );
        for body in [
            &br#"{"detail":"Profile revision conflict"}"#[..],
            br#"{"detail":"too many profiles for client sync"}"#,
            br#"{"detail":["Too many profiles for client sync"]}"#,
            br#"{"error":"Too many profiles for client sync"}"#,
            b"Too many profiles for client sync",
            b"",
        ] {
            assert_eq!(conflict_message(body), PROFILE_CHANGED);
        }
    }
    #[test]
    fn expiry_is_conservative_and_legacy_expiry_stays_unknown() {
        assert_eq!(token_deadline(100, Some(30)).unwrap(), Some(130));
        assert_eq!(token_deadline(100, None).unwrap(), None);
        assert!(token_deadline(100, Some(0)).is_err());
        assert!(token_deadline(u64::MAX, Some(1)).is_err());
        let mut client = Client::new("https://example.com").unwrap();
        assert!(!client.access_expired(u64::MAX));
        client.expires_at = Some(130);
        assert!(!client.access_expired(129));
        assert!(client.access_expired(130));
        assert!(client.access_expired(131));
    }
    #[tokio::test]
    async fn expired_token_never_contacts_the_portal() {
        let mut client = Client::new("https://127.0.0.1:1").unwrap();
        client.token = Zeroizing::new("x".repeat(43));
        client.expires_at = Some(1);
        assert_eq!(
            client.list().await.err().unwrap(),
            "Срок токена панели истёк. Привяжите устройство заново."
        );
        assert_eq!(format!("{client:?}"), "PortalClient([REDACTED])");
    }
    #[test]
    fn token_characters_are_validated_on_restore_too() {
        assert!(valid_token(&"x".repeat(43)));
        assert!(!valid_token(&format!("{}\n", "x".repeat(43))));
        assert!(!valid_token(&"x".repeat(129)));
    }
    #[test]
    fn snapshot_recheck_detects_rotation_removal_and_origin_change() {
        let profile = RemoteProfile {
            id: "managed-1".into(),
            revision: "1".into(),
            summary: Summary {
                name: "Office".into(),
                hostname: "vpn.example".into(),
            },
            origin: "portal_managed".into(),
        };
        let mut changed = profile.clone();
        assert!(same_revisions(
            std::slice::from_ref(&profile),
            std::slice::from_ref(&changed)
        ));
        changed.revision = "2".into();
        assert!(!same_revisions(std::slice::from_ref(&profile), &[changed]));
        assert!(!same_revisions(std::slice::from_ref(&profile), &[]));
        changed = profile.clone();
        changed.origin = "external_stored".into();
        assert!(!same_revisions(&[profile], &[changed]));
    }
    #[test]
    fn capabilities_fail_closed_for_unsupported_contracts() {
        let baseline = json!({"version":2,"formats":["profile_json"],"enrollment":["one_time_code"],"max_profile_bytes":MAX_INPUT,"routing":1,"future":true});
        assert!(
            serde_json::from_value::<Capabilities>(baseline.clone())
                .unwrap()
                .validate()
                .is_ok()
        );
        for (field, value) in [
            ("version", json!(3)),
            ("formats", json!([])),
            ("enrollment", json!([])),
            ("max_profile_bytes", json!(0)),
            ("routing", json!(2)),
        ] {
            let mut bad = baseline.clone();
            bad[field] = value;
            assert!(
                serde_json::from_value::<Capabilities>(bad)
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
    }
    #[test]
    fn rejects_credential_or_redirect_origins() {
        for url in [
            "http://localhost",
            "https://name:secret@example.com",
            "https://example.com/path",
            "https://example.com/?token=secret",
            "https://example.com/#x",
        ] {
            assert!(origin(url).is_err());
        }
        assert!(origin("https://example.com:8443/").is_ok());
    }
    #[test]
    fn path_segments_cannot_escape_api() {
        for id in ["../enroll", "//evil.invalid", "a?token=x", "a%2fb", ""] {
            assert!(identifier(id).is_err());
        }
        assert!(identifier("managed-1").is_ok());
    }
    fn parse(value: Value) -> Result<Option<RoutingPolicy>, String> {
        routing_policy(serde_json::from_value(value).map_err(|e| e.to_string())?)
    }
    fn policy() -> Value {
        json!({"group":"Офис","revision":"3:7","include":["10.0.0.0/8","0.0.0.0/0"],"exclude":["10.1.0.0/16"],"exclude_lan":true})
    }
    #[test]
    fn routing_policy_roundtrip() {
        assert_eq!(parse(json!({"policy":null})), Ok(None));
        assert_eq!(parse(json!({"policy":null,"future":1})), Ok(None));
        let parsed = parse(json!({ "policy": policy() })).unwrap().unwrap();
        assert_eq!(
            parsed,
            RoutingPolicy {
                group: "Офис".into(),
                revision: "3:7".into(),
                include: vec!["10.0.0.0/8".parse().unwrap(), "0.0.0.0/0".parse().unwrap()],
                exclude: vec!["10.1.0.0/16".parse().unwrap()],
                exclude_lan: true,
            }
        );
        assert_eq!(serde_json::to_value(&parsed).unwrap(), policy());
    }
    #[test]
    fn routing_policy_rejects_garbage_and_bounds() {
        assert!(parse(json!({})).is_err());
        assert!(parse(json!({"policy":"x"})).is_err());
        let many = |n: usize| (0..n).map(|i| format!("10.{i}.0.0/16")).collect::<Vec<_>>();
        for (key, bad) in [
            ("group", json!("")),
            ("group", json!("я".repeat(81))),
            ("group", json!("a\nb")),
            ("revision", json!("")),
            ("revision", json!("x".repeat(65))),
            ("revision", json!("a b")),
            ("include", json!([])),
            ("include", json!(many(17))),
            ("include", json!(["10.0.0.1/8"])),
            ("include", json!(["10.0.0.0"])),
            ("include", json!(["fd00::/8"])),
            ("exclude", json!(many(65))),
            ("exclude", json!(["10.0.0.0/33"])),
            ("exclude_lan", json!("true")),
            ("unexpected", json!(1)),
        ] {
            let mut value = policy();
            value[key] = bad;
            assert!(parse(json!({ "policy": value })).is_err(), "{key}");
        }
        let mut value = policy();
        value["group"] = json!("я".repeat(80));
        value["revision"] = json!("x".repeat(64));
        value["include"] = json!(many(16));
        value["exclude"] = json!(many(64));
        assert!(parse(json!({ "policy": value })).unwrap().is_some());
        let mut value = policy();
        value.as_object_mut().unwrap().remove("exclude");
        assert!(parse(json!({ "policy": value })).is_err());
    }
}

#[cfg(test)]
mod snapshot_tests;
