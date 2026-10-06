//! Origin-bound profile exchange. Secrets never appear in errors or Debug output.
use ipnet::Ipv4Net;
use reqwest::{Client as Http, Method, StatusCode, Url};
use rtrust_profile::{Format, MAX_INPUT, Profile};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use zeroize::Zeroizing;
const LIMIT: usize = 8 * MAX_INPUT;
#[derive(Clone, Deserialize)]
pub struct Summary {
    pub name: String,
    pub hostname: String,
}
#[derive(Clone, Deserialize)]
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
}
impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PortalClient([REDACTED])")
    }
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
    pub fn address(&self) -> &str {
        self.origin.as_str()
    }
    pub fn remember(&self) -> Result<(), String> {
        let bytes = Zeroizing::new(
            serde_json::to_vec(&json!({"origin":self.origin.as_str(),"token":self.token.as_str()}))
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
        }
        let saved: Saved =
            serde_json::from_slice(&bytes).map_err(|_| "Повреждена сохранённая привязка")?;
        let mut client = Self::new(&saved.origin)?;
        if !(40..=128).contains(&saved.token.len()) {
            return Err("Повреждена сохранённая привязка".into());
        }
        client.token = Zeroizing::new(saved.token);
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
        if !response.status().is_success() {
            return Err(match response.status().as_u16() {
                401 => "Код истёк или доступ устройства отозван. Привяжите устройство заново.",
                403 => "Недостаточно прав на эту операцию.",
                404 => "Профиль недоступен. Проверьте выданные устройству права.",
                409 => "Профиль изменился. Обновите список и повторите просмотр.",
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
    pub async fn enroll(mut self, code: &str, name: &str) -> Result<Self, String> {
        if !(20..=128).contains(&code.len()) || name.trim().is_empty() || name.len() > 80 {
            return Err("Укажите код панели и имя устройства (до 80 байт)".into());
        }
        #[derive(Deserialize)]
        struct Enrolled {
            token: String,
        }
        let platform = if cfg!(target_os = "macos") {
            "macos"
        } else if cfg!(target_os = "windows") {
            "windows"
        } else {
            "linux"
        };
        let value: Enrolled = self
            .request(
                Method::POST,
                "enroll",
                Some(json!({"code":code,"name":name,"platform":platform})),
            )
            .await?;
        if !(40..=128).contains(&value.token.len())
            || !value
                .token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err("Некорректный токен панели".into());
        }
        self.token = Zeroizing::new(value.token);
        Ok(self)
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
            if p.revision.is_empty() || p.revision.len() > 256 {
                return Err("Некорректная версия профиля".into());
            }
        }
        Ok(result.profiles)
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
        match self.exchange(Method::GET, "routing", None, true).await? {
            Some(routing) => routing_policy(routing),
            None => Ok(None),
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
