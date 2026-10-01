//! Origin-bound profile exchange. Secrets never appear in errors or Debug output.
use reqwest::{Client as Http, Method, Url};
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
        serde_json::from_slice(&bytes).map_err(|_| "Некорректный ответ панели".into())
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
}
