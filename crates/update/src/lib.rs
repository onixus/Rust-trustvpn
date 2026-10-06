//! Signed update metadata and bounded artifact download. No elevation or execution.
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::{digest, signature};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};
pub const ORIGIN: &str = "https://onixus-rf.duckdns.org";
pub const CURRENT_SEQUENCE: u64 = 9;
pub const CURRENT_IPC: u32 = 1;
const ROOT: &[u8] = include_bytes!("root.pub");
const MAX_PACKAGE: u64 = 256 * 1024 * 1024;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: u32,
    pub sequence: u64,
    pub version: String,
    pub target: String,
    pub min_ipc: u32,
    pub max_ipc: u32,
    pub published: u64,
    pub expires: u64,
    pub url: String,
    pub size: u64,
    pub sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub payload: String,
    pub signature: String,
}
#[derive(Clone)]
pub struct Release {
    manifest: Manifest,
    envelope: Vec<u8>,
}
impl Release {
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }
}
pub fn target() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}
pub fn now() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| "Некорректное системное время".into())
}
pub fn verify(data: &[u8], target: &str, now: u64, min_sequence: u64) -> Result<Release, String> {
    verify_key(data, ROOT, target, now, min_sequence)
}
fn verify_key(
    data: &[u8],
    key: &[u8],
    target: &str,
    now: u64,
    min_sequence: u64,
) -> Result<Release, String> {
    if data.len() > 16384 {
        return Err("Слишком большой манифест".into());
    }
    let envelope: Envelope = serde_json::from_slice(data).map_err(|_| "Некорректный манифест")?;
    let payload = STANDARD
        .decode(&envelope.payload)
        .map_err(|_| "Некорректный манифест")?;
    let sig = STANDARD
        .decode(&envelope.signature)
        .map_err(|_| "Некорректная подпись")?;
    signature::UnparsedPublicKey::new(&signature::ED25519, key)
        .verify(&payload, &sig)
        .map_err(|_| "Подпись обновления не подтверждена")?;
    let m: Manifest = serde_json::from_slice(&payload).map_err(|_| "Некорректные поля релиза")?;
    if m.schema != 1
        || m.target != target
        || m.sequence < min_sequence
        || m.min_ipc > CURRENT_IPC
        || m.max_ipc < CURRENT_IPC
    {
        return Err("Несовместимое обновление или запрещённое понижение версии".into());
    }
    if m.published > now.saturating_add(300)
        || m.expires <= now
        || m.expires <= m.published
        || m.expires - m.published > 31 * 86400
    {
        return Err("Манифест истёк или системное время неверно".into());
    }
    let url = reqwest::Url::parse(&m.url).map_err(|_| "Некорректный адрес обновления")?;
    if url.origin().ascii_serialization() != ORIGIN
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.path().starts_with("/rtrust/releases/")
        || m.size == 0
        || m.size > MAX_PACKAGE
        || m.sha256.len() != 64
        || !m.sha256.bytes().all(|b| b.is_ascii_hexdigit())
        || m.version.is_empty()
        || m.version.len() > 64
        || m.version.chars().any(char::is_control)
    {
        return Err("Недопустимые параметры обновления".into());
    }
    Ok(Release {
        manifest: m,
        envelope: data.to_vec(),
    })
}
fn http() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|_| "Не удалось создать клиент обновлений".into())
}
pub async fn check(min_sequence: u64) -> Result<Release, String> {
    let mut response = http()?
        .get(format!("{ORIGIN}/rtrust/releases/{}/latest.json", target()))
        .send()
        .await
        .map_err(|_| "Сервер обновлений недоступен")?;
    if !response.status().is_success() {
        return Err("Проверенный релиз пока не опубликован".into());
    }
    let mut data = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "Ответ сервера прерван")?
    {
        if data.len() + chunk.len() > 16384 {
            return Err("Слишком большой манифест".into());
        }
        data.extend_from_slice(&chunk);
    }
    verify(&data, &target(), now()?, min_sequence)
}
pub fn verify_file(file: &mut std::fs::File, release: &Release) -> Result<(), String> {
    let mut context = digest::Context::new(&digest::SHA256);
    let mut buf = [0u8; 65536];
    let mut count = 0u64;
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|_| "Не удалось прочитать пакет")?;
        if n == 0 {
            break;
        }
        count += n as u64;
        if count > release.manifest.size {
            return Err("Размер пакета не совпадает".into());
        }
        context.update(&buf[..n]);
    }
    let hash = context
        .finish()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    if count != release.manifest.size || hash != release.manifest.sha256.to_ascii_lowercase() {
        return Err("Хеш или размер пакета не совпадает".into());
    }
    Ok(())
}
pub async fn download(release: &Release, folder: &Path) -> Result<PathBuf, String> {
    download_mode(release, folder, false).await
}
pub async fn download_rollback(release: &Release, folder: &Path) -> Result<PathBuf, String> {
    download_mode(release, folder, true).await
}
async fn download_mode(
    release: &Release,
    folder: &Path,
    rollback: bool,
) -> Result<PathBuf, String> {
    // Recheck expiry just before downloading. The caller cannot construct Release.
    if rollback {
        verify_rollback(release.envelope())?;
    } else {
        verify(release.envelope(), &target(), now()?, CURRENT_SEQUENCE)?;
    }
    std::fs::create_dir_all(folder).map_err(|_| "Нет доступа к каталогу обновлений")?;
    let mut file = tempfile::NamedTempFile::new_in(folder)
        .map_err(|_| "Не удалось создать временный пакет")?;
    let mut response = http()?
        .get(&release.manifest.url)
        .send()
        .await
        .map_err(|_| "Не удалось загрузить пакет")?;
    if !response.status().is_success() {
        return Err("Сервер не выдал пакет".into());
    }
    let mut size = 0u64;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "Загрузка пакета прервана")?
    {
        size += chunk.len() as u64;
        if size > release.manifest.size {
            return Err("Пакет превышает заявленный размер".into());
        }
        file.write_all(&chunk)
            .map_err(|_| "Не удалось сохранить пакет")?;
    }
    file.flush().map_err(|_| "Не удалось записать пакет")?;
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(0))
        .map_err(|_| "Ошибка файла пакета")?;
    verify_file(file.as_file_mut(), release)?;
    file.as_file()
        .sync_all()
        .map_err(|_| "Не удалось сохранить пакет")?;
    let path = folder.join(format!(
        "release-{}-{}{}",
        release.manifest.sequence,
        release.manifest.sha256,
        if cfg!(windows) { ".exe" } else { ".package" }
    ));
    file.persist(&path)
        .map_err(|_| "Не удалось опубликовать проверенный пакет")?;
    Ok(path)
}
/// An explicitly requested rollback must be the exact currently running release,
/// signed by the same root. Expiry of historical metadata does not change its hash.
pub fn verify_rollback(data: &[u8]) -> Result<Release, String> {
    if data.len() > 16384 {
        return Err("Слишком большой манифест отката".into());
    }
    let envelope: Envelope =
        serde_json::from_slice(data).map_err(|_| "Некорректный манифест отката")?;
    let payload = STANDARD
        .decode(&envelope.payload)
        .map_err(|_| "Некорректный манифест отката")?;
    let m: Manifest =
        serde_json::from_slice(&payload).map_err(|_| "Некорректный манифест отката")?;
    let release = verify(data, &target(), m.published, CURRENT_SEQUENCE)?;
    if release.manifest.sequence != CURRENT_SEQUENCE {
        return Err("Пакет отката не соответствует установленной версии".into());
    }
    Ok(release)
}
pub fn cache_dir() -> Result<PathBuf, String> {
    directories::ProjectDirs::from("org", "RTrustTunnel", "RTrustTunnel")
        .map(|d| d.cache_dir().join("updates"))
        .ok_or("Нет каталога обновлений".into())
}
pub async fn rollback_release() -> Result<Release, String> {
    let mut response = http()?
        .get(format!(
            "{ORIGIN}/rtrust/releases/{CURRENT_SEQUENCE}/{}/manifest.json",
            target()
        ))
        .send()
        .await
        .map_err(|_| "Недоступен пакет для отката")?;
    if !response.status().is_success() {
        return Err("Пакет для отката не опубликован; обновление не запущено".into());
    }
    let mut data = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "Ответ сервера прерван")?
    {
        if data.len() + chunk.len() > 16384 {
            return Err("Слишком большой манифест".into());
        }
        data.extend_from_slice(&chunk);
    }
    verify_rollback(&data)
}
pub fn artifact_path(folder: &Path, release: &Release) -> PathBuf {
    folder.join(format!(
        "release-{}-{}{}",
        release.manifest.sequence,
        release.manifest.sha256,
        if cfg!(windows) { ".exe" } else { ".package" }
    ))
}
pub async fn stage(release: &Release) -> Result<PathBuf, String> {
    if release.manifest.sequence <= CURRENT_SEQUENCE {
        return Err("Новая версия не найдена".into());
    }
    let cache = cache_dir()?;
    std::fs::create_dir_all(&cache).map_err(|_| "Нет доступа к кэшу обновлений")?;
    let folder = tempfile::Builder::new()
        .prefix("transaction-")
        .tempdir_in(cache)
        .map_err(|_| "Не удалось подготовить обновление")?;
    let rollback = rollback_release().await?;
    download_rollback(&rollback, folder.path()).await?;
    download(release, folder.path()).await?;
    rtrust_store::write_private(&folder.path().join("release.json"), release.envelope())
        .map_err(|_| "Не удалось сохранить манифест")?;
    rtrust_store::write_private(&folder.path().join("rollback.json"), rollback.envelope())
        .map_err(|_| "Не удалось сохранить манифест отката")?;
    Ok(folder.keep())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    fn fixture() -> (Ed25519KeyPair, Manifest) {
        let pair = Ed25519KeyPair::from_seed_unchecked(&[42u8; 32]).unwrap();
        let m = Manifest {
            schema: 1,
            sequence: 5,
            version: "0.2.0".into(),
            target: "windows-x86_64".into(),
            min_ipc: 1,
            max_ipc: 1,
            published: 1000,
            expires: 2000,
            url: format!("{ORIGIN}/rtrust/releases/5/setup.exe"),
            size: 3,
            sha256: digest::digest(&digest::SHA256, b"abc")
                .as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        };
        (pair, m)
    }
    fn signed(pair: &Ed25519KeyPair, m: &Manifest) -> Vec<u8> {
        let bytes = serde_json::to_vec(m).unwrap();
        serde_json::to_vec(&Envelope {
            payload: STANDARD.encode(&bytes),
            signature: STANDARD.encode(pair.sign(&bytes).as_ref()),
        })
        .unwrap()
    }
    #[tokio::test]
    async fn installed_release_is_not_staged_as_an_update() {
        let (pair, mut manifest) = fixture();
        manifest.sequence = CURRENT_SEQUENCE;
        let release = verify_key(
            &signed(&pair, &manifest),
            pair.public_key().as_ref(),
            &manifest.target,
            1500,
            CURRENT_SEQUENCE,
        )
        .unwrap();
        assert_eq!(
            stage(&release).await.unwrap_err(),
            "Новая версия не найдена"
        );
    }
    #[test]
    fn verified_signature_binds_platform_sequence_and_expiry() {
        let (pair, mut m) = fixture();
        let data = signed(&pair, &m);
        let key = pair.public_key().as_ref();
        assert!(verify_key(&data, key, "windows-x86_64", 1500, 5).is_ok());
        assert!(verify_key(&data, key, "linux-x86_64", 1500, 5).is_err());
        assert!(verify_key(&data, key, "windows-x86_64", 1500, 6).is_err());
        assert!(verify_key(&data, key, "windows-x86_64", 2000, 5).is_err());
        assert!(verify_key(&data, &[0u8; 32], "windows-x86_64", 1500, 5).is_err());
        m.min_ipc = 2;
        assert!(verify_key(&signed(&pair, &m), key, "windows-x86_64", 1500, 5).is_err());
    }
    #[test]
    fn attacker_cannot_change_payload_or_redirect_artifacts() {
        let (pair, mut m) = fixture();
        let key = pair.public_key().as_ref();
        let mut envelope: Envelope = serde_json::from_slice(&signed(&pair, &m)).unwrap();
        m.sequence += 1;
        envelope.payload = STANDARD.encode(serde_json::to_vec(&m).unwrap());
        assert!(
            verify_key(
                &serde_json::to_vec(&envelope).unwrap(),
                key,
                "windows-x86_64",
                1500,
                0
            )
            .is_err()
        );
        for url in [
            "https://evil.example/rtrust/releases/a",
            "http://onixus-rf.duckdns.org/rtrust/releases/a",
            "https://onixus-rf.duckdns.org/profiles",
            "https://onixus-rf.duckdns.org/rtrust/releases/a?secret=b",
        ] {
            m.url = url.into();
            assert!(verify_key(&signed(&pair, &m), key, "windows-x86_64", 1500, 0).is_err());
        }
    }
    #[test]
    fn corrupted_truncated_or_extended_binary_is_rejected() {
        let (pair, m) = fixture();
        let release = verify_key(
            &signed(&pair, &m),
            pair.public_key().as_ref(),
            "windows-x86_64",
            1500,
            0,
        )
        .unwrap();
        for (bytes, ok) in [
            (b"abc".as_slice(), true),
            (b"abd", false),
            (b"ab", false),
            (b"abcd", false),
        ] {
            let mut file = tempfile::tempfile().unwrap();
            file.write_all(bytes).unwrap();
            use std::io::{Seek, SeekFrom};
            file.seek(SeekFrom::Start(0)).unwrap();
            assert_eq!(verify_file(&mut file, &release).is_ok(), ok);
        }
    }
}
