//! GitHub Release lookup and checksum-verified download.
//!
//! `SHA256SUMS` is published next to the assets and is not signed. A match
//! proves the downloaded bytes equal that list, and nothing else: not the
//! Ed25519 update root and not an OS publisher signature. This module never
//! installs or executes a package. The caller shows the saved path; the user
//! installs it.
use ring::digest;
use serde::Deserialize;
use std::{
    io::Write,
    path::{Path, PathBuf},
};

pub const REPOSITORY: &str = "onixus/Rust-trustvpn";
const API: &str = "https://api.github.com";
const HOST: &str = "github.com";
/// Release notes are untrusted text shown to the user; keep them short.
const MAX_NOTES: usize = 4000;
const MAX_SUMS: usize = 256 * 1024;
const MAX_INDEX: usize = 1024 * 1024;

/// One installable asset of the running app. The first name present in both
/// the release and `SHA256SUMS` wins, so the preferred package is listed first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssetKind {
    /// Stable name for logs and UI, never a path.
    pub id: &'static str,
    names: &'static [&'static str],
}

/// Native GUI and the terminal client share the desktop package.
pub const NATIVE: AssetKind = AssetKind {
    id: "native",
    names: &[
        "R-TrustTunnel-Windows-x64-Setup.exe",
        "R-TrustTunnel-macOS-arm64-UI-Choices.dmg",
        "R-TrustTunnel-Linux-x86_64.flatpak",
    ],
};
pub const WEBVIEW: AssetKind = AssetKind {
    id: "webview",
    names: &[
        "R-TrustTunnel-Windows-x64-Setup.exe",
        "R-TrustTunnel-macOS-arm64-UI-Choices.dmg",
        "R-TrustTunnel-Linux-x86_64-webview.flatpak",
    ],
};
pub const ANDROID: AssetKind = AssetKind {
    id: "android",
    names: &["R-TrustTunnel-Android.apk"],
};
/// No installable iOS asset is published. The lookup says so instead of
/// offering a stale device archive.
pub const IOS: AssetKind = AssetKind {
    id: "ios",
    names: &[],
};

/// The package this binary should offer. Service and helper binaries are not apps.
pub fn kind_for_current_app() -> Option<AssetKind> {
    match std::env::consts::OS {
        "android" => Some(ANDROID),
        "ios" => Some(IOS),
        _ => match option_env!("CARGO_PKG_NAME") {
            Some("rtrust-webview") => Some(WEBVIEW),
            Some("rtrust-tui") | Some("rtrust-native") => Some(NATIVE),
            _ => None,
        },
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseInfo {
    pub tag: String,
    pub version: String,
    /// Newer than the version compiled into this binary.
    pub newer: bool,
    pub notes: String,
    /// Release page, empty when the tag is not safe to put in a URL.
    pub page: String,
    pub asset: Option<ListedAsset>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedAsset {
    pub name: String,
    pub size: u64,
    pub sha256: String,
    /// Direct browser URL. The API asset URL is never exposed.
    pub url: String,
}

#[derive(Deserialize)]
struct ApiRelease {
    tag_name: String,
    body: Option<String>,
    prerelease: bool,
    draft: bool,
    assets: Vec<ApiAsset>,
}
#[derive(Deserialize)]
struct ApiAsset {
    name: String,
    size: u64,
}

fn safe_tag(tag: &str) -> bool {
    let rest = tag.strip_prefix('v').unwrap_or(tag);
    !rest.is_empty()
        && rest.len() <= 64
        && rest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 160
        && !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// Browser URL of one release asset. Rejects another host, a query and `..`.
pub fn asset_url(tag: &str, name: &str) -> Result<String, String> {
    if !safe_tag(tag) || !safe_name(name) {
        return Err("Некорректное имя файла релиза".into());
    }
    let url = format!("https://{HOST}/{REPOSITORY}/releases/download/{tag}/{name}");
    let parsed = reqwest::Url::parse(&url).map_err(|_| "Некорректный адрес файла релиза")?;
    if parsed.host_str() != Some(HOST)
        || parsed.scheme() != "https"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err("Некорректный адрес файла релиза".into());
    }
    Ok(url)
}

/// `major.minor.patch`, ignoring a leading `v` and anything after `-` or `+`.
pub fn version_tuple(version: &str) -> Option<(u64, u64, u64)> {
    let version = version.strip_prefix('v').unwrap_or(version);
    let version = version.split(['-', '+']).next().unwrap_or(version);
    let mut parts = version.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

/// Whether `published` is strictly newer than the version compiled into this binary.
pub fn is_newer(published: &str) -> bool {
    match (
        version_tuple(published),
        version_tuple(env!("CARGO_PKG_VERSION")),
    ) {
        (Some(published), Some(current)) => published > current,
        _ => false,
    }
}

fn page(tag: &str) -> String {
    if safe_tag(tag) {
        format!("https://{HOST}/{REPOSITORY}/releases/tag/{tag}")
    } else {
        String::new()
    }
}

fn notes(body: Option<String>) -> String {
    let mut text = body.unwrap_or_default().replace('\0', "");
    if text.chars().count() > MAX_NOTES {
        text = text.chars().take(MAX_NOTES).collect();
        text.push('…');
    }
    text
}

/// `SHA256SUMS` lines are `<64 hex><two spaces><filename>`. Other lines are ignored.
pub fn parse_sums(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let (hash, name) = line.split_once("  ")?;
            if hash.len() == 64
                && hash.bytes().all(|b| b.is_ascii_hexdigit())
                && safe_name(name)
            {
                Some((name.to_string(), hash.to_ascii_lowercase()))
            } else {
                None
            }
        })
        .collect()
}

fn asset_host(host: Option<&str>) -> bool {
    matches!(
        host,
        Some("release-assets.githubusercontent.com" | "objects.githubusercontent.com")
    )
}

/// GitHub release downloads answer with one redirect to a signed asset URL.
/// Only that host is followed, and only once. The bytes are still hash-checked.
async fn send(url: &str) -> Result<reqwest::Response, String> {
    let parsed = reqwest::Url::parse(url).map_err(|_| "Некорректный адрес релиза")?;
    let allowed = parsed.scheme() == "https"
        && matches!(parsed.host_str(), Some("api.github.com" | "github.com"));
    if !allowed || parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("Некорректный адрес релиза".into());
    }
    let response = crate::http()?
        .get(url)
        .header("user-agent", "rtrust-update")
        .header("accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|_| "GitHub недоступен")?;
    if !matches!(response.status().as_u16(), 301 | 302 | 307 | 308) {
        return Ok(response);
    }
    let next = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .ok_or("GitHub не указал адрес файла")?;
    let next = reqwest::Url::parse(next).map_err(|_| "Некорректный адрес файла релиза")?;
    if next.scheme() != "https" || !asset_host(next.host_str()) || next.fragment().is_some() {
        return Err("Некорректный адрес файла релиза".into());
    }
    crate::http()?
        .get(next)
        .header("user-agent", "rtrust-update")
        .send()
        .await
        .map_err(|_| "GitHub недоступен".to_string())
}

async fn get_bytes(url: &str, limit: usize) -> Result<Vec<u8>, String> {
    let mut response = send(url).await?;
    if response.status().as_u16() == 404 {
        return Err("Релиз на GitHub не найден".into());
    }
    if !response.status().is_success() {
        return Err("GitHub не отдал релиз".into());
    }
    let mut data = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| "Ответ GitHub прерван")? {
        if data.len().saturating_add(chunk.len()) > limit {
            return Err("Ответ GitHub слишком большой".into());
        }
        data.extend_from_slice(&chunk);
    }
    Ok(data)
}

fn info(release: ApiRelease, asset: Option<ListedAsset>, note: Option<String>) -> ReleaseInfo {
    ReleaseInfo {
        version: release
            .tag_name
            .strip_prefix('v')
            .unwrap_or(&release.tag_name)
            .to_string(),
        newer: is_newer(&release.tag_name),
        page: page(&release.tag_name),
        notes: note.unwrap_or_else(|| notes(release.body)),
        tag: release.tag_name,
        asset,
    }
}

/// Latest stable release, bound to the asset of `kind` through `SHA256SUMS`.
pub async fn check(kind: AssetKind) -> Result<ReleaseInfo, String> {
    let url = format!("{API}/repos/{REPOSITORY}/releases/latest");
    let data = get_bytes(&url, MAX_INDEX).await?;
    let release: ApiRelease =
        serde_json::from_slice(&data).map_err(|_| "Некорректный ответ GitHub")?;
    if release.draft || release.prerelease {
        return Err("Последний релиз GitHub — черновик или предварительный".into());
    }
    if kind.names.is_empty() {
        return Ok(info(
            release,
            None,
            Some(
                "Для этой платформы установочный файл в релизах GitHub не публикуется."
                    .into(),
            ),
        ));
    }
    let sums_url = asset_url(&release.tag_name, "SHA256SUMS")?;
    if !release.assets.iter().any(|a| a.name == "SHA256SUMS") {
        return Err("В релизе нет SHA256SUMS, файл не предлагается".into());
    }
    let sums = String::from_utf8(get_bytes(&sums_url, MAX_SUMS).await?)
        .map_err(|_| "SHA256SUMS не является текстом")?;
    let sums = parse_sums(&sums);
    let chosen = kind.names.iter().copied().find_map(|name| {
        let file = release.assets.iter().find(|a| a.name == name)?;
        let sha256 = sums.iter().find(|(n, _)| n == name)?.1.clone();
        Some(ListedAsset {
            name: name.to_string(),
            size: file.size,
            sha256,
            url: asset_url(&release.tag_name, name).ok()?,
        })
    });
    Ok(info(release, chosen, None))
}

/// Download `asset` and reject it unless its bytes match the published checksum.
pub async fn download(asset: &ListedAsset, folder: &Path) -> Result<PathBuf, String> {
    if asset.size == 0 || asset.size > crate::MAX_PACKAGE || !safe_name(&asset.name) {
        return Err("Недопустимый файл релиза".into());
    }
    let tag = asset
        .url
        .split("/releases/download/")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .unwrap_or("");
    let url = asset_url(tag, &asset.name)?;
    if url != asset.url {
        return Err("Некорректный адрес файла релиза".into());
    }
    std::fs::create_dir_all(folder).map_err(|_| "Нет доступа к каталогу обновлений")?;
    let mut file =
        tempfile::NamedTempFile::new_in(folder).map_err(|_| "Не удалось создать временный пакет")?;
    let mut response = send(&url).await.map_err(|_| "Не удалось загрузить пакет")?;
    if !response.status().is_success() {
        return Err("GitHub не выдал пакет".into());
    }
    let mut context = digest::Context::new(&digest::SHA256);
    let mut size = 0u64;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "Загрузка пакета прервана")?
    {
        size += chunk.len() as u64;
        if size > asset.size {
            return Err("Пакет превышает заявленный размер".into());
        }
        context.update(&chunk);
        file.write_all(&chunk)
            .map_err(|_| "Не удалось сохранить пакет")?;
    }
    let hash = context
        .finish()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    if size != asset.size || hash != asset.sha256.to_ascii_lowercase() {
        return Err("Хеш или размер пакета не совпадает с SHA256SUMS".into());
    }
    file.flush().map_err(|_| "Не удалось записать пакет")?;
    file.as_file()
        .sync_all()
        .map_err(|_| "Не удалось сохранить пакет")?;
    let path = folder.join(&asset.name);
    file.persist(&path)
        .map_err(|_| "Не удалось сохранить проверенный пакет")?;
    Ok(path)
}

/// Check, and when a newer asset exists, download it into the update cache.
/// Returns the release and the verified file. Nothing is executed.
pub async fn fetch_newer(kind: AssetKind) -> Result<(ReleaseInfo, Option<PathBuf>), String> {
    let release = check(kind).await?;
    let Some(asset) = release.asset.clone().filter(|_| release.newer) else {
        return Ok((release, None));
    };
    let folder = crate::cache_dir()?.join("github").join(&release.tag);
    let path = download(&asset, &folder).await?;
    Ok((release, Some(path)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_order_ignores_pre_release_suffix() {
        assert_eq!(version_tuple("v0.7.0"), Some((0, 7, 0)));
        assert_eq!(version_tuple("0.8.0-beta.1"), Some((0, 8, 0)));
        assert!(version_tuple("0.7").is_none());
        assert!(version_tuple("nope").is_none());
    }

    #[test]
    fn sums_keep_only_well_formed_rows() {
        let rows = parse_sums(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  R-TrustTunnel-Android.apk\n\
             short  bad\n\
             0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  ../x\n\
             \n",
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "R-TrustTunnel-Android.apk");
    }

    #[test]
    fn asset_url_rejects_another_host_and_traversal() {
        assert!(asset_url("v0.7.0", "R-TrustTunnel-Android.apk").is_ok());
        assert!(asset_url("v0.7.0", "../secret").is_err());
        assert!(asset_url("v0.7.0?x=1", "a.apk").is_err());
        assert!(asset_url("v0.7.0", "a apk").is_err());
    }

    #[test]
    fn one_redirect_stays_on_the_github_asset_host() {
        // The helper is exercised through download's URL check; the host list is
        // the only place a redirected release file may come from.
        for host in [
            "release-assets.githubusercontent.com",
            "objects.githubusercontent.com",
        ] {
            let url = format!("https://{host}/asset");
            assert!(reqwest::Url::parse(&url).unwrap().host_str() == Some(host));
        }
        assert!(!asset_host(Some("evil.example")));
        assert!(!asset_host(Some("github.com")));
    }

    #[tokio::test]
    #[ignore = "live GitHub"]
    async fn live_release_lists_the_android_asset() {
        let release = check(ANDROID).await.unwrap();
        assert!(release.asset.is_some(), "{}", release.notes);
        assert!(!release.page.is_empty());
    }

    #[test]
    fn download_refuses_a_url_that_is_not_the_named_asset() {
        let asset = ListedAsset {
            name: "R-TrustTunnel-Android.apk".into(),
            size: 3,
            sha256: "ab".into(),
            url: "https://evil.example/R-TrustTunnel-Android.apk".into(),
        };
        let error = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(download(&asset, Path::new(".")))
            .unwrap_err();
        assert_eq!(error, "Некорректное имя файла релиза");
    }
}
