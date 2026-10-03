//! Android codec and narrow JNI boundary. No privileged desktop service is used.
#[cfg(target_os = "android")]
mod bridge;
mod policy;
pub use policy::prepare;
use rtrust_profile::{Format, Profile};
use zeroize::Zeroizing;

pub fn import_profile(input: &str) -> Result<Zeroizing<String>, String> {
    let profile = Profile::import(input).map_err(|e| e.to_string())?;
    let export = profile.export(Format::Json).map_err(|e| e.to_string())?;
    Ok(Zeroizing::new(format!(
        "{{\"ok\":true,\"profile\":{}}}",
        export.content
    )))
}
pub fn export_profile(input: &str, format: i32) -> Result<Zeroizing<String>, String> {
    let profile = Profile::import(input).map_err(|e| e.to_string())?;
    let format = match format {
        0 => Format::Json,
        1 => Format::EndpointToml,
        2 => Format::CliToml,
        3 => Format::Link,
        4 => Format::Conf,
        _ => return Err("Unknown export format".into()),
    };
    let export = profile.export(format).map_err(|e| e.to_string())?;
    #[derive(serde::Serialize)]
    struct Output<'a> {
        ok: bool,
        content: &'a str,
        losses: &'a [&'static str],
    }
    serde_json::to_string(&Output {
        ok: true,
        content: &export.content,
        losses: &export.losses,
    })
    .map(Zeroizing::new)
    .map_err(|_| "Cannot encode export".into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn android_file_and_link_round_trip_and_redacted_errors() {
        let input = "hostname='mobile.example'\naddresses=['192.0.2.1:443']\nusername='test'\npassword='android-synthetic-canary'\n";
        let imported: serde_json::Value =
            serde_json::from_str(&import_profile(input).unwrap()).unwrap();
        let canonical = imported["profile"].to_string();
        for format in 0..4 {
            let exported: serde_json::Value =
                serde_json::from_str(&export_profile(&canonical, format).unwrap()).unwrap();
            let restored = Profile::import(exported["content"].as_str().unwrap()).unwrap();
            assert_eq!(
                restored.endpoint.password.expose(),
                "android-synthetic-canary"
            );
        }
        assert!(
            !import_profile("password='android-synthetic-canary'")
                .unwrap_err()
                .contains("canary")
        );
        assert!(export_profile(&canonical, 99).is_err());
        assert!(import_profile(&"x".repeat(rtrust_profile::MAX_INPUT + 1)).is_err());
    }
}
