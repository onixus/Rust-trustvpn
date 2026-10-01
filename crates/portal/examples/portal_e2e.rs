//! Synthetic fixture only; enrollment code stays in a protected file, not argv/logs.
use rtrust_portal::Client;
use rtrust_profile::{Format, Profile};
#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os().nth(1).ok_or("Fixture path required")?;
    let raw = zeroize::Zeroizing::new(std::fs::read(path)?);
    let data: serde_json::Value = serde_json::from_slice(&raw)?;
    let url = data["url"].as_str().ok_or("Missing URL")?;
    let code = data["code"].as_str().ok_or("Missing code")?;
    let ca = data["ca"].as_str().ok_or("Missing CA")?;
    if data["private_ca"].as_bool().unwrap_or(false) {
        assert!(
            Client::new(url)?
                .enroll(code, "Untrusted TLS")
                .await
                .is_err()
        );
    }
    let client = Client::with_certificate(url, Some(ca.as_bytes()))?
        .enroll(code, "Rust native E2E")
        .await?;
    assert!(
        Client::with_certificate(url, Some(ca.as_bytes()))?
            .enroll(code, "Replayed code")
            .await
            .is_err()
    );
    assert!(client.list().await?.is_empty());
    let profile = Profile::import(data["profile"].as_str().ok_or("Missing profile")?)?;
    let preview = client.preview_upload(&profile).await?;
    assert!(client.list().await?.is_empty(), "Preview must not commit");
    client.commit(&preview).await?;
    client.commit(&preview).await?;
    let mut list = client.list().await?;
    assert_eq!(list.len(), 1, "Idempotent commit and device grant");
    let downloaded = client.download(&list[0]).await?;
    assert_eq!(
        downloaded.export(Format::Json)?.content,
        profile.export(Format::Json)?.content
    );
    let old = list[0].clone();
    let mut edited = profile.clone();
    edited.name = "Updated through native API".into();
    let replace = client.preview_upload(&edited).await?;
    client.replace(&replace, &old).await?;
    client.replace(&replace, &old).await?; // same request is idempotent
    let latest = client.list().await?;
    assert_eq!(latest.len(), 1);
    assert_ne!(latest[0].revision, old.revision);
    assert_eq!(client.download(&latest[0]).await?.name, edited.name);
    let stale = client.preview_upload(&profile).await?;
    assert!(client.replace(&stale, &old).await.is_err());
    assert_eq!(client.download(&latest[0]).await?.name, edited.name);
    list[0].revision = "stale".into();
    assert!(client.download(&list[0]).await.is_err());
    list[0].id = "../enroll".into();
    assert!(client.download(&list[0]).await.is_err());
    println!(
        "PASS Rust portal: verified TLS, one-time enrollment, grants, preview/commit, idempotency, download/replace roundtrip, idempotency, stale write/read rejection"
    );
    Ok(())
}
