//! Isolated HTTPS publication check. Credentials are read only from a private fixture.
use rtrust_portal::{Client, RoutingPolicy};
use std::io::{BufRead, Write};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os().nth(1).ok_or("Fixture path required")?;
    let raw = zeroize::Zeroizing::new(std::fs::read(path)?);
    let data: serde_json::Value = serde_json::from_slice(&raw)?;
    let client = Client::with_certificate(
        data["url"].as_str().ok_or("Missing URL")?,
        Some(data["ca"].as_str().ok_or("Missing CA")?.as_bytes()),
    )?
    .enroll(
        data["code"].as_str().ok_or("Missing code")?,
        "Route publication E2E",
    )
    .await?;
    println!("ready");
    std::io::stdout().flush()?;
    for line in std::io::stdin().lock().lines() {
        let expected: serde_json::Value = serde_json::from_str(&line?)?;
        let actual = client.routing().await;
        if expected.get("error").and_then(|v| v.as_bool()) == Some(true) {
            assert!(actual.is_err(), "Revoked device must not read routes");
        } else {
            let expected: Option<RoutingPolicy> = serde_json::from_value(expected)?;
            assert_eq!(
                actual?, expected,
                "Published routes must reach the client unchanged"
            );
        }
        println!("checked");
        std::io::stdout().flush()?;
    }
    Ok(())
}
