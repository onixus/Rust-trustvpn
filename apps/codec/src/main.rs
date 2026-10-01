//! Bounded stdin/stdout adapter for the shared codec. Never reads files or connects.
use rtrust_profile::{Format, MAX_INPUT, Profile};
use serde::Deserialize;
use std::io::{Read, Write};
use zeroize::Zeroizing;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    content: String,
    #[serde(default)]
    format: Option<String>,
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = Zeroizing::new(Vec::new());
    std::io::stdin()
        .take((8 * MAX_INPUT + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 8 * MAX_INPUT {
        return Err("Input exceeds limit".into());
    }
    let input: Input = serde_json::from_slice(&bytes).map_err(|_| "Invalid codec request")?;
    let content = Zeroizing::new(input.content);
    let profile = Profile::import(&content)?;
    let format = match input.format.as_deref().unwrap_or("profile_json") {
        "profile_json" => Format::Json,
        "endpoint_toml" => Format::EndpointToml,
        "cli_toml" => Format::CliToml,
        "tt" => Format::Link,
        _ => return Err("Unknown export format".into()),
    };
    let export = profile.export(format)?;
    let result = Zeroizing::new(serde_json::to_vec(
        &serde_json::json!({"content":export.content,"losses":export.losses,"summary":{"name":profile.name,"hostname":profile.endpoint.hostname,"addresses":profile.endpoint.addresses,"protocol":profile.endpoint.upstream_protocol}}),
    )?);
    std::io::stdout().write_all(&result)?;
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
