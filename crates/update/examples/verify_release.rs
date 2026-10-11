//! Read-only publication verification using the client's pinned update root.
use std::io::Read;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 4 {
        return Err("usage: verify_release ENVELOPE ARTIFACT TARGET SEQUENCE".into());
    }
    let mut envelope = Vec::new();
    std::fs::File::open(&args[0])?
        .take(16385)
        .read_to_end(&mut envelope)?;
    let sequence: u64 = args[3].parse()?;
    let release = rtrust_update::verify(&envelope, &args[2], rtrust_update::now()?, sequence)?;
    rtrust_update::verify_publication(
        &release,
        &mut std::fs::File::open(&args[1])?,
        &args[2],
        sequence,
    )?;
    println!(
        "{}",
        serde_json::json!({"version": release.manifest().version})
    );
    Ok(())
}
