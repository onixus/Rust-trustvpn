use super::routes::command;
const TABLE: &str = "rtrust_boot";
pub fn active() -> Result<bool, String> {
    if !std::path::Path::new("/usr/sbin/nft").exists() {
        return Ok(false);
    }
    let listing: serde_json::Value =
        serde_json::from_slice(&command("/usr/sbin/nft", &["-j", "list", "tables"])?)
            .map_err(|_| "Cannot inspect boot firewall")?;
    let exists = listing["nftables"]
        .as_array()
        .ok_or("Invalid firewall listing")?
        .iter()
        .any(|e| e["table"]["family"] == "inet" && e["table"]["name"] == TABLE);
    Ok(exists)
}
pub fn guard(enable: bool) -> Result<(), String> {
    let exists = active()?;
    if exists == enable {
        return Ok(());
    }
    let script = if enable {
        super::full::guard_script().replace("rtrust_full", TABLE)
    } else {
        format!("delete table inet {TABLE}\n")
    };
    super::full::nft(&script)
}
