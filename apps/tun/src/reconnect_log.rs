//! Last ten transport reconnects.
//!
//! The ordinary journal drops an error after 60 minutes, so a later look at the
//! machine cannot tell why a tunnel that is already back up reconnected. These
//! lines go through the same writer and the same protected directory, marked
//! `keep=reconnect` so age pruning leaves them alone. After each one the writer
//! drops every such line but the ten newest. A line never carries an address,
//! hostname, credential or free-form error text.
use std::time::{SystemTime, UNIX_EPOCH};

const MARK: &str = "keep=reconnect";
const MAX_LINE: usize = 512;

/// `head` is one of the existing fixed event names. `fields` is the closed
/// `key=value` tail from [`crate::reason`], never a Display string.
///
/// Returns immediately. The service journal writer does the disk work, so a
/// slow disk cannot stall the reconnect loop. A rejected or dropped line is
/// lost; reconnect itself is unaffected.
pub fn record(head: &str, fields: &str) {
    let Ok(line) = line(head, fields) else {
        return;
    };
    #[cfg(not(test))]
    rtrust_journal::service().reconnect(line);
    #[cfg(test)]
    let _ = line;
}

fn line(head: &str, fields: &str) -> Result<String, ()> {
    if !closed_head(head) || !closed_fields(fields) {
        return Err(());
    }
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let line = format!(
        "{time} pid={} level=error {MARK} {head} {fields}\n",
        std::process::id()
    );
    if line.len() > MAX_LINE {
        return Err(());
    }
    Ok(line)
}

fn closed_token(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// A fixed event name. Spaces are allowed (`VPN transport stopped`); anything
/// else, including punctuation that could carry an address, is not.
fn closed_head(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ' ')
        && !value.starts_with(' ')
        && !value.ends_with(' ')
        && !value.contains("  ")
}

/// `key=value` pairs separated by one space. Values stay in the reason-token
/// alphabet, so an address or a path cannot be smuggled in.
fn closed_fields(fields: &str) -> bool {
    !fields.is_empty()
        && fields.split(' ').all(|token| {
            let Some((key, value)) = token.split_once('=') else {
                return false;
            };
            closed_token(key) && !value.is_empty() && closed_token(value)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_text_and_addresses_are_refused() {
        assert!(
            line(
                "VPN transport stopped",
                "reason=idle_timeout transport=h3 uptime_ms=4"
            )
            .is_ok()
        );
        assert!(line("VPN transport stopped", "reason=connect to 192.0.2.1").is_err());
        assert!(line("stopped: vpn.example", "reason=ended").is_err());
        assert!(line("VPN transport stopped", "").is_err());
    }
}
