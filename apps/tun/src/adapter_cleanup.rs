//! Bounded recovery for a device whose PnP identity can appear asynchronously.
use std::time::{Duration, Instant};

pub(crate) fn remove_until_absent(
    mut remove: impl FnMut() -> Result<String, String>,
    mut absent: impl FnMut() -> Result<(), String>,
    timeout: Duration,
    interval: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        // A successful enumeration with no match is not proof of removal: the
        // driver registry key may be temporarily unavailable during PnP changes.
        // A removal error on a device already being torn down is retried until
        // the deadline; the interface table is never consulted after a failed
        // removal, so protection is retained if it keeps failing.
        let failure = match remove() {
            Err(error) => error,
            Ok(attempt) => match absent() {
                Ok(()) => return Ok(()),
                // The PnP summary distinguishes "no matching device" from
                // "removed but still listed" on the next field failure.
                Err(reason) => format!(
                    "Wintun adapter removal is still pending: {reason}; last removal: {attempt}"
                ),
            },
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(failure);
        }
        std::thread::sleep(interval.min(remaining));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn retries_removal_when_identity_becomes_available_later() {
        let attempts = Cell::new(0);
        remove_until_absent(
            || {
                attempts.set(attempts.get() + 1);
                Ok(String::new())
            },
            || {
                if attempts.get() >= 3 {
                    Ok(())
                } else {
                    Err("interface still present".into())
                }
            },
            Duration::from_secs(1),
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(attempts.get(), 3);
    }

    #[test]
    fn removal_success_does_not_override_a_present_or_unreadable_interface() {
        for reason in [
            "foreign adapter still present",
            "Cannot inspect network interfaces",
        ] {
            let error = remove_until_absent(
                || Ok("matched 0".into()),
                || Err(reason.into()),
                Duration::ZERO,
                Duration::ZERO,
            )
            .unwrap_err();
            assert!(error.contains(reason));
            assert!(error.contains("last removal: matched 0"));
        }
    }

    #[test]
    fn transient_deletion_error_is_retried_before_the_deadline() {
        let attempts = Cell::new(0);
        remove_until_absent(
            || {
                attempts.set(attempts.get() + 1);
                if attempts.get() == 1 {
                    Err("Cannot remove owned Wintun device (13)".into())
                } else {
                    Ok("matched 1".into())
                }
            },
            || Ok(()),
            Duration::from_secs(1),
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(attempts.get(), 2);
    }

    #[test]
    fn deletion_error_is_not_hidden_by_an_empty_interface_table() {
        let result = remove_until_absent(
            || Err("Access denied".into()),
            || Ok(()),
            Duration::ZERO,
            Duration::ZERO,
        );
        assert_eq!(result, Err("Access denied".into()));
    }
}
