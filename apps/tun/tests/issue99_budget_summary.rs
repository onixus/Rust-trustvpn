//! Independent tester coverage for issue #99 at the service boundary: an
//! unproven degraded exit (verdict B) never restores the reconnect budget,
//! and `dataplane_summary` stays `key=number` with the established prefix.
#![cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
use rtrust_control::recovery::{BURST_ATTEMPTS, Budget, COOLDOWN, STABLE_CONNECTION};
use std::time::Duration;

type Exit = Result<(), Box<dyn std::error::Error + Send + Sync>>;
fn degraded(proven: bool) -> Exit {
    Err(rtrust_engine::Error::Degraded { proven }.into())
}

#[test]
fn repeated_unproven_degraded_sessions_reach_the_cooldown() {
    let exit = degraded(false);
    assert!(rtrust_tun::unproven(&exit));
    assert_eq!(rtrust_tun::degraded(&exit), Some(false));
    let mut budget = Budget::default();
    let mut delays = Vec::new();
    // Each reconnect lives long (an hour) but ends unproven-degraded again.
    for _ in 0..=BURST_ATTEMPTS {
        budget.disconnected(Duration::from_secs(3600), rtrust_tun::unproven(&exit));
        delays.push(budget.next_delay(0));
    }
    let (burst, last) = delays.split_at(BURST_ATTEMPTS as usize);
    assert!(burst.iter().all(|d| *d < COOLDOWN), "{burst:?}");
    assert!(last[0] >= COOLDOWN, "{last:?}");
    assert!(budget.cooling());
    // The same series with a proven exit restores the budget every time.
    let mut proven = Budget::default();
    for _ in 0..=BURST_ATTEMPTS * 2 {
        proven.disconnected(STABLE_CONNECTION, rtrust_tun::unproven(&degraded(true)));
        assert!(proven.next_delay(0) < COOLDOWN);
    }
}

#[test]
fn other_engine_errors_are_not_degraded() {
    for error in [
        rtrust_engine::Error::Credit,
        rtrust_engine::Error::Timeout,
        rtrust_engine::Error::Protocol,
    ] {
        let exit: Exit = Err(error.into());
        assert_eq!(rtrust_tun::degraded(&exit), None);
        assert!(!rtrust_tun::unproven(&exit));
    }
}

#[test]
fn live_summary_is_numeric_with_the_established_prefix() {
    let base = rtrust_tun::stats::snapshot();
    let line = rtrust_tun::stats::snapshot().since(&base).render();
    let keys: Vec<_> = line
        .split(' ')
        .map(|token| {
            let (key, value) = token.split_once('=').expect(token);
            assert!(
                !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
                "{token}"
            );
            key
        })
        .collect();
    assert_eq!(
        keys,
        [
            "syn_accepted",
            "syn_refused",
            "handshake_reset",
            "handshake_timeout",
            "backlog_discarded",
            "udp_evicted",
            "tcp_opened",
            "tcp_answered",
            "tcp_quiet",
            "tcp_open_failed",
            "credit_timeout"
        ]
    );
    assert!(!line.contains(':') && !line.contains('.') && !line.contains('['));
}
