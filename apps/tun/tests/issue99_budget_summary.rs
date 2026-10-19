//! Independent tester coverage for issue #99 at the service boundary: an
//! unproven degraded exit (verdict B) never restores the reconnect budget,
//! and `dataplane_summary` stays `key=number` with the established prefix.
#![cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
use rtrust_control::recovery::{BURST_ATTEMPTS, Budget, COOLDOWN, STABLE_CONNECTION};
use std::time::Duration;

type Exit = Result<(), Box<dyn std::error::Error + Send + Sync>>;
fn degraded(proven: bool) -> Exit {
    Err(rtrust_engine::Error::Degraded {
        proven,
        kind: rtrust_engine::Stall::Quiet,
    }
    .into())
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

fn stalled(proven: bool, kind: rtrust_engine::Stall) -> Exit {
    Err(rtrust_engine::Error::Degraded { proven, kind }.into())
}

#[test]
fn degraded_event_line_is_two_fixed_tokens() {
    use rtrust_engine::Stall;
    for (proven, kind, line) in [
        (
            false,
            Stall::Quiet,
            "transport_degraded proven=false kind=quiet",
        ),
        (
            true,
            Stall::Quiet,
            "transport_degraded proven=true kind=quiet",
        ),
        (
            false,
            Stall::Silent,
            "transport_degraded proven=false kind=silent",
        ),
        (
            true,
            Stall::Silent,
            "transport_degraded proven=true kind=silent",
        ),
    ] {
        let exit = stalled(proven, kind);
        let (p, k) = rtrust_tun::degraded_kind(&exit).unwrap();
        assert_eq!((p, k), (proven, kind));
        assert_eq!(rtrust_tun::degraded_event(p, k), line);
        assert_eq!(rtrust_tun::unproven(&exit), !proven);
    }
    let other: Exit = Err(rtrust_engine::Error::Credit.into());
    assert_eq!(rtrust_tun::degraded_kind(&other), None);
}

/// F1 residual risk, quantified: a session that ends `Degraded{proven: true,
/// kind: Quiet}` at its earliest possible proven verdict (75 s) restores the
/// budget every time, so reconnects never reach the cooldown. Compares an
/// hour of such cycles with the same cycles ending unproven.
#[test]
fn proven_quiet_cycles_never_cool_down_but_are_bounded_by_session_length() {
    let session = Duration::from_secs(75);
    let hour = |proven: bool| {
        let exit = stalled(proven, rtrust_engine::Stall::Quiet);
        let mut budget = Budget::default();
        let (mut clock, mut reconnects, mut cooled) = (Duration::ZERO, 0, false);
        while clock < Duration::from_secs(3600) {
            clock += session;
            budget.disconnected(session, rtrust_tun::unproven(&exit));
            let delay = budget.next_delay(u64::MAX);
            cooled |= budget.cooling();
            clock += delay;
            reconnects += 1;
        }
        (reconnects, cooled)
    };
    let (proven, proven_cooled) = hour(true);
    let (unproven, unproven_cooled) = hour(false);
    assert!(!proven_cooled && unproven_cooled);
    // Proven: one reconnect per 75 s + at most 2.5 s, about 46 an hour.
    assert!((45..=48).contains(&proven), "{proven}");
    // Unproven: bursts of 8 then a 300-330 s cooldown, far fewer.
    assert!(unproven < proven && unproven <= 30, "{unproven}");
    println!("reconnects/hour proven={proven} unproven={unproven}");
}
