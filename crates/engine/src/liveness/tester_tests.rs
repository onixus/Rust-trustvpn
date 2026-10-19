//! Independent tester coverage for verdict B (issue #99): exact thresholds at
//! the session level, the grace boundary, long polls, mixed address families,
//! neutral errors, concurrency and bounded memory. Synthetic targets only.
use super::*;
use crate::Error;

fn ms(v: u64) -> Duration {
    Duration::from_millis(v)
}
fn s(v: u64) -> Duration {
    Duration::from_secs(v)
}
fn named(i: u32) -> String {
    format!("q{i}.example.invalid:443")
}
/// `n` targets whose keyed host buckets are distinct and not in `taken`.
fn distinct(l: &Liveness, n: usize, taken: &mut u64, make: impl Fn(u32) -> String) -> Vec<String> {
    let mut out = Vec::new();
    for i in 1..100_000 {
        let target = make(i);
        let bit = l.host(&target);
        if *taken & bit == 0 {
            *taken |= bit;
            out.push(target);
            if out.len() == n {
                return out;
            }
        }
    }
    panic!("not enough host buckets for {n}")
}
fn quiet_flow(l: &Liveness, target: &str, t: Duration) -> Watch {
    let mut watch = l.watch(target);
    l.wrote_at(&mut watch, t);
    watch
}
fn answered_flow(l: &Liveness, target: &str, wrote: Duration) {
    let mut watch = quiet_flow(l, target, wrote);
    l.inbound();
    l.read(&mut watch);
}
fn quiet_set(l: &Liveness, n: usize, hosts: &[String], t: Duration) {
    for i in 0..n {
        quiet_flow(l, &hosts[i % hosts.len()], t);
    }
}

#[test]
fn count_boundary_is_exactly_24_at_exactly_six_hosts() {
    for (n, expected) in [(23, None), (24, Some(false))] {
        let l = Liveness::new(SILENCE);
        let six = distinct(&l, 6, &mut 0, named);
        quiet_set(&l, n, &six, ms(100));
        // Slot 0 is immature until 15 s (5 s slot + 10 s grace).
        assert_eq!(l.degraded_at(ms(14_999)), None, "{n} immature");
        assert_eq!(l.degraded_at(s(15)), expected, "{n}");
    }
}

#[test]
fn host_boundary_is_exactly_six() {
    for (hosts, expected) in [(5, None), (6, Some(false))] {
        let l = Liveness::new(SILENCE);
        let targets = distinct(&l, hosts, &mut 0, named);
        quiet_set(&l, 60, &targets, s(1));
        assert_eq!(l.degraded_at(s(16)), expected, "{hosts} hosts");
    }
}

#[test]
fn share_boundary_is_exactly_80_percent_at_the_session_level() {
    // (quiet, answered): 24/30 = 80%, 24/31 = 77%, 32/40 = 80%, 30/38 = 79%.
    for (quiet, answered, expected) in [
        (24, 6, Some(false)),
        (24, 7, None),
        (32, 8, Some(false)),
        (30, 8, None),
    ] {
        let l = Liveness::new(SILENCE);
        let mut taken = 0;
        let silent = distinct(&l, 6, &mut taken, named);
        let live = distinct(&l, 8, &mut taken, |i| {
            format!("live{i}.example.invalid:443")
        });
        quiet_set(&l, quiet, &silent, s(1));
        for i in 0..answered {
            answered_flow(&l, &live[i % live.len()], s(2));
        }
        assert_eq!(l.degraded_at(s(16)), expected, "{quiet}/{answered}");
    }
}

#[test]
fn an_answer_from_a_quiet_host_removes_that_host_from_the_spread() {
    // Documented behaviour: hosts count only when no flow to them answered.
    let l = Liveness::new(SILENCE);
    let six = distinct(&l, 6, &mut 0, named);
    quiet_set(&l, 40, &six, s(1));
    assert_eq!(l.degraded_at(s(16)), Some(false));
    answered_flow(&l, &six[0], s(2));
    assert_eq!(l.quiet_at(s(16)).hosts, 5);
    assert_eq!(l.degraded_at(s(16)), None);
}

#[test]
fn an_answer_within_9_s_is_never_quiet_whatever_the_slot_phase() {
    for wrote in [ms(0), ms(2_500), ms(4_999)] {
        let l = Liveness::new(SILENCE);
        let six = distinct(&l, 6, &mut 0, named);
        let mut flows: Vec<_> = (0..30)
            .map(|i| quiet_flow(&l, &six[i % 6], wrote))
            .collect();
        let answer = wrote + s(9);
        let mut t = wrote;
        while t <= s(90) {
            if t >= answer {
                flows.iter_mut().for_each(|w| l.read(w));
            }
            assert_eq!(l.degraded_at(t), None, "wrote {wrote:?} at {t:?}");
            t += ms(100);
        }
    }
}

#[test]
fn an_answer_after_11_s_counts_only_when_the_slot_matured_first() {
    // Written at the start of slot 0: it matures at 15 s, after the answer.
    let l = Liveness::new(SILENCE);
    let six = distinct(&l, 6, &mut 0, named);
    let mut flows: Vec<_> = (0..30)
        .map(|i| quiet_flow(&l, &six[i % 6], ms(0)))
        .collect();
    // `read` is dated by the write's slot only, so any answer before 15 s
    // (here 11 s after the write) is counted as answered.
    flows.iter_mut().for_each(|w| l.read(w));
    assert_eq!(l.degraded_at(s(15)), None);
    // Written late in slot 0 and answered 11 s later (15.9 s): judged quiet
    // from 15 s until the answers arrive. Effective grace is 10 to 15 s.
    let l = Liveness::new(SILENCE);
    let six = distinct(&l, 6, &mut 0, named);
    let mut flows: Vec<_> = (0..30)
        .map(|i| quiet_flow(&l, &six[i % 6], ms(4_900)))
        .collect();
    assert_eq!(l.degraded_at(ms(14_999)), None);
    assert_eq!(l.degraded_at(s(15)), Some(false));
    flows.iter_mut().for_each(|w| l.read(w));
    assert_eq!(l.degraded_at(ms(15_900)), None);
}

#[test]
fn long_polls_answered_at_tls_then_idle_are_healthy() {
    let l = Liveness::new(SILENCE);
    let hosts = distinct(&l, 20, &mut 0, named);
    let mut flows = Vec::new();
    for i in 0..60u64 {
        let t = ms(i * 150);
        let mut w = quiet_flow(&l, &hosts[i as usize % 20], t);
        l.inbound();
        l.read(&mut w);
        flows.push(w);
    }
    // Two minutes of requests on the same flows, no answer: later writes do
    // not re-arm a flow, and nothing new opens.
    for t in (10..130).map(s) {
        for w in &mut flows {
            l.wrote_at(w, t);
            assert_eq!(*w, Watch::Off);
        }
        assert_eq!(l.degraded_at(t), None, "{t:?}");
    }
}

#[test]
fn plain_http_long_polls_answered_after_30_s_are_judged_quiet_meanwhile() {
    // Limitation, not a defect: 24+ port-80 long polls over 6+ hosts that a
    // server answers only after the grace look like #99 until answered.
    let l = Liveness::new(SILENCE);
    let six = distinct(&l, 6, &mut 0, |i| format!("poll{i}.example.invalid:80"));
    let mut flows: Vec<_> = (0..24).map(|i| quiet_flow(&l, &six[i % 6], s(1))).collect();
    assert_eq!(l.degraded_at(s(15)), Some(false));
    flows.iter_mut().for_each(|w| l.read(w));
    assert_eq!(l.degraded_at(s(30)), None);
}

#[test]
fn mixed_ipv4_and_ipv6_hosts_are_counted_by_host_not_family_or_port() {
    let l = Liveness::new(SILENCE);
    let mut taken = 0;
    let v4 = distinct(&l, 3, &mut taken, |i| {
        format!("192.0.2.{}:443", i % 254 + 1)
    });
    let v6 = distinct(&l, 3, &mut taken, |i| format!("[2001:db8::{i:x}]:443"));
    assert_eq!(l.host("[2001:db8::1]:443"), l.host("[2001:db8::1]:8443"));
    assert_eq!(l.host("192.0.2.1:443"), l.host("192.0.2.1:80"));
    assert!(answers_first("[2001:db8::1]:853"));
    assert!(!answers_first("[2001:db8::1]"));
    assert!(!answers_first("2001:db8::1"));
    assert!(!answers_first("[2001:db8::1]:4430"));
    for i in 0..12 {
        quiet_flow(&l, &v4[i % 3], s(1));
        quiet_flow(&l, &v6[i % 3], s(1));
    }
    assert_eq!(l.quiet_at(s(16)).hosts, 6);
    assert_eq!(l.degraded_at(s(16)), Some(false));
    // The same 24 flows to three v4 hosts and their v6 ports: three hosts.
    let l = Liveness::new(SILENCE);
    let v6 = distinct(&l, 3, &mut 0, |i| format!("[2001:db8::{i:x}]:443"));
    for i in 0..24 {
        let target = &v6[i % 3];
        let other = target.replace("]:443", "]:8443");
        quiet_flow(&l, if i % 2 == 0 { target } else { &other }, s(1));
    }
    assert_eq!(l.degraded_at(s(16)), None);
}

#[test]
fn neutral_errors_on_watched_ports_never_feed_verdict_b() {
    for error in [
        Error::Rejected(403),
        Error::Rejected(502),
        Error::Authentication,
        Error::Destination,
        Error::Unsupported("x"),
        Error::Protocol,
        Error::Io,
    ] {
        let l = Liveness::new(SILENCE);
        let hosts = distinct(&l, 10, &mut 0, named);
        for i in 0..40 {
            l.opened_at(&Err(error.clone()), &hosts[i % 10], s(1), s(1));
        }
        assert_eq!(l.quiet_at(s(16)), Quiet::default(), "{error:?}");
    }
    for error in [Error::Timeout, Error::Credit] {
        let l = Liveness::new(SILENCE);
        let hosts = distinct(&l, 6, &mut 0, named);
        for i in 0..24 {
            l.opened_at(&Err(error.clone()), &hosts[i % 6], s(1), s(1));
        }
        assert_eq!(l.quiet_at(s(16)).failed, 24, "{error:?}");
        // Before verdict A's silence period: B alone, unproven.
        assert_eq!(l.degraded_at(s(16)), Some(false), "{error:?}");
        // On an unwatched port neither is counted by B.
        let l = Liveness::new(SILENCE);
        for i in 0..24 {
            l.opened_at(
                &Err(error.clone()),
                &format!("q{i}.example.invalid:6881"),
                s(1),
                s(1),
            );
        }
        assert_eq!(l.quiet_at(s(16)).failed, 0);
    }
}

#[test]
fn unwritten_flows_and_udp_only_traffic_leave_no_evidence() {
    let l = Liveness::new(SILENCE);
    let hosts = distinct(&l, 10, &mut 0, named);
    for i in 0..100 {
        // Dropped before any write: `closed` sees `Fresh`.
        let watch = l.watch(&hosts[i % 10]);
        assert!(matches!(watch, Watch::Fresh(_)));
        closed(watch);
    }
    for t in (0..120).map(s) {
        // Shared UDP relay: traffic both ways, no per-flow report.
        l.outbound();
        l.inbound();
        assert_eq!(l.quiet_at(t), Quiet::default());
        assert_eq!(l.degraded_at(t), None);
    }
}

#[test]
fn verdict_b_persists_while_quiet_and_clears_once_answers_dominate() {
    let l = Liveness::new(SILENCE);
    let mut taken = 0;
    let silent = distinct(&l, 8, &mut taken, named);
    let live = distinct(&l, 8, &mut taken, |i| {
        format!("live{i}.example.invalid:443")
    });
    quiet_set(&l, 30, &silent, s(1));
    for t in 15..20 {
        assert_eq!(l.degraded_at(s(t)), Some(false));
    }
    // Answered traffic resumes on other hosts; the share falls below 80%.
    let mut cleared = None;
    for t in 20..90u64 {
        answered_flow(&l, &live[t as usize % 8], s(t));
        if cleared.is_none() && l.degraded_at(s(t)).is_none() {
            cleared = Some(t);
        }
        if let Some(c) = cleared {
            assert_eq!(l.degraded_at(s(t)), None, "relapsed at {t} after {c}");
        }
    }
    assert!(cleared.is_some_and(|t| t <= 40), "{cleared:?}");
}

#[test]
fn path_a_with_delivery_wins_over_b_and_stays_proven() {
    let l = Liveness::new(SILENCE);
    let mut taken = 0;
    let six = distinct(&l, 6, &mut taken, named);
    let live = distinct(&l, 1, &mut taken, |i| {
        format!("live{i}.example.invalid:443")
    });
    answered_flow(&l, &live[0], s(0));
    for i in 0..24 {
        l.opened_at(&Ok(()), &six[i % 6], s(1), s(1));
        quiet_flow(&l, &six[i % 6], s(1));
    }
    assert_eq!(l.verdict_at(s(16)), Verdict::Quiet);
    assert_eq!(l.degraded_at(s(16)), Some(false));
    // No inbound at all for the silence period: verdict A, proven.
    assert_eq!(l.verdict_at(s(21)), Verdict::Degraded);
    assert_eq!(l.degraded_at(s(21)), Some(true));
}

#[test]
fn concurrent_flows_and_judging_stay_bounded_and_consistent() {
    let l = Liveness::new(SILENCE);
    let hosts: Vec<_> = (0..200).map(named).collect();
    let writes = std::sync::atomic::AtomicU64::new(0);
    std::thread::scope(|scope| {
        for thread in 0..8u64 {
            let (l, hosts, writes) = (&l, &hosts, &writes);
            scope.spawn(move || {
                for i in 0..20_000u64 {
                    // Jittered, partly out-of-order clock over ~1000 s:
                    // forces ring recycling and late events.
                    let t = ms((i * 50 + thread * 3_000) % 1_000_000);
                    let target = &hosts[((i * 7 + thread) % 200) as usize];
                    match i % 5 {
                        0 => l.opened_at(&Err(Error::Timeout), target, t, t),
                        1 => l.opened_at(&Err(Error::Credit), target, t, t),
                        _ => {
                            let mut w = l.watch(target);
                            writes.fetch_add(1, Relaxed);
                            l.wrote_at(&mut w, t);
                            if i % 3 == 0 {
                                l.read(&mut w);
                            }
                            closed(w);
                        }
                    }
                }
            });
        }
        let (l, writes) = (&l, &writes);
        scope.spawn(move || {
            for i in 0..20_000u64 {
                let q = l.quiet_at(ms(i * 50));
                assert!(q.answered <= q.wrote, "{q:?}");
                assert!(q.hosts <= 64);
                assert!(u64::from(q.wrote) <= writes.load(Relaxed));
                let _ = l.degraded_at(ms(i * 50));
            }
        });
    });
    for t in (0..1_100).map(s) {
        let q = l.quiet_at(t);
        assert!(q.answered <= q.wrote && q.hosts <= 64, "{q:?}");
    }
}

#[test]
fn state_is_fixed_size_whatever_the_flow_count() {
    // No per-flow or per-destination storage: the ring and sets are fixed.
    assert!(std::mem::size_of::<Liveness>() <= 2048);
    let l = Liveness::new(SILENCE);
    for i in 0..200_000u64 {
        let t = ms(i * 20);
        quiet_flow(&l, &named((i % 5_000) as u32), t);
    }
    // Only the last 12 mature slots are judged: 250 writes per 5 s slot.
    let q = l.quiet_at(ms(200_000 * 20));
    assert!(q.wrote <= 12 * 250, "{q:?}");
}

#[test]
fn a_new_session_starts_clean_after_a_degraded_one() {
    let old = Liveness::new(SILENCE);
    let six = distinct(&old, 6, &mut 0, named);
    quiet_set(&old, 40, &six, s(1));
    assert_eq!(old.degraded_at(s(16)), Some(false));
    let new = Liveness::new(SILENCE);
    for t in (0..90).map(s) {
        assert_eq!(new.degraded_at(t), None);
    }
    // Keys are per session: the same target maps independently.
    let distinct_keys = (0..64)
        .map(named)
        .filter(|t| old.host(t) != new.host(t))
        .count();
    assert!(distinct_keys > 0);
}
