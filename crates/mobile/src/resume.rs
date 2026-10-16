//! Check a connected transport as soon as the device wakes from deep sleep.
//! Monotonic timers stop while suspended, so without this the periodic health
//! check, idle timeouts and liveness windows only notice a transport that died
//! during sleep long after the user is back.
use std::{future::Future, time::Duration};
use tokio::sync::Notify;

/// A wake check answers within this bound or the transport is replaced.
/// Below the 10 s periodic health bound: the dead case is the common one here.
pub const CHECK_TIMEOUT: Duration = Duration::from_secs(6);

/// Wakes reported by the OS adapter. Only a session already waiting is woken:
/// a wake before it connected says nothing about it.
#[derive(Default)]
pub struct Wakes(Notify);
impl Wakes {
    pub fn notify(&self) {
        self.0.notify_waiters();
    }
}

/// Resolves only when a check started at a wake fails or times out; never
/// while the transport answers. Dropping it cancels a check in progress.
pub async fn watch<E, F, Fut>(
    wakes: &Wakes,
    bound: Duration,
    mut check: F,
    timed_out: fn() -> E,
) -> E
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<(), E>>,
{
    loop {
        wakes.0.notified().await;
        match tokio::time::timeout(bound, check()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return error,
            Err(_) => return timed_out(),
        }
    }
}

/// Wait `delay` of real time, suspend included. `now` reads a clock that keeps
/// counting while suspended (CLOCK_BOOTTIME on Android); the monotonic timer
/// does not, so a backoff begun before sleep would otherwise still run on
/// after wake. Each wake re-reads `now`; the timer finishing alone is enough,
/// because real time never advances slower than the monotonic clock.
pub async fn sleep_real(wakes: &Wakes, delay: Duration, now: impl Fn() -> Duration) {
    let deadline = now().saturating_add(delay);
    loop {
        let remaining = deadline.saturating_sub(now());
        if remaining.is_zero() {
            return;
        }
        tokio::select! {
            _ = tokio::time::sleep(remaining) => return,
            _ = wakes.0.notified() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    };

    async fn settle() {
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn healthy_transport_is_kept_and_dead_one_is_reported_at_wake() {
        let wakes = Arc::new(Wakes::default());
        let checks = Arc::new(AtomicU32::new(0));
        let (w, c) = (wakes.clone(), checks.clone());
        let watcher = tokio::spawn(async move {
            watch(
                &w,
                CHECK_TIMEOUT,
                || {
                    let n = c.fetch_add(1, Ordering::SeqCst);
                    async move { if n == 0 { Ok(()) } else { Err("dead") } }
                },
                || "timeout",
            )
            .await
        });
        settle().await;
        assert_eq!(checks.load(Ordering::SeqCst), 0, "no check without a wake");
        wakes.notify();
        settle().await;
        assert_eq!(checks.load(Ordering::SeqCst), 1);
        assert!(!watcher.is_finished(), "an answering transport is kept");
        wakes.notify();
        assert_eq!(watcher.await.unwrap(), "dead");
    }

    #[tokio::test(start_paused = true)]
    async fn silent_transport_times_out_within_bound() {
        let wakes = Arc::new(Wakes::default());
        let w = wakes.clone();
        let watcher = tokio::spawn(async move {
            watch(
                &w,
                CHECK_TIMEOUT,
                std::future::pending::<Result<(), &str>>,
                || "timeout",
            )
            .await
        });
        settle().await;
        wakes.notify();
        let started = tokio::time::Instant::now();
        assert_eq!(watcher.await.unwrap(), "timeout");
        assert_eq!(started.elapsed(), CHECK_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn backoff_spanning_sleep_ends_at_wake() {
        let wakes = Arc::new(Wakes::default());
        // Real-time clock in seconds; the paused monotonic clock stays put
        // while "suspended", as on a sleeping device.
        let real = Arc::new(AtomicU32::new(1000));
        let (w, r) = (wakes.clone(), real.clone());
        let waiter = tokio::spawn(async move {
            sleep_real(&w, Duration::from_secs(48), || {
                Duration::from_secs(r.load(Ordering::SeqCst).into())
            })
            .await
        });
        settle().await;
        tokio::time::sleep(Duration::from_secs(5)).await;
        real.fetch_add(5, Ordering::SeqCst);
        wakes.notify();
        settle().await;
        assert!(!waiter.is_finished(), "wake inside the delay keeps waiting");
        real.fetch_add(600, Ordering::SeqCst);
        wakes.notify();
        let started = tokio::time::Instant::now();
        waiter.await.unwrap();
        assert_eq!(
            started.elapsed(),
            Duration::ZERO,
            "no further wait after sleep"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn backoff_without_sleep_takes_its_full_delay() {
        let wakes = Wakes::default();
        let started = tokio::time::Instant::now();
        sleep_real(&wakes, Duration::from_secs(48), || started.elapsed()).await;
        assert_eq!(started.elapsed(), Duration::from_secs(48));
    }

    #[tokio::test(start_paused = true)]
    async fn wake_before_watching_is_not_carried_over() {
        let wakes = Arc::new(Wakes::default());
        wakes.notify();
        let w = wakes.clone();
        let watcher = tokio::spawn(async move {
            watch(
                &w,
                CHECK_TIMEOUT,
                || async { Err::<(), _>("dead") },
                || "timeout",
            )
            .await
        });
        settle().await;
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert!(!watcher.is_finished());
        watcher.abort();
    }
}
