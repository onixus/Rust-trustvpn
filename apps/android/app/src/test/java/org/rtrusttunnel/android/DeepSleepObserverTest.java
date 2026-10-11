package org.rtrusttunnel.android;

/** Plain Java regression: no device, Android runtime, sleeps or network effects. */
public final class DeepSleepObserverTest {
    private static void check(boolean value, String label) {
        if (!value) throw new AssertionError(label);
    }
    public static void main(String[] args) {
        DeepSleepObserver observer = new DeepSleepObserver();
        Object old = new Object(), current = new Object();
        check(!observer.sample(old, 5000, 1000, 1000), "inactive");
        observer.start(old);
        check(!observer.sample(old, 5000, 1000, 1000), "first sample is baseline");
        check(!observer.sample(old, 65000, 61000, 61000), "long awake polling gap");
        check(!observer.sample(old, 66000, 61500, 61500), "subthreshold sleep");
        check(observer.sample(old, 69000, 62500, 62500), "two seconds kernel deep sleep");
        check(!observer.sample(old, 69001, 62501, 62501), "reported once");
        check(!observer.sample(old, 1, 0, 0), "clock reversal resets baseline");
        check(observer.sample(old, 3001, 1000, 1000), "new clock baseline");
        check(!observer.sample(old, 6001, 2000, 2100), "skewed sample ignored");
        check(!observer.sample(old, 7001, 3000, 3000), "baseline after skew");
        check(!observer.sample(old, 9001, 5000, 4000), "uptime reversal ignored");
        check(!observer.sample(old, 9001, 9100, 9100), "invalid clock difference ignored");
        observer.stop();
        check(!observer.sample(old, 20001, 5000, 5000), "stopped observer");
        observer.start(current);
        check(!observer.sample(old, 20001, 5000, 5000), "old session cannot mutate baseline");
        check(!observer.sample(current, 20001, 5000, 5000), "new session baseline");
        check(observer.sample(current, 23001, 6000, 6000), "new session resume");
        Object skewed = new Object();
        observer.start(skewed);
        check(!observer.sample(skewed, 1000, 1000, 1001), "no sleep with one ms read skew is baseline");
        check(observer.sample(skewed, 4001, 2001, 2001), "first deep sleep after skewed awake baseline");
        observer.start(skewed);
        check(!observer.sample(skewed, 5000, 1000, 1050), "fifty ms bracket baseline");
        check(!observer.sample(skewed, 7999, 2000, 2000), "read skew cannot inflate 1999 ms sleep");
        System.out.println("PASS Android deep-sleep clock and session regressions");
    }
}
