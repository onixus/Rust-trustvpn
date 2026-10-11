package org.rtrusttunnel.android;

/** Cumulative deep sleep from Android kernel clocks, never from a delayed poll. */
final class DeepSleepObserver {
    private static final long RESUME_THRESHOLD_MS = 2000;
    private static final long MAX_SAMPLE_SPAN_MS = 50;
    private Object session;
    private boolean baseline;
    private long previousElapsed, previousUptime, previousSleepUpper;

    void start(Object token) { session = token; baseline = false; }
    void stop() { session = null; baseline = false; }

    boolean sample(Object token, long elapsed, long uptimeBefore, long uptimeAfter) {
        if (session == null || token != session) return false;
        // Bracket the elapsed-clock read: an unrelated scheduling pause between
        // clock reads must not manufacture evidence of suspend.
        if (elapsed < 0 || uptimeBefore < 0 || uptimeAfter < uptimeBefore
            || uptimeAfter - uptimeBefore > MAX_SAMPLE_SPAN_MS || elapsed < uptimeBefore) {
            baseline = false;
            return false;
        }
        // Use the new lower bound minus the old upper bound, so even a 50 ms
        // change in read skew cannot turn subthreshold sleep into an event.
        long sleptLower = Math.max(0, elapsed - uptimeAfter);
        long sleptUpper = elapsed - uptimeBefore;
        boolean resumed = baseline && elapsed >= previousElapsed && uptimeAfter >= previousUptime
            && sleptLower >= previousSleepUpper && sleptLower - previousSleepUpper >= RESUME_THRESHOLD_MS;
        previousElapsed = elapsed; previousUptime = uptimeAfter; previousSleepUpper = sleptUpper;
        baseline = true;
        return resumed;
    }
}
