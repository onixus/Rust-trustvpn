package org.rtrusttunnel.android;

/** Deterministic intent/cleanup interleavings using the production state machine. */
public final class TunnelLifecycleTest {
    private static void check(boolean value, String label) {
        if (!value) throw new AssertionError(label);
    }
    private static TunnelLifecycle.Start start(int id) {
        return new TunnelLifecycle.Start(id, "synthetic-" + id, id % 2 == 0);
    }
    public static void main(String[] args) {
        TunnelLifecycle lifecycle = new TunnelLifecycle();
        check(lifecycle.start(start(1)), "initial start owns core");
        check(lifecycle.stop(2), "stop begins cleanup");
        check(!lifecycle.start(start(3)), "START during cleanup waits");
        check(!lifecycle.start(start(4)), "pending queue is bounded to latest START");
        TunnelLifecycle.Start next = lifecycle.completeStop();
        check(next != null && next.id == 4 && next.recover
            && next.profileId.equals("synthetic-4"), "latest request executes after cleanup");
        check(!lifecycle.start(start(5)), "active START never creates second owner");
        check(lifecycle.latestId() == 5, "new active startId fences stale stopSelf");
        check(lifecycle.stop(6), "restarted session can stop");
        check(!lifecycle.start(start(7)), "queued again");
        check(!lifecycle.stop(8), "second STOP does not duplicate cleanup");
        check(lifecycle.completeStop() == null && lifecycle.latestId() == 8,
            "STOP cancels older queued START and owns stopSelfResult id");
        check(lifecycle.start(start(9)), "same instance can restart after cleanup");
        check(lifecycle.beginStop(), "failure begins terminal cleanup");
        check(!lifecycle.start(start(10)), "new request during failure waits");
        check(!lifecycle.beginStop(), "duplicate failure cleanup rejected");
        check(lifecycle.completeStop().id == 10, "failure cannot discard later start");
        check(lifecycle.stop(11), "revoke starts final stop");
        check(!lifecycle.start(start(12)), "pending before revoke");
        check(!lifecycle.stop(lifecycle.latestId()), "revoke cancels pending even during cleanup");
        check(lifecycle.completeStop() == null, "permission revoke never restarts pending");
        check(lifecycle.start(start(13)), "start before destruction");
        check(lifecycle.stop(14), "stop before destruction");
        check(!lifecycle.start(start(15)), "pending before destruction");
        lifecycle.destroy();
        check(lifecycle.completeStop() == null && !lifecycle.start(start(16)),
            "destroyed instance cannot restart from stale completion");
        for (int i = 0; i < 1000; i++) {
            TunnelLifecycle toggles = new TunnelLifecycle();
            check(toggles.start(start(1)) && toggles.stop(2), "toggle start stop");
            check(!toggles.start(start(3)) && toggles.completeStop().id == 3,
                "rapid toggle restarts once");
            check(toggles.stop(4) && toggles.completeStop() == null, "toggle ends cleanly");
        }
        System.out.println("PASS Android START/STOP lifecycle regressions");
    }
}
