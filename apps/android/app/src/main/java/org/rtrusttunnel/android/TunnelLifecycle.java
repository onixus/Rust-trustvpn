package org.rtrusttunnel.android;

/** Serial service intent state; one pending request, no Android or native ownership. */
final class TunnelLifecycle {
    static final class Start {
        final int id;
        final String profileId;
        final boolean recover;
        Start(int id, String profileId, boolean recover) {
            this.id = id; this.profileId = profileId; this.recover = recover;
        }
    }
    private boolean running, stopping, destroyed;
    private int latestId;
    private Start pending;

    synchronized boolean start(Start request) {
        if (destroyed) return false;
        latestId = request.id;
        if (stopping) { pending = request; return false; }
        if (running) return false;
        running = true;
        return true;
    }
    /** Records a non-request intent; true while a session or cleanup owns the service. */
    synchronized boolean acknowledgeIfBusy(int id) {
        latestId = id;
        return running || stopping || destroyed;
    }
    synchronized boolean stop(int id) {
        latestId = id;
        pending = null;
        return beginStop();
    }
    synchronized boolean beginStop() {
        if (destroyed || stopping) return false;
        stopping = true;
        return true;
    }
    synchronized Start completeStop() {
        if (destroyed) return null;
        running = false;
        stopping = false;
        Start next = pending;
        pending = null;
        if (next != null) running = true;
        return next;
    }
    synchronized int latestId() { return latestId; }
    synchronized boolean destroyed() { return destroyed; }
    synchronized void destroy() { destroyed = true; pending = null; stopping = true; }
}
