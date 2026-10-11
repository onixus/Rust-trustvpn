package org.rtrusttunnel.android;

/** All configuration parsing and VPN packets use the shared Rust implementation. */
public final class NativeCore {
    public static final NativeCore INSTANCE = new NativeCore();
    static { System.loadLibrary("rtrust_android"); }
    private NativeCore() {}
    public native String parse(String raw);
    public native String export(String raw, int format);
    public native String plan(String raw);
    public native boolean start(String raw, int fd, Object protector);
    public native void stop();
    /** OS-selected underlying network changed; no address/name crosses JNI. */
    public native void networkChanged();
    /** Kernel clocks report deep sleep while this native session is active. */
    public native void resumed();
    /** Redacted local flow decisions; 0 identity, 1 enable, 2 disable, 3 poll. */
    public native String flowCapture(long session, long capture, int operation);
    public native String status();
    public native String flowPolicy(String request);
}
