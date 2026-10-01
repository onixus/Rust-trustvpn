package org.rtrusttunnel.android;

/** All configuration parsing and VPN packets use the shared Rust implementation. */
public final class NativeCore {
    public static final NativeCore INSTANCE = new NativeCore();
    static { System.loadLibrary("rtrust_android"); }
    private NativeCore() {}
    public native String parse(String raw);
    public native String export(String raw, int format);
    public native boolean start(String raw, int fd, Object protector);
    public native void stop();
    public native String status();
}
