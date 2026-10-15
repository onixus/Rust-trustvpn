package org.rtrusttunnel.android;

/** Diagnostics line for reconnect recovery; plain JDK, no Android classes. */
public final class RecoveryStatusTest {
    private static void check(String actual, String expected) {
        if (!actual.equals(expected)) throw new AssertionError(actual + " != " + expected);
    }
    public static void main(String[] args) {
        check(RecoveryStatus.line(-1, 12, null, 0, false), "Recovery: no active session");
        check(RecoveryStatus.line(1, 12, null, 0, false), "Connection attempts: 1 of 12");
        check(RecoveryStatus.line(2, 12, "wake_check_failed", 42, false),
            "Connection attempts: 2 of 12 · last end: no answer after sleep, 42 s ago");
        check(RecoveryStatus.line(12, 12, "connect_failed", 600, true),
            "Попытки подключения: 12 из 12 · последний обрыв: не удалось подключиться, 10 мин назад");
        check(RecoveryStatus.line(1, 12, "replaced", 7200, true),
            "Попытки подключения: 1 из 12 · последний обрыв: смена сети или перезапуск, 2 ч назад");
        check(RecoveryStatus.line(1, 12, "future_reason", -5, false),
            "Connection attempts: 1 of 12 · last end: unknown, 0 s ago");
        System.out.println("PASS Android recovery-status diagnostics line");
    }
}
