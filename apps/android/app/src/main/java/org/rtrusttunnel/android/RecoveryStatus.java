package org.rtrusttunnel.android;

/** One diagnostics line about reconnect recovery: budget use and the coarse cause
 *  and age of the last connection end. No endpoint, address or error text. */
final class RecoveryStatus {
    private RecoveryStatus() {}

    /** {@code attempts < 0}: no recovery session; {@code reason == null}: no end yet. */
    static String line(int attempts, int limit, String reason, long ageSeconds, boolean ru) {
        if (attempts < 0) return ru ? "Восстановление: нет активной сессии" : "Recovery: no active session";
        StringBuilder out = new StringBuilder(ru ? "Попытки подключения: " : "Connection attempts: ")
            .append(attempts).append(ru ? " из " : " of ").append(limit);
        if (reason == null) return out.toString();
        out.append(ru ? " · последний обрыв: " : " · last end: ").append(cause(reason, ru))
            .append(", ").append(age(Math.max(0, ageSeconds), ru));
        return out.toString();
    }
    private static String cause(String reason, boolean ru) {
        switch (reason) {
            case "replaced": return ru ? "смена сети или перезапуск" : "network change or restart";
            case "wake_check_failed": return ru ? "не ответил после сна" : "no answer after sleep";
            case "degraded": return ru ? "трафик перестал проходить" : "traffic stopped passing";
            case "transport_lost": return ru ? "транспорт разорван" : "transport lost";
            case "connect_failed": return ru ? "не удалось подключиться" : "connection failed";
            default: return ru ? "неизвестно" : "unknown";
        }
    }
    private static String age(long seconds, boolean ru) {
        if (seconds < 120) return seconds + (ru ? " с назад" : " s ago");
        if (seconds < 7200) return seconds / 60 + (ru ? " мин назад" : " min ago");
        return seconds / 3600 + (ru ? " ч назад" : " h ago");
    }
}
