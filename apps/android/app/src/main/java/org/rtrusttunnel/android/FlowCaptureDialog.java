package org.rtrusttunnel.android;

import android.app.*;
import android.os.*;
import android.widget.*;
import org.json.*;

/** Explicit local opt-in; closing/backgrounding clears the bounded capture. */
final class FlowCaptureDialog {
    private static String text(String en, String ru) {
        return java.util.Locale.getDefault().getLanguage().equals("ru") ? ru : en;
    }
    static AlertDialog show(Activity activity) {
        Handler handler = new Handler(Looper.getMainLooper());
        TextView output = new TextView(activity); output.setPadding(24,24,24,24);
        ScrollView scroll = new ScrollView(activity); scroll.addView(output);
        AlertDialog dialog = new AlertDialog.Builder(activity)
            .setTitle(text("Observe local flow decisions", "Наблюдать решения маршрутизации"))
            .setView(scroll).setPositiveButton(text("Close", "Закрыть"), null).create();
        final long[] token = {-1,-1};
        final Runnable poll = new Runnable() {
            public void run() {
                if (!dialog.isShowing() || token[0] < 0) return;
                try {
                    JSONObject snapshot = new JSONObject(NativeCore.INSTANCE.flowCapture(token[0],token[1],3));
                    if (snapshot.has("error")) { output.setText(text("Capture stopped. Open again after connecting.", "Наблюдение завершено. Откройте снова после подключения.")); return; }
                    StringBuilder result = new StringBuilder(text("Actual flow policy selections; delivery and OS protection are not verified. No addresses are recorded.\n", "Реальные решения политики потока; доставка и системная защита не проверены. Адреса не записываются.\n"));
                    if (snapshot.optLong("lagged") > 0) result.append(text("Some events were lost: ","Часть событий потеряна: ")).append(snapshot.optLong("lagged")).append('\n');
                    if (snapshot.optLong("discarded_stale") > 0) result.append(text("Old policy events discarded: ","События прежней политики отброшены: ")).append(snapshot.optLong("discarded_stale")).append('\n');
                    if (snapshot.optLong("discarded_oversize") > 0) result.append(text("Events omitted for size: ","События пропущены по размеру: ")).append(snapshot.optLong("discarded_oversize")).append('\n');
                    JSONArray events = snapshot.optJSONArray("events");
                    if (events == null || events.length() == 0) result.append(text("No new observed decisions.", "Новых решений нет."));
                    for (int i=0; events != null && i<Math.min(32,events.length()); i++) {
                        JSONObject event=events.getJSONObject(i), decision=event.getJSONObject("decision");
                        if (decision.optBoolean("prediction",true)) continue;
                        String action=decision.optString("action");
                        result.append(action.equals("tunnel")?text("VPN","VPN"):action.equals("direct")?text("Direct","Напрямую"):action.equals("block")?text("Blocked","Заблокировано"):text("Unknown","Неизвестно"));
                        result.append(" · ").append(reason(decision.optString("reason")));
                        String source=decision.optJSONObject("context").optString("source");
                        result.append(" · ").append(source.equals("embedded_profile")?text("profile policy","политика профиля"):text("other policy source","другой источник политики"));
                        JSONObject version=event.getJSONObject("version");
                        String revision=version.optString("revision");
                        result.append(" · ").append(text("policy ","политика ")).append(revision.matches("[0-9a-f]{64}") ? revision.substring(0,12) : text("opaque revision","непрозрачная ревизия"));
                        result.append(" / ").append(version.optLong("epoch"));
                        result.append(" · ").append(event.optLong("age_ms")).append(" ms\n");
                    }
                    output.setText(result.toString());
                    handler.postDelayed(this,1000);
                } catch (Exception ignored) { output.setText(text("Capture unavailable", "Наблюдение недоступно")); }
            }
        };
        dialog.setOnDismissListener(ignored -> {
            handler.removeCallbacks(poll);
            if (token[0] >= 0) NativeCore.INSTANCE.flowCapture(token[0],token[1],2);
            token[0]=-1; token[1]=-1; output.setText("");
        });
        dialog.show();
        try {
            JSONObject identity=new JSONObject(NativeCore.INSTANCE.flowCapture(0,0,0));
            JSONObject before=identity.getJSONObject("token");
            JSONObject started=new JSONObject(NativeCore.INSTANCE.flowCapture(before.getLong("session"),before.getLong("capture"),1));
            JSONObject accepted=started.getJSONObject("token");
            token[0]=accepted.getLong("session"); token[1]=accepted.getLong("capture");
            handler.post(poll);
        } catch (Exception ignored) { output.setText(text("Connect before starting capture", "Перед наблюдением подключите VPN")); }
        return dialog;
    }
    private static String reason(String reason) {
        switch(reason) {
            case "dns_always_tunneled": return text("DNS uses VPN", "DNS через VPN");
            case "matched_rule": return text("matching rule", "совпало правило");
            case "default_tunnel": return text("default VPN policy", "VPN по умолчанию");
            case "default_direct": return text("default direct policy", "напрямую по умолчанию");
            case "unknown_name_protected": return text("unknown name stays protected", "неизвестное имя защищено");
            case "shared_ip_conflict_protected": return text("conflicting names stay protected", "конфликт имён защищён");
            default: return text("other policy reason", "другая причина политики");
        }
    }
}
