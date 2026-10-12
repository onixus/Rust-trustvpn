package org.rtrusttunnel.android;

import android.app.*;
import android.os.*;
import android.widget.*;
import org.json.*;

/** Session-only flow changes. Imported portal policies are never locally editable. */
final class FlowPolicyDialog {
    private static String text(String en, String ru) {
        return java.util.Locale.getDefault().getLanguage().equals("ru") ? ru : en;
    }
    static AlertDialog show(Activity activity) {
        LinearLayout panel = new LinearLayout(activity); panel.setOrientation(LinearLayout.VERTICAL); panel.setPadding(24,16,24,16);
        TextView help = new TextView(activity); help.setText(text("Rules apply until Disconnect, including automatic recovery. VPN routes, DNS and protection stay fixed. Existing connections are interrupted before a change is confirmed. Portal policies are locked; a tunnel-only connection cannot gain a direct path.","Правила действуют до отключения, включая автоматическое восстановление. Маршруты, DNS и защита VPN сохраняются. Старые соединения прерываются до подтверждения изменения. Политики панели заблокированы; подключение только через VPN не может получить прямой обход.")); panel.addView(help);
        Spinner mode = new Spinner(activity); mode.setAdapter(new ArrayAdapter<>(activity,android.R.layout.simple_spinner_dropdown_item,new String[]{text("All except listed","Всё, кроме перечисленного"),text("Only listed","Только перечисленное")})); panel.addView(mode);
        EditText rules = new EditText(activity); rules.setHint(text("IP, network, domain or domain:port, one per line","IP, сеть, домен или домен:порт, по одному на строку")); rules.setMaxLines(6); panel.addView(rules);
        EditText destination = new EditText(activity); destination.setSingleLine(true); destination.setText("192.0.2.1:443"); panel.addView(destination);
        TextView output = new TextView(activity); panel.addView(output);
        Button preview = new Button(activity); preview.setText(text("Preview route (offline)","Предпросмотр маршрута (без сети)")); panel.addView(preview);
        Button apply = new Button(activity); apply.setText(text("Apply to current connection","Применить к текущему подключению")); panel.addView(apply);
        Button rollback = new Button(activity); rollback.setText(text("Restore previous rules","Вернуть предыдущие правила")); rollback.setEnabled(false); panel.addView(rollback);
        AlertDialog dialog = new AlertDialog.Builder(activity).setTitle(text("Current connection rules","Правила текущего подключения"))
            .setView(panel).setNegativeButton(text("Close","Закрыть"),null).create();
        final JSONObject[] version = {null}; final String[] previous = {null}; final boolean[] busy = {false}; final long[] session = {-1};
        java.util.function.Consumer<JSONObject> send = request -> {
            if (busy[0]) return; busy[0] = true; apply.setEnabled(false); preview.setEnabled(false); rollback.setEnabled(false);
            output.setText(text("Checking rules…","Проверка правил…"));
            new Thread(() -> {
                JSONObject response;
                try { response = new JSONObject(NativeCore.INSTANCE.flowPolicy(request.toString())); }
                catch (Exception error) { response = new JSONObject(); }
                final JSONObject result = response;
                activity.runOnUiThread(() -> {
                    busy[0] = false;
                    if (!dialog.isShowing() || activity.isDestroyed()) return;
                    if (result.optBoolean("ok")) {
                        if (request.optString("op").equals("apply") && version[0] != null) previous[0] = version[0].optString("revision");
                        if (request.optString("op").equals("rollback")) previous[0] = null;
                        version[0] = result.optJSONObject("version");
                        session[0] = result.optLong("session", -1);
                        if (session[0] < 0) version[0] = null;
                        JSONObject decision = result.optJSONObject("decision");
                        output.setText(decision != null ? text("Prediction: ","Прогноз: ") + decision.optString("action") + " · " + decision.optString("reason") : request.optString("op").equals("version") ? text("Current revision loaded.","Текущая ревизия загружена.") : text("Applied; previous connections have ended.","Применено; прежние соединения завершены."));
                    } else { version[0] = null; output.setText(text("Rules unavailable, changed or controlled by the portal. Close and reopen to refresh.","Правила недоступны, изменились или управляются панелью. Откройте окно заново для обновления.")); }
                    apply.setEnabled(version[0] != null); preview.setEnabled(version[0] != null); rollback.setEnabled(version[0] != null && previous[0] != null);
                });
            },"vpn-policy").start();
        };
        java.util.function.Function<String,JSONObject> request = operation -> {
            try {
                JSONObject data = new JSONObject().put("op",operation).put("expected",version[0]).put("session",session[0]);
                if (operation.equals("rollback")) return data.put("previous_revision",previous[0]);
                JSONArray exclusions = new JSONArray();
                for (String rule : rules.getText().toString().split("[\\r\\n,]+")) if (!rule.trim().isEmpty()) exclusions.put(rule.trim());
                if (exclusions.length() > 64 || rules.length() > 32768) return null;
                data.put("policy",new JSONObject().put("mode",mode.getSelectedItemPosition() == 0 ? "general" : "selective").put("exclusions",exclusions));
                if (operation.equals("preview")) data.put("destination",destination.getText().toString());
                return data;
            } catch (Exception error) { return null; }
        };
        preview.setOnClickListener(v -> { JSONObject data = request.apply("preview"); if (data != null) send.accept(data); });
        apply.setOnClickListener(v -> { JSONObject data = request.apply("apply"); if (data != null) send.accept(data); });
        rollback.setOnClickListener(v -> { JSONObject data = request.apply("rollback"); if (data != null) send.accept(data); });
        dialog.show();
        try { send.accept(new JSONObject().put("op","version")); } catch (JSONException ignored) { }
        return dialog;
    }
}
