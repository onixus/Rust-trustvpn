package org.rtrusttunnel.android;

import android.app.*;
import android.net.*;
import android.os.*;
import android.text.Editable;
import android.text.TextWatcher;
import android.widget.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.*;
import javax.net.ssl.*;
import org.json.*;

/** Read-only checks bound to this app's VPN Network; never uses a default socket. */
final class DiagnosticsDialog {
    // A cancelled system DNS call may finish late. No second DNS worker or
    // unbounded queue can be created while it remains blocked.
    static final ThreadPoolExecutor WORKER = new ThreadPoolExecutor(1, 1, 30,
        TimeUnit.SECONDS, new SynchronousQueue<>(), task -> { Thread t = new Thread(task, "vpn-diagnostic"); t.setDaemon(true); return t; });
    private static String text(String en, String ru) {
        return java.util.Locale.getDefault().getLanguage().equals("ru") ? ru : en;
    }
    static long generation() throws Exception {
        JSONObject status = new JSONObject(NativeCore.INSTANCE.status());
        if (!TunnelService.active || status.optInt("state") != 2) throw new IOException();
        return status.getJSONObject("observations").getLong("generation");
    }
    private static Network vpn(ConnectivityManager cm) {
        if (Build.VERSION.SDK_INT < 31) return null;
        Network found = null;
        for (Network n : cm.getAllNetworks()) {
            NetworkCapabilities c = cm.getNetworkCapabilities(n);
            if (c != null && c.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                && c.getOwnerUid() == android.os.Process.myUid()) {
                if (found != null) return null;
                found = n;
            }
        }
        return found;
    }
    static boolean validTarget(String host) {
        if (host.isEmpty() || host.length() > 253 || !host.equals(host.trim())) return false;
        if (host.contains(":")) return InetAddresses.isNumericAddress(host);
        for (String label : host.split("\\.", -1)) {
            if (!label.matches("[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?")) return false;
        }
        return true;
    }
    static int response(InputStream input) throws IOException {
        int total = 0;
        for (int interim = 0; interim <= 8; interim++) {
            ByteArrayOutputStream headers = new ByteArrayOutputStream();
            int tail = 0;
            while (tail != 0x0d0a0d0a) {
                int b = input.read();
                if (b < 0 || ++total > 8192) throw new IOException();
                headers.write(b); tail = (tail << 8) | b;
            }
            String[] lines = headers.toString(StandardCharsets.US_ASCII.name()).split("\r\n");
            if (!lines[0].matches("HTTP/1\\.[01] [0-9]{3}( .*)?") || lines.length > 65) throw new IOException();
            int status = Integer.parseInt(lines[0].substring(9,12));
            if (status == 101 || status < 100 || status > 599) throw new IOException();
            for (int i = 1; i < lines.length; i++) {
                if (!lines[i].matches("[!#$%&'*+.^_`|~0-9A-Za-z-]+:[\\t\\x20-\\x7e]*")) throw new IOException();
            }
            if (status >= 200) return status;
        }
        throw new IOException();
    }
    static final class Job {
        volatile boolean cancelled;
        private Socket socket;
        synchronized void own(Socket next) throws IOException {
            if (cancelled) { next.close(); throw new IOException(); }
            socket = next;
        }
        synchronized void cancel() {
            cancelled = true;
            if (socket != null) try { socket.close(); } catch (IOException ignored) { }
        }
        void current(ConnectivityManager cm, Network network, long epoch) throws Exception {
            if (cancelled || generation() != epoch || !network.equals(vpn(cm))) throw new Changed();
        }
    }
    private static final class Changed extends IOException { }
    static JSONObject check(Activity activity, String host, Job job) {
        String dns = "not_checked", route = "not_checked", https = "not_checked", cause = "undetermined";
        Integer status = null;
        long started = System.currentTimeMillis(), epoch = -1;
        try {
            ConnectivityManager cm = activity.getSystemService(ConnectivityManager.class);
            epoch = generation(); Network network = vpn(cm);
            if (network == null) { cause = "check_unsupported"; route = "unsupported"; }
            else {
                job.current(cm, network, epoch);
                InetAddress[] answers = network.getAllByName(host);
                job.current(cm, network, epoch);
                if (answers.length == 0 || answers.length > 8) throw new UnknownHostException();
                dns = InetAddresses.isNumericAddress(host) ? "not_checked" : "passed";
                LinkProperties link = cm.getLinkProperties(network);
                RouteInfo best = null;
                if (link != null) for (RouteInfo candidate : link.getRoutes()) {
                    if (candidate.matches(answers[0]) && (best == null || candidate.getDestination().getPrefixLength() > best.getDestination().getPrefixLength())) best = candidate;
                }
                if (best == null || Build.VERSION.SDK_INT >= 33 && best.getType() != RouteInfo.RTN_UNICAST) { route = "route_mismatch"; cause = "route_outside_vpn"; }
                else {
                    route = "configured"; // LinkProperties are configuration, not packet attestation.
                    Socket raw = network.getSocketFactory().createSocket(); job.own(raw);
                    raw.connect(new InetSocketAddress(answers[0],443),3000); raw.setSoTimeout(5000);
                    job.current(cm, network, epoch);
                    SSLSocket tls = (SSLSocket)((SSLSocketFactory)SSLSocketFactory.getDefault()).createSocket(raw,host,443,true);
                    job.own(tls); tls.setSoTimeout(5000);
                    SSLParameters params = tls.getSSLParameters(); params.setEndpointIdentificationAlgorithm("HTTPS"); tls.setSSLParameters(params);
                    tls.startHandshake(); job.current(cm, network, epoch);
                    String authority = host.contains(":") ? "[" + host + "]" : host;
                    tls.getOutputStream().write(("HEAD / HTTP/1.1\r\nHost: " + authority + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                    status = response(tls.getInputStream()); job.current(cm, network, epoch);
                    https = "passed"; cause = "responded";
                }
            }
        } catch (Changed ignored) { cause = "session_changed"; https = "session_changed"; status = null; }
        catch (UnknownHostException ignored) { dns = "failed"; cause = "name_resolution"; }
        catch (SSLHandshakeException | SSLPeerUnverifiedException ignored) { https = "tls_failed"; cause = "certificate_rejected"; }
        catch (SocketTimeoutException ignored) { https = "timeout"; }
        catch (Exception ignored) { https = "connection_failed"; }
        finally { job.cancel(); }
        if (epoch >= 0) try { if (generation() != epoch) { cause = "session_changed"; https = "session_changed"; status = null; } }
        catch (Exception ignored) { cause = "session_changed"; https = "session_changed"; status = null; }
        JSONObject result = new JSONObject();
        try {
            result.put("schema",1).put("started_at_ms",started).put("finished_at_ms",System.currentTimeMillis())
                .put("generation",epoch).put("dns",dns).put("dns_scope","answer_from_owned_vpn_network_not_dns_egress_attestation")
                .put("route",route).put("route_source","android_vpn_link_properties")
                .put("https",https).put("cause",cause).put("http_status",status == null ? JSONObject.NULL : status)
                .put("guard","not_checked").put("scope","one_destination_owned_vpn_network_no_global_protection_claim");
        } catch (JSONException ignored) { }
        return result;
    }
    static AlertDialog show(Activity activity) {
        Handler handler = new Handler(Looper.getMainLooper());
        LinearLayout panel = new LinearLayout(activity); panel.setOrientation(LinearLayout.VERTICAL); panel.setPadding(24,16,24,16);
        TextView help = new TextView(activity); help.setText(text("System DNS and one HTTPS HEAD through this app's VPN Network. No direct fallback or upload. Android 12+ is required to verify network ownership.", "Системный DNS и один HTTPS HEAD через VPN-сеть приложения. Без прямого обхода и отправки отчёта. Для проверки владельца сети нужен Android 12+.")); panel.addView(help);
        EditText target = new EditText(activity); target.setSingleLine(true); target.setText("example.com"); panel.addView(target);
        TextView output = new TextView(activity); panel.addView(output);
        EditText preview = new EditText(activity); preview.setMinLines(4); preview.setMaxLines(8); panel.addView(preview);
        Button save = new Button(activity); save.setText(text("Save edited report locally…", "Сохранить редактированный отчёт…")); panel.addView(save);
        save.setOnClickListener(v -> { if (activity instanceof MainActivity && preview.length() > 0) ((MainActivity)activity).saveDiagnostic(preview.getText().toString()); });
        final Job[] active = {null}; final long[] lastStart = {-5000}; final long[] request = {0};
        AlertDialog dialog = new AlertDialog.Builder(activity).setTitle(text("Check VPN path", "Проверить путь VPN"))
            .setView(panel).setNegativeButton(text("Close", "Закрыть"), null).setPositiveButton(text("Check / repeat", "Проверить / повторить"),null).create();
        final JSONObject[] latest = {null}; final long[] reportRequest = {-1};
        Runnable freshness = new Runnable() { public void run() {
            if (!dialog.isShowing()) return;
            if (latest[0] != null && active[0] == null) {
                JSONObject result = latest[0]; long age = System.currentTimeMillis()-result.optLong("finished_at_ms");
                boolean historical = age < 0 || age > 6000 || reportRequest[0] != request[0];
                try { historical |= generation() != result.optLong("generation",-1); } catch (Exception ignored) { historical = true; }
                output.setText((historical ? text("Historical result · ","Исторический результат · ") : "") + Math.max(0,age)/1000 + text(" seconds · "," секунд · ") + result.optString("cause") + " · " + result.optString("https"));
            }
            handler.postDelayed(this,500);
        }};
        Runnable cancel = () -> { request[0]++; if (active[0] != null) active[0].cancel(); active[0] = null; };
        target.addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s,int start,int count,int after) { }
            public void onTextChanged(CharSequence s,int start,int before,int count) { cancel.run(); output.setText(text("Destination changed; repeat the check.","Адрес изменился; повторите проверку.")); }
            public void afterTextChanged(Editable e) { }
        });
        dialog.setOnDismissListener(d -> { cancel.run(); handler.removeCallbacksAndMessages(null); });
        dialog.show(); handler.post(freshness);
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(view -> {
            String host = target.getText().toString(); long now = SystemClock.elapsedRealtime();
            if (!validTarget(host)) { output.setText(text("Enter hostname or IP without URL or port.","Введите hostname или IP без URL и порта.")); return; }
            if (now-lastStart[0] < 5000) { output.setText(text("Wait five seconds.","Подождите пять секунд.")); return; }
            cancel.run(); lastStart[0] = now; Job job = new Job(); active[0] = job; long id = request[0];
            output.setText(text("Checking…", "Проверка…"));
            Runnable deadline = () -> { if (id == request[0] && active[0] == job) { cancel.run(); output.setText(text("Time limit reached; cause undetermined.","Время истекло; причина не установлена.")); } };
            handler.postDelayed(deadline,15000);
            try {
                WORKER.execute(() -> {
                    JSONObject result = check(activity,host,job);
                    handler.post(() -> {
                        handler.removeCallbacks(deadline);
                        if (!dialog.isShowing() || id != request[0] || activity.isDestroyed()) return;
                        active[0] = null; latest[0] = result; reportRequest[0] = id;
                        output.setText(text("Result for one address: ","Результат для одного адреса: ") + result.optString("cause") + " · " + result.optString("https"));
                        // A new automatic result never overwrites the user's redactions.
                        if (preview.getText().length() == 0) preview.setText(result.toString());
                    });
                });
            } catch (RejectedExecutionException ignored) { cancel.run(); handler.removeCallbacks(deadline); output.setText(text("Previous DNS operation is still finishing; try later.","Предыдущая DNS-проверка ещё завершается; повторите позже.")); }
        });
        return dialog;
    }
}
