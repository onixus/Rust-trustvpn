package org.rtrusttunnel.android;

import android.app.Instrumentation;
import android.content.*;
import android.net.*;
import android.view.*;
import android.widget.TextView;
import org.json.*;

/** Uses synthetic endpoints and app-only routing; restores the original encrypted vault. */
final class ProfileSelectionAcceptance {
    private static void check(boolean ok, String message) { if (!ok) throw new AssertionError(message); }
    private static View find(View view, String name) {
        if (view instanceof TextView && ((TextView) view).getText().toString().equals(name)) return view;
        if (view instanceof ViewGroup) for (int i = 0; i < ((ViewGroup) view).getChildCount(); i++) {
            View found = find(((ViewGroup) view).getChildAt(i), name); if (found != null) return found;
        }
        return null;
    }
    private static void awaitPlan(Context context, boolean ipv6) throws Exception {
        ConnectivityManager cm = context.getSystemService(ConnectivityManager.class);
        for (int attempt = 0; attempt < 150; attempt++) {
            for (Network network : cm.getAllNetworks()) {
                NetworkCapabilities caps = cm.getNetworkCapabilities(network);
                LinkProperties links = cm.getLinkProperties(network);
                if (caps == null || !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) || links == null) continue;
                boolean hasIPv6 = false;
                for (LinkAddress address : links.getLinkAddresses()) if (address.getAddress() instanceof java.net.Inet6Address) hasIPv6 = true;
                if (TunnelService.active && hasIPv6 == ipv6) return;
            }
            Thread.sleep(100);
        }
        throw new AssertionError("Selected profile VPN plan was not established");
    }
    private static void stop(Context context) throws Exception {
        context.startService(new Intent(context, TunnelService.class).setAction(TunnelService.STOP));
        for (int i = 0; i < 100; i++) { if (!TunnelService.active) { Thread.sleep(500); return; } Thread.sleep(100); }
        throw new AssertionError("Test VPN did not stop");
    }
    static boolean run(Instrumentation test) throws Exception {
        Context context = test.getTargetContext();
        check(VpnService.prepare(context) == null, "Existing VPN consent is required");
        ProfileVault vault = new ProfileVault(context); JSONObject original = vault.read();
        java.io.File source = new java.io.File(context.getCacheDir(), "vpn-fixture.json");
        JSONObject fixture = source.exists() ? new JSONObject(new String(java.nio.file.Files.readAllBytes(source.toPath()), java.nio.charset.StandardCharsets.UTF_8)) : null;
        source.delete();
        MainActivity activity = null;
        try {
            JSONObject first = new JSONObject(NativeCore.INSTANCE.parse("hostname='selection.example'\naddresses=['192.0.2.1:443']\nusername='synthetic'\npassword='selection-test'\n")).getJSONObject("profile");
            first.put("name", "Selection default"); first.getJSONObject("endpoint").put("has_ipv6", false);
            JSONObject second = new JSONObject(first.toString()); second.put("name", "Selection second"); second.getJSONObject("endpoint").put("has_ipv6", true);
            if (fixture != null) {
                second = new JSONObject(NativeCore.INSTANCE.parse(fixture.getJSONObject("base").toString())).getJSONObject("profile");
                second.put("name", "Selection second");
            }
            vault.write(new JSONObject().put("default", "first").put("profiles", new JSONArray()
                .put(new JSONObject().put("id", "first").put("profile", first))
                .put(new JSONObject().put("id", "second").put("profile", second)))
                .put("app_routing", new AppRouting(true, java.util.Collections.singletonList(context.getPackageName())).json()));
            activity = (MainActivity) test.startActivitySync(new Intent(context, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
            MainActivity app = activity;
            test.runOnMainSync(() -> {
                View title = find(app.findViewById(android.R.id.content), "Selection second");
                check(title != null, "Second profile exists in UI");
                ((View) title.getParent().getParent()).performClick();
                app.toggle();
            });
            awaitPlan(context, true);
            check(vault.read().getString("default").equals("first"), "Selecting and connecting never changes default");
            if (fixture != null) {
                long deadline = android.os.SystemClock.elapsedRealtime() + 45000;
                while (android.os.SystemClock.elapsedRealtime() < deadline && new JSONObject(NativeCore.INSTANCE.status()).optInt("state") != 2) Thread.sleep(200);
                check(new JSONObject(NativeCore.INSTANCE.status()).optInt("state") == 2, "Selected second profile connects to real endpoint");
                NetworkAcceptance.awaitVpn(context);
                NetworkAcceptance.verifyTraffic(fixture);
                check(java.net.InetAddress.getByName("profile-selection.fixture.test").getHostAddress().equals(fixture.getString("target")), "System DNS through selected VPN");
                javax.net.ssl.HttpsURLConnection https = (javax.net.ssl.HttpsURLConnection) new java.net.URL("https://1.1.1.1/").openConnection();
                try {
                    https.setConnectTimeout(15000); https.setReadTimeout(15000); https.setInstanceFollowRedirects(false);
                    int code = https.getResponseCode();
                    check(code >= 200 && code < 400, "Verified TLS HTTPS through selected VPN");
                } finally { https.disconnect(); }
            }
            stop(context);
            test.runOnMainSync(app::finish); activity = null;
            // Exercise the actual widget entry point rather than a direct service call.
            activity = (MainActivity) test.startActivitySync(new Intent(context, WidgetActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
            awaitPlan(context, false);
            check(vault.read().getString("default").equals("first"), "Widget retains default");
            stop(context);
            MainActivity widgetScreen = activity;
            test.runOnMainSync(() -> {
                View title = find(widgetScreen.findViewById(android.R.id.content), "Selection second");
                check(title != null, "Widget-opened screen exposes profile selection");
                ((View) title.getParent().getParent()).performClick();
                widgetScreen.toggle();
            });
            awaitPlan(context, true);
            check(vault.read().getString("default").equals("first"), "App connection after widget open retains default");
        } finally {
            try { stop(context); } finally {
                if (activity != null) { MainActivity closing = activity; test.runOnMainSync(closing::finish); }
                vault.write(original);
                check(vault.read().toString().equals(original.toString()), "Original vault restored");
            }
        }
        return fixture != null;
    }
}
