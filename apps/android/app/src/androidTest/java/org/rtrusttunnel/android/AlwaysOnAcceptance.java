package org.rtrusttunnel.android;

import android.app.Instrumentation;
import android.content.*;
import android.net.*;
import android.os.SystemClock;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import org.json.*;

/** Phases driven by ci/android_always_on_e2e.py, which switches system Always-on/lockdown in Settings. */
final class AlwaysOnAcceptance {
    private static final String ID = "always-on-test";
    private static void check(boolean ok, String message) { if (!ok) throw new AssertionError(message); }
    private static int state() throws Exception { return new JSONObject(NativeCore.INSTANCE.status()).getInt("state"); }
    private static JSONObject fixture(Context context) throws Exception {
        File source = new File(context.getCacheDir(), "vpn-fixture.json");
        try { return new JSONObject(new String(Files.readAllBytes(source.toPath()), StandardCharsets.UTF_8)); }
        finally { source.delete(); }
    }
    private static boolean vpnNetwork(Context context) {
        ConnectivityManager cm = context.getSystemService(ConnectivityManager.class);
        for (Network network : cm.getAllNetworks()) {
            NetworkCapabilities caps = cm.getNetworkCapabilities(network);
            if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return true;
        }
        return false;
    }
    static void run(Instrumentation test, String phase) throws Exception {
        Context context = test.getTargetContext();
        ProfileVault vault = new ProfileVault(context);
        switch (phase) {
            case "seed": {
                JSONObject profile = new JSONObject(NativeCore.INSTANCE.parse(fixture(context).getJSONObject("base").toString())).getJSONObject("profile");
                profile.put("policy", new JSONObject().put("kill_switch", "always_on"));
                check(new JSONObject(NativeCore.INSTANCE.plan(profile.toString())).getJSONObject("plan").getBoolean("require_lockdown"), "kill_switch=always_on requires lockdown");
                vault.edit(data -> {
                    data.put("test_previous_default", data.getString("default"));
                    data.put("test_previous_routing", data.opt("app_routing"));
                    data.put("app_routing", new AppRouting(false, java.util.Collections.emptyList()).json());
                    data.getJSONArray("profiles").put(new JSONObject().put("id", ID).put("profile", profile));
                    data.put("default", ID);
                });
                return;
            }
            case "refused": {
                check(vault.read().getString("default").equals(ID), "Seeded profile selected");
                context.startForegroundService(new Intent(context, TunnelService.class));
                String expected = context.getString(R.string.cannot_start_vpn_check_the_profile);
                long end = SystemClock.elapsedRealtime() + 20000;
                while (SystemClock.elapsedRealtime() < end && !(expected.equals(TunnelService.problem) && !TunnelService.active)) Thread.sleep(100);
                check(expected.equals(TunnelService.problem) && !TunnelService.active, "require_lockdown refused without system lockdown");
                Thread.sleep(500);
                check(!vpnNetwork(context), "Refused profile leaves no VPN network");
                check(state() == 0, "Core never started");
                return;
            }
            case "connected": {
                JSONObject fixture = fixture(context);
                check(vault.read().getString("default").equals(ID), "Seeded profile selected");
                context.startForegroundService(new Intent(context, TunnelService.class));
                long end = SystemClock.elapsedRealtime() + 45000;
                while (SystemClock.elapsedRealtime() < end && state() != 2) Thread.sleep(100);
                check(state() == 2, "require_lockdown connects under Always-on with lockdown, got " + NativeCore.INSTANCE.status());
                check(TunnelService.active && TunnelService.alwaysOn && TunnelService.lockdown && TunnelService.problem.isEmpty(), "Service reports Always-on and lockdown");
                NetworkAcceptance.verifyTraffic(fixture);
                return;
            }
            case "finish": {
                if (TunnelService.active) {
                    context.startService(new Intent(context, TunnelService.class).setAction(TunnelService.STOP));
                    for (int i = 0; i < 100 && TunnelService.active; i++) Thread.sleep(100);
                }
                vault.edit(data -> {
                    JSONArray old = data.getJSONArray("profiles"), kept = new JSONArray();
                    for (int i = 0; i < old.length(); i++) if (!old.getJSONObject(i).getString("id").equals(ID)) kept.put(old.get(i));
                    data.put("profiles", kept);
                    if (!data.has("test_previous_default")) return; // seed never ran
                    data.put("default", data.getString("test_previous_default"));
                    if (data.has("test_previous_routing")) data.put("app_routing", data.get("test_previous_routing")); else data.remove("app_routing");
                    data.remove("test_previous_default"); data.remove("test_previous_routing");
                });
                return;
            }
            default: throw new AssertionError("Unknown always-on phase");
        }
    }
}
