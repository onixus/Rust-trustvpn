package org.rtrusttunnel.android;

import android.app.*;
import android.content.*;
import android.content.pm.PackageManager;
import android.net.*;
import android.os.*;
import android.graphics.drawable.GradientDrawable;
import android.view.*;
import android.widget.*;
import java.util.*;
import org.json.*;

final class AppRoutingAcceptance {
    private static void check(boolean ok, String message) { if (!ok) throw new AssertionError(message); }
    static void smoke(Instrumentation test) throws Exception {
        Context context = test.getTargetContext();
        check(!AppRouting.read(new JSONObject()).selectedOnly, "Legacy vault keeps all-app routing");
        for (String invalid : new String[]{"{\"mode\":\"selected\",\"packages\":[]}", "{\"mode\":\"other\",\"packages\":[]}", "{\"mode\":\"selected\",\"packages\":[42]}", "null"}) {
            boolean rejected = false;
            try { AppRouting.read(new JSONObject("{\"app_routing\":" + invalid + "}")); } catch (Exception expected) { rejected = true; }
            check(rejected, "Malformed routing must not become all apps");
        }
        AppRouting missing = new AppRouting(true, Collections.singletonList("org.rtrusttunnel.nonexistent.fixture"));
        boolean rejected = false; try { missing.validateInstalled(context.getPackageManager()); } catch (PackageManager.NameNotFoundException expected) { rejected = true; }
        check(rejected, "Missing selected package is rejected");
        ProfileVault vault = new ProfileVault(context); JSONObject original = vault.read();
        try {
            AppRouting selected = new AppRouting(true, Arrays.asList(context.getPackageName(), context.getPackageName()));
            vault.saveAppRouting(selected);
            AppRouting restored = AppRouting.read(new ProfileVault(context).read());
            check(restored.selectedOnly && restored.packages.size() == 1, "Encrypted app selection persists and deduplicates");
            check(vault.read().getJSONArray("profiles").toString().equals(original.getJSONArray("profiles").toString()), "Saving app selection retains profiles");
        } finally { vault.write(original); }
        check(MainActivity.connectionColor(true, 2, false) != MainActivity.connectionColor(false, 0, false), "Connected color differs from disconnected");
        check(MainActivity.connectionColor(true, 1, false) == MainActivity.connectionColor(true, 3, false), "Connect/reconnect color");
        check(MainActivity.connectionColor(false, 0, true) == MainActivity.connectionColor(true, 4, false), "Service and core errors use error color");
        Activity activity = test.startActivitySync(new Intent(context, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
        try {
            test.runOnMainSync(() -> {
                ViewGroup content = activity.findViewById(android.R.id.content);
                LinearLayout root = (LinearLayout) content.getChildAt(0);
                View last = root.getChildAt(root.getChildCount() - 1);
                check(last instanceof Button && ((Button) last).getText().toString().equals("Connect default profile"), "Connect button is fixed below profile list");
            });
        } finally { test.runOnMainSync(activity::finish); }
    }
    static void uidRouting(Instrumentation test, JSONObject fixture) throws Exception {
        Context context = test.getTargetContext(); ProfileVault vault = new ProfileVault(context);
        JSONObject original = vault.read(); ConnectivityManager cm = context.getSystemService(ConnectivityManager.class);
        try {
            // The instrumentation process uses the target UID; the shell is a distinct UID.
            for (boolean included : new boolean[]{false, true}) {
                vault.saveAppRouting(new AppRouting(true, Collections.singletonList(included ? context.getPackageName() : "com.android.shell")));
                context.startForegroundService(new Intent(context, TunnelService.class));
                long end = SystemClock.elapsedRealtime() + 45000;
                while (SystemClock.elapsedRealtime() < end && new JSONObject(NativeCore.INSTANCE.status()).getInt("state") != 2) Thread.sleep(100);
                check(new JSONObject(NativeCore.INSTANCE.status()).getInt("state") == 2, "Selected-app VPN connects");
                boolean expected = false;
                for (int i = 0; i < 50; i++) {
                    NetworkCapabilities caps = cm.getNetworkCapabilities(cm.getActiveNetwork());
                    if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == included) { expected = true; break; }
                    Thread.sleep(100);
                }
                check(expected, included ? "Selected UID uses VPN" : "Unselected UID uses underlying network");
                if (included) NetworkAcceptance.verifyTraffic(fixture);
                context.startService(new Intent(context, TunnelService.class).setAction(TunnelService.STOP));
                end = SystemClock.elapsedRealtime() + 10000;
                while (TunnelService.active && SystemClock.elapsedRealtime() < end) Thread.sleep(100);
                check(!TunnelService.active, "Selected-app VPN stopped");
                // Android may briefly retain the destroyed Service instance in its main queue.
                Thread.sleep(300);
            }
        } finally {
            if (TunnelService.active) {
                context.startService(new Intent(context, TunnelService.class).setAction(TunnelService.STOP));
                for (int i = 0; i < 100 && TunnelService.active; i++) Thread.sleep(100);
            }
            vault.write(original);
        }
    }
}
