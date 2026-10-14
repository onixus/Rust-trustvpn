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
        JSONObject first = new JSONObject().put("name", "first"), second = new JSONObject().put("name", "second");
        JSONObject profiles = new JSONObject().put("default", "first").put("profiles", new JSONArray()
            .put(new JSONObject().put("id", "first").put("profile", first))
            .put(new JSONObject().put("id", "second").put("profile", second)));
        check(ProfileVault.resolveProfile(profiles, "second") == second, "App uses explicitly selected profile");
        check(ProfileVault.resolveProfile(profiles, profiles.getString("default")) == first, "Widget uses default profile");
        profiles.getJSONArray("profiles").getJSONObject(0).put("remote_id", "managed-1");
        ProfileVault.Selection managedSelection = ProfileVault.resolveSelection(profiles, null);
        profiles.put("default", "second");
        check(managedSelection.profile == first && !managedSelection.localPolicy && managedSelection.id.equals("first"), "Loaded content retains its managed provenance after default change");
        check(ProfileVault.resolveSelection(profiles, null).localPolicy, "New default selection resolves local provenance");
        boolean missingProfile = false;
        try { ProfileVault.resolveProfile(profiles, "removed"); } catch (Exception expected) { missingProfile = true; }
        check(missingProfile, "Removed selection never falls back to default");
        JSONObject portable=new JSONObject(NativeCore.INSTANCE.parse("hostname='test.example'\naddresses=['192.0.2.1:443']\nusername='synthetic'\npassword='synthetic'\n")).getJSONObject("profile");
        JSONObject group=new JSONObject().put("group","Team").put("revision","admin:1:2")
            .put("include",new JSONArray().put("10.0.0.0/8")).put("exclude",new JSONArray().put("10.2.0.0/16")).put("exclude_lan",false);
        JSONObject grouped=new JSONObject(NativeCore.INSTANCE.planManaged(portable.toString(),group.toString()));
        check(grouped.getBoolean("ok") && !grouped.getJSONObject("plan").getBoolean("ipv6"), "Managed IPv4 group plans through JNI and blocks IPv6");
        group.put("exclude_lan",true);
        check(!new JSONObject(NativeCore.INSTANCE.planManagedOnNetwork(portable.toString(),group.toString(),"null")).getBoolean("ok"), "Unobserved LAN never becomes an empty exclusion");
        check(new JSONObject(NativeCore.INSTANCE.planManagedOnNetwork(portable.toString(),group.toString(),"[\"10.1.0.7/24\"]")).getBoolean("ok"), "Observed LAN prefix compiles through JNI");
        JSONObject lease=new JSONObject().put("version",1).put("issued_wall",1000).put("issued_elapsed",100).put("duration_ms",5000).put("boot",7);
        check(OfflineLease.valid(lease,2000,1100,7), "Fresh lease accepted");
        check(!OfflineLease.valid(lease,2000,5100,7), "Sleep elapsed time expires lease");
        check(!OfflineLease.valid(lease,999,1100,7) && !OfflineLease.valid(lease,2000,1100,8), "Clock rollback and reboot need fresh receipt");
        AppRouting missing = new AppRouting(true, Collections.singletonList("org.rtrusttunnel.nonexistent.fixture"));
        boolean rejected = false; try { missing.validateInstalled(context.getPackageManager()); } catch (PackageManager.NameNotFoundException expected) { rejected = true; }
        check(rejected, "Missing selected package is rejected");
        ProfileVault vault = new ProfileVault(context); JSONObject original = vault.read();
        try {
            group.put("exclude_lan",false);
            JSONObject registration=new JSONObject().put("origin","https://panel.example").put("token","synthetic-registration");
            vault.edit(data -> data.put("portal",registration));
            JSONObject managedEntry=new JSONObject().put("id","portal:managed-1").put("remote_id","managed-1").put("revision","r1").put("profile",portable).put("managed_routing",group);
            vault.syncPortal(registration,new JSONArray().put(managedEntry));
            ProfileVault.Selection managed=vault.selection("portal:managed-1");
            check(!managed.localPolicy && managed.managedRouting.getString("revision").equals("admin:1:2"), "Encrypted snapshot binds group and managed ownership to profile");
            String before=vault.read().toString();
            JSONObject unsupported=new JSONObject(managedEntry.toString()); unsupported.remove("managed_routing"); unsupported.put("routing_unsupported",true);
            boolean refused=false;
            try { vault.syncPortal(registration,new JSONArray().put(unsupported)); } catch (Exception expected) { refused=true; }
            check(refused && before.equals(vault.read().toString()), "Capability regression leaves whole snapshot intact");
            JSONObject conflict=new JSONObject(managedEntry.toString()); conflict.getJSONObject("managed_routing").put("include",new JSONArray().put("172.16.0.0/12"));
            refused=false;
            try { vault.syncPortal(registration,new JSONArray().put(conflict)); } catch (Exception expected) { refused=true; }
            check(refused && before.equals(vault.read().toString()), "Same-revision managed route conflict remains atomic");
            vault.write(original);
            AppRouting selected = new AppRouting(true, Arrays.asList(context.getPackageName(), context.getPackageName()));
            vault.saveAppRouting(selected);
            AppRouting restored = AppRouting.read(new ProfileVault(context).read());
            check(restored.selectedOnly && restored.packages.size() == 1, "Encrypted app selection persists and deduplicates");
            check(vault.read().getJSONArray("profiles").toString().equals(original.getJSONArray("profiles").toString()), "Saving app selection retains profiles");
        } finally { vault.write(original); }
        check(MainActivity.connectionColor(true, 2, false) != MainActivity.connectionColor(false, 0, false), "Connected color differs from disconnected");
        check(MainActivity.connectionColor(true, 1, false) == MainActivity.connectionColor(true, 3, false), "Connect/reconnect color");
        check(MainActivity.connectionColor(false, 0, true) == MainActivity.connectionColor(true, 4, false), "Service and core errors use error color");
        check(MainActivity.connectionColor(true, 2, false) != MainActivity.WARNING, "A running tunnel is not shown as a warning");
        check(VpnWidget.button(R.string.connected) == R.drawable.widget_button_on && VpnWidget.button(R.string.connecting) == R.drawable.widget_button_busy
            && VpnWidget.button(R.string.disconnected) == R.drawable.widget_button_off, "Widget separates off, connecting and running");
        check("p".equals(MainActivity.badgeProfile(true, 0, "p")) && MainActivity.badgeProfile(false, 0, "p") == null
            && MainActivity.badgeProfile(true, 1, "p") == null, "Connected badge only on a connected primary");
        long now = System.currentTimeMillis();
        JSONObject passed = new JSONObject().put("outcome", "passed").put("observed_at_ms", now).put("valid_for_ms", 5000);
        JSONObject checks = new JSONObject().put("schema", 2);
        for (String key : ObservationStatus.KEYS) checks.put(key, passed);
        check(ObservationStatus.level(checks) == ObservationStatus.VERIFIED, "Fresh passed checks are verified");
        checks.put("dns", new JSONObject().put("outcome", "failed"));
        check(ObservationStatus.level(checks) == ObservationStatus.WARNING, "A failed check is a warning");
        checks.put("dns", new JSONObject().put("outcome", "passed").put("observed_at_ms", now - 60000).put("valid_for_ms", 5000));
        check(ObservationStatus.level(checks) == ObservationStatus.RUNNING, "A stale pass is not verified");
        check(ObservationStatus.level(new JSONObject().put("schema", 2).put("transport", new JSONObject().put("outcome", "configured").put("observed_at_ms", now).put("valid_for_ms", 5000))) == ObservationStatus.RUNNING, "Transport alone is running, not verified");
        Activity activity = test.startActivitySync(new Intent(context, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
        try {
            test.runOnMainSync(() -> {
                ViewGroup content = activity.findViewById(android.R.id.content);
                LinearLayout root = (LinearLayout) content.getChildAt(0);
                View last = root.getChildAt(root.getChildCount() - 1);
                check(last instanceof Button && ((Button) last).getText().toString().equals(activity.getString(R.string.connect_selected_profile)), "Connect button is fixed below profile list");
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
                NetworkAcceptance.settle(context);
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
