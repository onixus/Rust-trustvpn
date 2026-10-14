package org.rtrusttunnel.android;

import android.app.Instrumentation;
import android.content.*;
import android.net.*;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import java.lang.reflect.Field;
import java.util.concurrent.*;
import org.json.*;

/** Isolated test package only: synthetic app-only TUN, no connected/leak claim. */
final class TunnelLifecycleAcceptance {
    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }
    private static Object field(Object owner, Class<?> type, String name) throws Exception {
        Field field = type.getDeclaredField(name); field.setAccessible(true); return field.get(owner);
    }
    private static TunnelService service() throws Exception {
        return (TunnelService) field(null, TunnelService.class, "running");
    }
    private static void await(java.util.concurrent.Callable<Boolean> condition, String label) throws Exception {
        long deadline = SystemClock.elapsedRealtime() + 10000;
        while (SystemClock.elapsedRealtime() < deadline) {
            if (condition.call()) return;
            Thread.sleep(20);
        }
        throw new AssertionError(label);
    }
    static void run(Instrumentation test) throws Exception {
        Context context = test.getTargetContext();
        check(context.getPackageName().endsWith(".lifecycle_test"), "Requires isolated lifecycle_test package");
        check(!TunnelService.active && !TunnelService.alwaysOn, "Requires inactive non Always-on test VPN");
        check(VpnService.prepare(context) == null, "Existing isolated VPN consent required");
        ProfileVault vault = new ProfileVault(context);
        JSONObject original = vault.read();
        try {
            JSONObject profile = new JSONObject(NativeCore.INSTANCE.parse(
                "hostname='lifecycle.example'\naddresses=['192.0.2.1:443']\nusername='synthetic'\npassword='lifecycle-synthetic'\n")).getJSONObject("profile");
            vault.write(new JSONObject().put("default", "first").put("profiles", new JSONArray()
                .put(new JSONObject().put("id", "first").put("profile", profile))
                .put(new JSONObject().put("id", "second").put("profile", profile)))
                .put("app_routing", new AppRouting(true, java.util.Collections.singletonList(context.getPackageName())).json()));
            context.startForegroundService(new Intent(context, TunnelService.class).putExtra(TunnelService.PROFILE_ID, "first"));
            await(() -> service() != null && field(service(), TunnelService.class, "tun") != null, "Initial TUN established");
            for (int cycle = 0; cycle < 5; cycle++) {
                TunnelService old = service();
                check(old != null, "Service exists before cycle");
                ExecutorService worker = (ExecutorService) field(null, TunnelService.class, "worker");
                CountDownLatch held = new CountDownLatch(1);
                CountDownLatch cycleRelease = new CountDownLatch(1);
                worker.execute(() -> {
                    held.countDown();
                    try { cycleRelease.await(20, TimeUnit.SECONDS); }
                    catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
                });
                try {
                    check(held.await(5, TimeUnit.SECONDS), "Lifecycle worker held at cleanup boundary");
                    ConnectivityManager.NetworkCallback oldCallback =
                        (ConnectivityManager.NetworkCallback) field(old, TunnelService.class, "callback");
                    ParcelFileDescriptor oldTun = (ParcelFileDescriptor) field(old, TunnelService.class, "tun");
                    check(oldTun != null && oldCallback != null, "Owned TUN and callback exist");
                    String latest = cycle % 2 == 0 ? "second" : "first";
                    String superseded = latest.equals("first") ? "second" : "first";
                    context.startService(new Intent(context, TunnelService.class).setAction(TunnelService.STOP));
                    context.startForegroundService(new Intent(context, TunnelService.class).putExtra(TunnelService.PROFILE_ID, superseded));
                    context.startForegroundService(new Intent(context, TunnelService.class).putExtra(TunnelService.PROFILE_ID, latest));
                    TunnelLifecycle lifecycle = (TunnelLifecycle) field(old, TunnelService.class, "lifecycle");
                    await(() -> { synchronized (lifecycle) {
                        TunnelLifecycle.Start pending = (TunnelLifecycle.Start) field(lifecycle, TunnelLifecycle.class, "pending");
                        return pending != null && latest.equals(pending.profileId);
                    } }, "Latest START recorded before old cleanup completes");
                    cycleRelease.countDown();
                    await(() -> service() == old && TunnelService.active
                        && latest.equals(TunnelService.connectedProfileId())
                        && field(old, TunnelService.class, "tun") != null
                        && field(old, TunnelService.class, "tun") != oldTun
                        && field(old, TunnelService.class, "callback") != oldCallback,
                        "Pending START reuses instance after replacing TUN and callback");
                    check(!oldTun.getFileDescriptor().valid(), "Previous TUN descriptor closed");
                    synchronized (field(old, TunnelService.class, "networkEvents")) {
                        long epoch = (Long) field(old, TunnelService.class, "networkEpoch");
                        Network underlying = (Network) field(old, TunnelService.class, "underlying");
                        if (underlying != null) oldCallback.onLinkPropertiesChanged(underlying, new LinkProperties());
                        check((Long) field(old, TunnelService.class, "networkEpoch") == epoch,
                            "Stale callback cannot mutate new session");
                        DeepSleepObserver observer = (DeepSleepObserver) field(old, TunnelService.class, "sleepObserver");
                        check(!observer.sample(oldCallback, 10000, 1000, 1000), "Stale sleep token rejected");
                    }
                    Thread.sleep(250);
                    check(service() == old && TunnelService.active, "Old completion did not stop newer request");
                } finally { cycleRelease.countDown(); }
            }
        } finally {
            try {
                context.startService(new Intent(context, TunnelService.class).setAction(TunnelService.STOP));
                await(() -> service() == null && !TunnelService.active, "Test service cleanup completed");
                check(new JSONObject(NativeCore.INSTANCE.status()).optInt("state") == 0, "Native core stopped");
            } finally { vault.write(original); }
        }
    }
}
