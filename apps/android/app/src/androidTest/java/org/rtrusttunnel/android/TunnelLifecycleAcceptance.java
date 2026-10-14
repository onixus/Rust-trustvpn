package org.rtrusttunnel.android;

import android.app.Instrumentation;
import android.content.*;
import android.net.VpnService;
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
        CountDownLatch release = new CountDownLatch(1);
        try {
            JSONObject profile = new JSONObject(NativeCore.INSTANCE.parse(
                "hostname='lifecycle.example'\naddresses=['192.0.2.1:443']\nusername='synthetic'\npassword='lifecycle-synthetic'\n")).getJSONObject("profile");
            vault.write(new JSONObject().put("default", "first").put("profiles", new JSONArray()
                .put(new JSONObject().put("id", "first").put("profile", profile))
                .put(new JSONObject().put("id", "second").put("profile", profile)))
                .put("app_routing", new AppRouting(true, java.util.Collections.singletonList(context.getPackageName())).json()));
            context.startForegroundService(new Intent(context, TunnelService.class).putExtra(TunnelService.PROFILE_ID, "first"));
            await(() -> service() != null && field(service(), TunnelService.class, "tun") != null, "Initial TUN established");
            TunnelService old = service();
            Object oldCallback = field(old, TunnelService.class, "callback");
            ExecutorService worker = (ExecutorService) field(null, TunnelService.class, "worker");
            CountDownLatch held = new CountDownLatch(1);
            worker.execute(() -> {
                held.countDown();
                try { release.await(10, TimeUnit.SECONDS); }
                catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
            });
            check(held.await(5, TimeUnit.SECONDS), "Lifecycle worker held at cleanup boundary");
            context.startService(new Intent(context, TunnelService.class).setAction(TunnelService.STOP));
            context.startForegroundService(new Intent(context, TunnelService.class).putExtra(TunnelService.PROFILE_ID, "second"));
            TunnelLifecycle lifecycle = (TunnelLifecycle) field(old, TunnelService.class, "lifecycle");
            await(() -> { synchronized (lifecycle) {
                return field(lifecycle, TunnelLifecycle.class, "pending") != null;
            } }, "START recorded before old cleanup completes");
            release.countDown();
            await(() -> service() == old && TunnelService.active
                && "second".equals(TunnelService.connectedProfileId())
                && field(old, TunnelService.class, "tun") != null
                && field(old, TunnelService.class, "callback") != oldCallback,
                "Pending START reuses instance after replacing TUN and callback");
            Thread.sleep(250);
            check(service() == old && TunnelService.active, "Old completion did not stop newer request");
        } finally {
            release.countDown();
            try {
                context.startService(new Intent(context, TunnelService.class).setAction(TunnelService.STOP));
                await(() -> service() == null && !TunnelService.active, "Test service cleanup completed");
                check(new JSONObject(NativeCore.INSTANCE.status()).optInt("state") == 0, "Native core stopped");
            } finally { vault.write(original); }
        }
    }
}
