package org.rtrusttunnel.android;

import android.content.Context;
import androidx.work.*;
import java.util.concurrent.TimeUnit;
import org.json.*;

/** Credentials stay in the Keystore vault, never in WorkManager's database. */
public final class PortalSyncWorker extends Worker {
    static final String WORK = "portal-profile-sync";
    static final Object SYNC = new Object();
    public PortalSyncWorker(Context context, WorkerParameters parameters) { super(context, parameters); }
    static void schedule(Context context) throws Exception {
        JSONObject portal = new ProfileVault(context).read().optJSONObject("portal");
        WorkManager manager = WorkManager.getInstance(context);
        // Enrollment alone keeps the worker: token renewal must not depend on
        // profile sync being enabled, or on the VPN being disconnected.
        if (portal == null) {
            manager.cancelUniqueWork(WORK); return;
        }
        PeriodicWorkRequest request = new PeriodicWorkRequest.Builder(PortalSyncWorker.class, 1, TimeUnit.HOURS)
            .setConstraints(new Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 1, TimeUnit.MINUTES).build();
        manager.enqueueUniquePeriodicWork(WORK, ExistingPeriodicWorkPolicy.KEEP, request);
    }
    @Override public Result doWork() {
        ProfileVault vault = new ProfileVault(getApplicationContext());
        JSONObject session = null;
        try {
            session = vault.read().optJSONObject("portal");
            if (session == null) return Result.success();
            synchronized (SYNC) {
                if (PortalClient.renewalDue(session, System.currentTimeMillis() / 1000)) {
                    try {
                        long deadline = new PortalClient(getApplicationContext(), session).renewAccess();
                        if (isStopped()) return Result.retry();
                        vault.renewPortalAccess(session, deadline);
                        session = vault.read().optJSONObject("portal");
                    } catch (PortalClient.Failure failure) {
                        if (failure.status == 401 || failure.status == 403) {
                            try { vault.expirePortalSync(session); } catch (Exception ignored) { return Result.retry(); }
                            return Result.success();
                        }
                        return Result.retry();
                    }
                }
                if (session == null || !session.optBoolean("background_sync")) return Result.success();
                if (isStopped()) return Result.retry();
                JSONArray remote = new PortalClient(getApplicationContext(),session).download(this::isStopped);
                if (isStopped()) return Result.retry();
                vault.syncPortalBackground(session, remote);
            }
            return Result.success();
        } catch (PortalClient.Failure failure) {
            if (session != null && (failure.status == 401 || failure.status == 403)) {
                try { vault.expirePortalSync(session); } catch (Exception ignored) { return Result.retry(); }
                return Result.success();
            }
            return Result.retry();
        } catch (Exception failure) { return Result.retry(); }
    }
}
