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
        if (portal == null || !portal.optBoolean("background_sync")) {
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
            if (session == null || !session.optBoolean("background_sync")) return Result.success();
            synchronized (SYNC) {
                if (isStopped()) return Result.retry();
                JSONArray remote = new PortalClient(session.getString("origin"), session.getString("token")).download();
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
