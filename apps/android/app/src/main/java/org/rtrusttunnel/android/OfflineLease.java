package org.rtrusttunnel.android;

import android.content.Context;
import android.os.SystemClock;
import android.provider.Settings;
import org.json.*;

/** Authenticated vault receipt; sleep counts, reboot/clock rollback requires sync. */
final class OfflineLease {
    static int boot(Context context) { return Settings.Global.getInt(context.getContentResolver(),Settings.Global.BOOT_COUNT,-1); }
    static JSONObject issue(Context context,JSONObject server,long wall,long elapsed) throws Exception {
        long ttl=server.getLong("max_age_seconds"), token=server.getLong("token_remaining_seconds");
        if (server.getInt("version")!=1 || ttl<60 || ttl>86400 || token<=0 || token>30*86400) throw new IllegalArgumentException("Invalid freshness lease");
        int boot=boot(context); if(boot<0) throw new IllegalStateException("Boot identity unavailable");
        return new JSONObject().put("version",1).put("issued_wall",wall).put("issued_elapsed",elapsed)
            .put("duration_ms",Math.multiplyExact(Math.min(ttl,token),1000)).put("boot",boot);
    }
    static boolean valid(JSONObject lease,long wall,long elapsed,int boot) {
        if(lease==null || boot<0) return false;
        long start=lease.optLong("issued_wall",-1), monotonic=lease.optLong("issued_elapsed",-1), duration=lease.optLong("duration_ms",-1);
        return lease.optInt("version") ==1 && lease.optInt("boot",-2)==boot && start>0 && monotonic>=0 && duration>0 && duration<=86400000
            && wall>=start && elapsed>=monotonic && wall-start<duration && elapsed-monotonic<duration;
    }
    static boolean valid(Context context,JSONObject lease) {return valid(lease,System.currentTimeMillis(),SystemClock.elapsedRealtime(),boot(context));}
}
