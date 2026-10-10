package org.rtrusttunnel.android;

import android.content.Context;
import org.json.JSONObject;

/** Rendering only: the Rust core supplies all decisions and reason codes. */
final class ObservationStatus {
    private static String label(Context context, JSONObject observation) {
        String outcome = observation == null ? "unknown" : observation.optString("outcome", "unknown");
        if (outcome.equals("passed") || outcome.equals("configured")) {
            long time = observation.optLong("observed_at_ms", -1);
            long now = System.currentTimeMillis();
            long ttl = Math.min(6000, observation.optLong("valid_for_ms", 0));
            if (time < 0 || now < time || now - time > ttl) outcome = "stale";
        }
        int id;
        switch (outcome) {
            case "passed": id = R.string.observation_passed; break;
            case "failed": id = R.string.observation_failed; break;
            case "configured": id = R.string.observation_running; break;
            case "stale": id = R.string.observation_stale; break;
            case "unsupported": id = R.string.observation_unsupported; break;
            default: id = R.string.observation_unchecked;
        }
        return context.getString(id);
    }
    static String summary(Context context, JSONObject snapshot) {
        if (snapshot == null || snapshot.optInt("schema") != 1) snapshot = new JSONObject();
        return context.getString(R.string.observation_summary,
            label(context, snapshot.optJSONObject("transport")), label(context, snapshot.optJSONObject("route")),
            label(context, snapshot.optJSONObject("dns")), label(context, snapshot.optJSONObject("guard")),
            label(context, snapshot.optJSONObject("connectivity")));
    }
}
