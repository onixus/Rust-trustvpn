package org.rtrusttunnel.android;

import android.content.Context;
import android.graphics.Typeface;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.StyleSpan;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.JSONObject;

/** Rendering only: the Rust core supplies all decisions and reason codes. */
final class ObservationStatus {
    static final String[] KEYS = {"transport", "route", "dns", "guard", "connectivity"};
    static final int[] NAMES = {R.string.check_transport, R.string.check_route, R.string.check_dns, R.string.check_guard, R.string.check_connectivity};
    /** Overall level of a running tunnel. Only every check passed and fresh is VERIFIED. */
    static final int RUNNING = 0, VERIFIED = 1, WARNING = 2;

    static JSONObject snapshot(JSONObject snapshot) {
        return snapshot == null || snapshot.optInt("schema") != 2 ? new JSONObject() : snapshot;
    }
    /** Normalised outcome: passed or configured results become stale after their TTL. */
    static String outcome(JSONObject observation) {
        String outcome = observation == null ? "unknown" : observation.optString("outcome", "unknown");
        if (outcome.equals("passed") || outcome.equals("configured")) {
            long time = observation.optLong("observed_at_ms", -1);
            long now = System.currentTimeMillis();
            long ttl = Math.min(6000, observation.optLong("valid_for_ms", 0));
            if (time < 0 || now < time || now - time > ttl) outcome = "stale";
        }
        return outcome;
    }
    static int color(Context context, String outcome) {
        switch (outcome) {
            case "passed": return context.getColor(R.color.state_verified);
            case "failed": return context.getColor(R.color.state_error);
            case "configured": return context.getColor(R.color.state_on);
            default: return context.getColor(R.color.state_idle);
        }
    }
    static int level(JSONObject snapshot) {
        snapshot = snapshot(snapshot);
        boolean verified = true;
        for (String key : KEYS) {
            String outcome = outcome(snapshot.optJSONObject(key));
            if (outcome.equals("failed")) return WARNING;
            if (!outcome.equals("passed")) verified = false;
        }
        return verified ? VERIFIED : RUNNING;
    }
    static String label(Context context, JSONObject observation) { return label(context, outcome(observation)); }
    static String label(Context context, String outcome) {
        int id;
        switch (outcome) {
            case "passed": id = R.string.observation_passed; break;
            case "failed": id = R.string.observation_failed; break;
            case "configured": id = R.string.observation_running; break;
            case "stale": id = R.string.observation_stale; break;
            case "unsupported": id = R.string.observation_unsupported; break;
            default: return null; // Never produced a result: omitted, not listed as unchecked.
        }
        return context.getString(id);
    }
    private static final Pattern ARGUMENT = Pattern.compile("%(\\d)\\$s");
    private static final String SEPARATOR = " · ";
    /** One line per check with a result: the localized name in bold, its outcome in regular weight. */
    static CharSequence summary(Context context, JSONObject snapshot) {
        if (snapshot == null || snapshot.optInt("schema") != 2) snapshot = new JSONObject();
        String[] outcomes = {label(context, snapshot.optJSONObject("transport")), label(context, snapshot.optJSONObject("route")),
            label(context, snapshot.optJSONObject("dns")), label(context, snapshot.optJSONObject("guard")),
            label(context, snapshot.optJSONObject("connectivity"))};
        String format = context.getString(R.string.observation_summary);
        SpannableStringBuilder text = new SpannableStringBuilder();
        Matcher argument = ARGUMENT.matcher(format);
        int literal = 0;
        while (argument.find()) {
            String name = format.substring(literal, argument.start());
            String outcome = outcomes[Integer.parseInt(argument.group(1)) - 1];
            literal = argument.end();
            if (name.startsWith(SEPARATOR)) name = name.substring(SEPARATOR.length());
            if (outcome == null) continue;
            if (text.length() > 0) text.append('\n');
            if (!name.isEmpty()) name = name.substring(0, 1).toUpperCase(context.getResources().getConfiguration().getLocales().get(0)) + name.substring(1);
            int start = text.length();
            text.append(name).setSpan(new StyleSpan(Typeface.BOLD), start, text.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            text.append(outcome);
        }
        return text.append(format.substring(literal));
    }
}
