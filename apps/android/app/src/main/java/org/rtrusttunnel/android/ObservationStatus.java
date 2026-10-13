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
    private static final Pattern ARGUMENT = Pattern.compile("%(\\d)\\$s");
    private static final String SEPARATOR = " · ";
    /** The check names of the localized summary in bold, their outcomes in regular weight. */
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
            if (name.startsWith(SEPARATOR)) { text.append(SEPARATOR); name = name.substring(SEPARATOR.length()); }
            int start = text.length();
            text.append(name).setSpan(new StyleSpan(Typeface.BOLD), start, text.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            text.append(outcomes[Integer.parseInt(argument.group(1)) - 1]);
            literal = argument.end();
        }
        return text.append(format.substring(literal));
    }
}
