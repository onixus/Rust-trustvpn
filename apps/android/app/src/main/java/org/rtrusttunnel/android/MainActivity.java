package org.rtrusttunnel.android;

import android.app.*;
import android.content.*;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.*;
import android.content.res.ColorStateList;
import android.net.*;
import android.os.*;
import android.text.Editable;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.text.style.ForegroundColorSpan;
import android.view.*;
import android.widget.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.json.*;

/**
 * Native Android widgets; no WebView and no remote UI code. One activity hosts the
 * screens (home, profiles, add, checks, actions) with its own back stack.
 */
public class MainActivity extends Activity {
    private static final int PICK = 10, SAVE = 11, CONSENT = 12, QR_IMAGE = 13, DIAGNOSTIC_SAVE = 14;
    static final int HOME = 0, PROFILES = 1, ADD = 2, CHECKS = 3, ACTIONS = 4, APPS = 5;
    /** Connection state shown to the user. */
    static final int S_OFF = 0, S_CONNECTING = 1, S_RECONNECTING = 2, S_RUNNING = 3, S_VERIFIED = 4, S_WARNING = 5, S_ERROR = 6;
    /** Connection state colours: grey off, blue connecting or running, green verified, yellow warning, red error. */
    static final int IDLE = Color.rgb(107, 122, 140), BUSY = Color.rgb(77, 163, 255), ON = BUSY,
        VERIFIED = Color.rgb(61, 214, 140), WARNING = Color.rgb(224, 165, 38), ERROR = Color.rgb(229, 72, 77);

    /** Display data only: names, hosts and protocols; never credentials. */
    static final class Info {
        String id, name, protocol, host, managed; boolean server, isDefault;
        boolean matches(String query) {
            String q = query.toLowerCase(Locale.ROOT);
            return name.toLowerCase(Locale.ROOT).contains(q) || host.toLowerCase(Locale.ROOT).contains(q) || protocol.toLowerCase(Locale.ROOT).contains(q);
        }
    }
    private static final class Row { String name, value; int color, valueColor; boolean ring; String note; }

    private String diagnosticExport;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private String selectedId, pendingConnectId, liveProfileId, problemText = "";
    private ProfileVault vault;
    private AlertDialog flowCapture;
    private Palette p;
    private Backdrop backdrop;
    private FrameLayout host;
    private int screen = HOME, uiState = S_OFF, backupIndex;
    private final ArrayDeque<Integer> back = new ArrayDeque<>();
    private Object backCallback; // android.window.OnBackInvokedCallback, API 33+
    private JSONObject observations;
    private final List<Info> profiles = new ArrayList<>();
    private final Set<String> backups = new HashSet<>();
    private String routingSummary = "", portalHost;
    private String renderKey = "";
    // Views of the visible screen; null on other screens.
    private TextView tagText, headline, description, stateChip;
    private View tagDot;
    private LinearLayout checksBox, strip, list, results;
    private SlideButton slider;
    private EditText search;
    private TextView checkedAt;

    /**
     * Path check run automatically on connect, on every app open, after a session or
     * network change and every 5 minutes while open: DNS, route and one HTTPS request,
     * only through this app's VPN network (DiagnosticsDialog.check). The target is the
     * host Android itself probes for connectivity.
     */
    static final String PATH_TARGET = "connectivitycheck.gstatic.com";
    private static final long PATH_REFRESH_MS = 5 * 60_000, PATH_MIN_GAP_MS = 5_000, PATH_DEADLINE_MS = 15_000;
    private JSONObject pathResult;
    private DiagnosticsDialog.Job pathJob;
    private long sessionGeneration = -1, pathGeneration = -1, pathAt, pathStarted = -PATH_MIN_GAP_MS;
    private boolean pathForce = true, pathSplit, routingExcludesSelf;
    /** Instrumentation turns this off so automatic checks add no traffic to stand fixtures. */
    static volatile boolean autoPathChecks = true;

    private final Runnable poll = new Runnable() {
        public void run() {
            try {
                JSONObject state = new JSONObject(NativeCore.INSTANCE.status());
                TunnelService.refreshPolicy();
                int nativeState = state.optInt("state", 0);
                boolean problem = !TunnelService.problem.isEmpty(), running = nativeState == 2 && !problem;
                observations = running ? ObservationStatus.snapshot(state.optJSONObject("observations")) : null;
                sessionGeneration = running && state.optJSONObject("observations") != null ? state.getJSONObject("observations").optLong("generation", -1) : -1;
                if (running) maybeCheckPath(); else stopPathCheck(true);
                int level = running ? level() : ObservationStatus.RUNNING;
                JSONObject recovery = state.optJSONObject("recovery");
                backupIndex = recovery == null ? 0 : recovery.optInt("selected_index");
                if (problem || nativeState == 4 || nativeState < 0 || nativeState > 4) {
                    uiState = S_ERROR; problemText = problem ? TunnelService.problem : getString(R.string.connection_failed);
                }
                else if (running) uiState = level == ObservationStatus.VERIFIED ? S_VERIFIED : level == ObservationStatus.WARNING ? S_WARNING : S_RUNNING;
                else if (nativeState == 3) uiState = S_RECONNECTING;
                else if (nativeState == 1 || TunnelService.active) uiState = S_CONNECTING;
                else uiState = S_OFF;
                // Only a connected primary is marked running: not while connecting, failing or on a backup.
                String live = badgeProfile(running, backupIndex, TunnelService.connectedProfileId());
                if (!Objects.equals(live, liveProfileId)) { liveProfileId = live; reload(); }
            } catch (Exception ignored) {
                uiState = S_ERROR; problemText = getString(R.string.vpn_status_unavailable); observations = null;
                if (liveProfileId != null) { liveProfileId = null; reload(); }
            }
            renderState();
            handler.postDelayed(this, 500);
        }
    };

    @Override public void onCreate(Bundle state) {
        setTheme(Palette.light(this) ? R.style.Theme_RTrust_Light : R.style.Theme_RTrust);
        super.onCreate(state);
        if (state != null) {
            selectedId = state.getString("selectedProfile"); pendingConnectId = state.getString("pendingConnectProfile");
            screen = state.getInt("screen", HOME); if (screen != HOME) back.push(HOME);
        }
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        vault = new ProfileVault(this);
        try { PortalSyncWorker.schedule(this); } catch (Exception ignored) { /* Reconcile again on next launch. */ }
        p = Palette.of(this);
        backdrop = new Backdrop(p);
        host = new FrameLayout(this); host.setBackground(backdrop);
        host.setOnApplyWindowInsetsListener((view, insets) -> {
            android.graphics.Insets bars = Build.VERSION.SDK_INT >= 30 ? insets.getInsets(WindowInsets.Type.systemBars()) : insets.getSystemWindowInsets();
            int bottom = bars.bottom;
            if (Build.VERSION.SDK_INT >= 30) bottom = Math.max(bottom, insets.getInsets(WindowInsets.Type.ime()).bottom);
            view.setPadding(bars.left, bars.top, bars.right, bottom); return insets;
        });
        setContentView(host);
        reload(); build(); incoming(getIntent());
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission("android.permission.POST_NOTIFICATIONS") != android.content.pm.PackageManager.PERMISSION_GRANTED)
            requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, 20);
    }
    @Override protected void onSaveInstanceState(Bundle state) {
        super.onSaveInstanceState(state);
        state.putString("selectedProfile", selectedId);
        state.putString("pendingConnectProfile", pendingConnectId);
        state.putInt("screen", screen);
    }

    // ---- Navigation -------------------------------------------------------------------

    private void show(int next) {
        if (next == screen) return;
        back.push(screen); screen = next; build();
    }
    private void goBack() {
        if (back.isEmpty()) return;
        if (screen == APPS) picker = null;
        screen = back.pop(); build();
    }
    /** Below API 33 only; syncBack() registers the API 33+ callback. */
    @SuppressWarnings("deprecation") @android.annotation.SuppressLint("GestureBackNavigation")
    @Override public void onBackPressed() { if (back.isEmpty()) super.onBackPressed(); else goBack(); }
    private void home() { back.clear(); picker = null; screen = HOME; build(); }
    /** API 33+ (and always when targeting 36) routes Back here instead of onBackPressed. */
    private void syncBack() {
        if (Build.VERSION.SDK_INT < 33) return;
        android.window.OnBackInvokedDispatcher dispatcher = getOnBackInvokedDispatcher();
        if (!back.isEmpty() && backCallback == null) {
            backCallback = (android.window.OnBackInvokedCallback) this::goBack;
            dispatcher.registerOnBackInvokedCallback(android.window.OnBackInvokedDispatcher.PRIORITY_DEFAULT, (android.window.OnBackInvokedCallback) backCallback);
        } else if (back.isEmpty() && backCallback != null) {
            dispatcher.unregisterOnBackInvokedCallback((android.window.OnBackInvokedCallback) backCallback);
            backCallback = null;
        }
    }
    private void build() {
        host.removeAllViews();
        tagText = headline = description = stateChip = checkedAt = null; tagDot = null;
        checksBox = strip = list = results = appsList = null; slider = null; search = null; appsMessage = appsCount = null; renderKey = "";
        View view;
        switch (screen) {
            case PROFILES: view = profilesScreen(); break;
            case ADD: view = addScreen(); break;
            case CHECKS: view = checksScreen(); break;
            case ACTIONS: view = actionsScreen(); break;
            case APPS: view = appsScreen(); break;
            default: view = homeScreen();
        }
        host.addView(view, new FrameLayout.LayoutParams(-1, -1));
        syncBack();
        renderState();
    }

    // ---- State ------------------------------------------------------------------------

    private int stateColor() {
        switch (uiState) {
            case S_OFF: return p.grey;
            case S_VERIFIED: return p.green;
            case S_WARNING: return p.yellow;
            case S_ERROR: return p.red;
            default: return p.blue;
        }
    }
    private Info info(String id) { for (Info info : profiles) if (info.id.equals(id)) return info; return null; }

    /** Index of each check in ObservationStatus.KEYS. */
    private static final int TRANSPORT = 0, ROUTE = 1, DNS = 2, GUARD = 3, CONNECTIVITY = 4;
    private static final int PASSED = 1, FAILED = -1, UNKNOWN = 0, OUTSIDE = 2;

    private boolean pathRunning() { return pathJob != null; }
    private boolean pathFresh() {
        return pathResult != null && pathGeneration == sessionGeneration && sessionGeneration >= 0
            && System.currentTimeMillis() - pathAt <= PATH_REFRESH_MS + PATH_DEADLINE_MS;
    }
    /** Why the app cannot check its own VPN path, or 0. */
    private int pathBlocked() {
        if (Build.VERSION.SDK_INT < 31) return R.string.v3_check_needs_android12; // network ownership needs API 31
        if (routingExcludesSelf) return R.string.v3_check_app_excluded;
        return 0;
    }
    /** True when this app's VPN carries no IPv4 default route, so the test address may lawfully stay outside. */
    private boolean splitTunnel() {
        if (Build.VERSION.SDK_INT < 31) return false; // checks never run there; see pathBlocked()
        try {
            ConnectivityManager cm = getSystemService(ConnectivityManager.class);
            for (Network network : cm.getAllNetworks()) {
                NetworkCapabilities caps = cm.getNetworkCapabilities(network);
                if (caps == null || !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) || caps.getOwnerUid() != android.os.Process.myUid()) continue;
                LinkProperties links = cm.getLinkProperties(network);
                if (links == null) return false;
                for (RouteInfo route : links.getRoutes()) if (route.isDefaultRoute() && route.getDestination().getAddress() instanceof java.net.Inet4Address) return false;
                return true;
            }
        } catch (Exception ignored) { /* Treat as full tunnel: a mismatch then stays a failure. */ }
        return false;
    }
    private void maybeCheckPath() {
        if (!autoPathChecks || pathBlocked() != 0) return;
        long now = SystemClock.elapsedRealtime();
        if (pathRunning() || now - pathStarted < PATH_MIN_GAP_MS) return;
        boolean stale = !pathFresh() || System.currentTimeMillis() - pathAt > PATH_REFRESH_MS;
        if (!stale && !pathForce) return;
        pathForce = false; pathStarted = now;
        DiagnosticsDialog.Job job = new DiagnosticsDialog.Job(); pathJob = job;
        long generation = sessionGeneration;
        // No answer within the deadline counts as no access, never as the previous pass.
        Runnable deadline = () -> {
            if (pathJob != job) return;
            job.cancel(); pathJob = null; renderKey = "";
            try { pathResult = new JSONObject().put("https", "timeout").put("generation", generation); pathGeneration = generation; pathAt = System.currentTimeMillis(); }
            catch (JSONException ignored) { pathResult = null; }
        };
        handler.postDelayed(deadline, PATH_DEADLINE_MS);
        try {
            DiagnosticsDialog.WORKER.execute(() -> {
                JSONObject result = DiagnosticsDialog.check(this, PATH_TARGET, job);
                handler.post(() -> {
                    handler.removeCallbacks(deadline);
                    if (pathJob != job || isDestroyed()) return;
                    pathJob = null;
                    // A result from an earlier session or network says nothing about this one.
                    if (result.optLong("generation", -2) == generation && generation == sessionGeneration && !"session_changed".equals(result.optString("cause"))) {
                        pathResult = result; pathGeneration = generation; pathAt = System.currentTimeMillis(); pathSplit = splitTunnel();
                    }
                    renderKey = ""; renderState();
                });
            });
        } catch (java.util.concurrent.RejectedExecutionException busy) { handler.removeCallbacks(deadline); pathJob = null; pathResult = null; }
    }
    private void stopPathCheck(boolean forget) {
        if (pathJob != null) { pathJob.cancel(); pathJob = null; }
        if (forget) { pathResult = null; pathGeneration = -1; }
    }
    private void recheck() { pathForce = true; pathStarted = -PATH_MIN_GAP_MS; renderKey = ""; }

    /** PASSED, FAILED or UNKNOWN for a check, from the app's path check or the core. */
    private int verdict(int check) {
        if (check == GUARD) return TunnelService.active && TunnelService.alwaysOn && TunnelService.lockdown ? PASSED : UNKNOWN;
        if (pathFresh()) {
            String value = check == ROUTE ? pathResult.optString("route") : check == DNS ? pathResult.optString("dns") : check == CONNECTIVITY ? pathResult.optString("https") : "";
            if (check == ROUTE && value.equals("configured") || check != ROUTE && value.equals("passed")) return PASSED;
            if (check == ROUTE && value.equals("route_mismatch") && pathSplit) return OUTSIDE;
            if (check == ROUTE && value.equals("route_mismatch") || check == DNS && value.equals("failed")
                || check == CONNECTIVITY && (value.equals("tls_failed") || value.equals("timeout") || value.equals("connection_failed"))) return FAILED;
        }
        if (observations == null) return UNKNOWN;
        String outcome = ObservationStatus.outcome(observations.optJSONObject(ObservationStatus.KEYS[check]));
        return outcome.equals("passed") || check == TRANSPORT && outcome.equals("configured") ? PASSED : outcome.equals("failed") ? FAILED : UNKNOWN;
    }
    /** Green needs route, DNS and internet access passed; the guard is reported, not required. */
    private int level() {
        if (ObservationStatus.level(observations) == ObservationStatus.WARNING) return ObservationStatus.WARNING;
        boolean all = true;
        for (int check : new int[]{TRANSPORT, ROUTE, DNS, CONNECTIVITY}) {
            int v = verdict(check);
            if (v == FAILED) return ObservationStatus.WARNING;
            if (v != PASSED) all = false;
        }
        return all ? ObservationStatus.VERIFIED : ObservationStatus.RUNNING;
    }
    private String failedName() {
        for (int check : new int[]{TRANSPORT, ROUTE, DNS, CONNECTIVITY}) if (verdict(check) == FAILED) return getString(ObservationStatus.NAMES[check]);
        return getString(ObservationStatus.NAMES[CONNECTIVITY]);
    }
    private String ago(long at) {
        long minutes = (System.currentTimeMillis() - at) / 60_000;
        return minutes < 1 ? getString(R.string.v3_just_now) : getString(R.string.v3_minutes_ago, minutes);
    }

    /** Five checks for the current state, each in plain words. */
    private List<Row> rows() {
        int[] notes = {R.string.v3_note_transport, R.string.v3_note_route, R.string.v3_note_dns, R.string.v3_note_guard, R.string.v3_note_connectivity};
        int[][] words = {{R.string.v3_transport_ok, R.string.observation_failed}, {R.string.v3_route_ok, R.string.v3_route_bad},
            {R.string.v3_dns_ok, R.string.v3_dns_bad}, {R.string.v3_guard_on, R.string.v3_guard_off}, {R.string.v3_net_ok, R.string.v3_net_bad}};
        boolean live = uiState == S_RUNNING || uiState == S_VERIFIED || uiState == S_WARNING;
        List<Row> rows = new ArrayList<>();
        for (int i = 0; i < ObservationStatus.KEYS.length; i++) {
            Row row = new Row(); row.name = getString(ObservationStatus.NAMES[i]); row.note = getString(notes[i]);
            row.ring = true; row.color = p.empty; row.value = getString(R.string.v3_not_checked);
            if (i == TRANSPORT && uiState == S_OFF) row.value = getString(R.string.v3_check_off);
            else if (i == TRANSPORT && (uiState == S_CONNECTING || uiState == S_RECONNECTING)) { row.value = getString(R.string.v3_check_connecting); row.color = p.blue; }
            else if (i == TRANSPORT && uiState == S_ERROR) { row.value = getString(R.string.observation_failed); row.color = p.red; row.ring = false; }
            else if (live) {
                int v = verdict(i);
                if (v == PASSED) { row.value = getString(words[i][0]); row.color = p.green; row.ring = false; }
                else if (v == FAILED) { row.value = getString(words[i][1]); row.color = p.yellow; row.ring = false; }
                else if (v == OUTSIDE) row.value = getString(R.string.v3_route_split);
                else if (i != GUARD && i != TRANSPORT && pathBlocked() != 0) row.value = getString(R.string.v3_check_unavailable);
                else if (i == GUARD) row.value = getString(R.string.v3_guard_off);
                else if (pathRunning()) { row.value = getString(R.string.v3_checking); row.color = p.blue; }
            }
            row.valueColor = row.ring ? (row.color == p.blue ? p.blueText : p.muted) : p.textFor(row.color);
            rows.add(row);
        }
        return rows;
    }

    /** Repaints the visible screen's state parts; cheap when nothing changed. */
    private void renderState() {
        int color = stateColor();
        backdrop.setAccent(color);
        // While the service runs, name the profile it serves, not a newer selection in the strip.
        String serving = TunnelService.active ? TunnelService.connectedProfileId() : null;
        Info selected = info(serving != null ? serving : selectedId);
        String name = selected == null ? null : selected.name;
        String key = uiState + "|" + name + "|" + backupIndex + "|" + problemText + "|" + TunnelService.active + TunnelService.alwaysOn;
        List<Row> rows = rows();
        for (Row row : rows) key += "|" + row.value + row.color;
        if (pathFresh()) key += "|" + ago(pathAt);
        if (key.equals(renderKey)) return;
        renderKey = key;
        if (tagDot != null) ((GradientDrawable) tagDot.getBackground()).setColor(color);
        if (tagText != null) tagText.setText(selected == null ? "R-TRUSTTUNNEL" : (selected.name + " · " + selected.protocol).toUpperCase(Locale.getDefault()));
        if (headline != null) {
            int[] lines;
            switch (uiState) {
                case S_CONNECTING: lines = new int[]{R.string.v3_tunnel, R.string.v3_connecting_2}; break;
                case S_RECONNECTING: lines = new int[]{R.string.v3_tunnel, R.string.v3_reconnecting_2}; break;
                case S_RUNNING: lines = new int[]{R.string.v3_tunnel, R.string.v3_running_2}; break;
                case S_VERIFIED: lines = new int[]{R.string.v3_tunnel, R.string.v3_verified_2}; break;
                case S_WARNING: lines = new int[]{R.string.v3_warning_1, R.string.v3_warning_2}; break;
                case S_ERROR: lines = new int[]{R.string.v3_error_1, R.string.v3_error_2}; break;
                default: lines = new int[]{R.string.v3_off_1, R.string.v3_off_2};
            }
            SpannableStringBuilder text = new SpannableStringBuilder(getString(lines[0])).append('\n');
            int start = text.length(); text.append(getString(lines[1]));
            text.setSpan(new ForegroundColorSpan(p.textFor(color)), start, text.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            headline.setText(text); fitHeadline();
        }
        if (description != null) {
            String host = selected == null ? "" : selected.host.isEmpty() ? selected.name : selected.host;
            String text;
            switch (uiState) {
                case S_CONNECTING: text = getString(R.string.v3_connecting_desc, host); break;
                case S_RECONNECTING: text = getString(R.string.v3_reconnecting_desc); break;
                case S_RUNNING: text = getString(pathBlocked() != 0 ? pathBlocked() : pathRunning() || pathForce ? R.string.v3_running_desc : R.string.v3_running_unchecked_desc); break;
                case S_VERIFIED: text = getString(R.string.v3_verified_desc, ago(pathAt)); break;
                case S_WARNING: text = getString(R.string.v3_warning_desc, failedName()); break;
                case S_ERROR: text = problemText; break;
                default: text = name == null ? getString(R.string.v3_off_desc_none) : getString(R.string.v3_off_desc, name);
            }
            if ((uiState == S_VERIFIED || uiState == S_WARNING) && verdict(GUARD) != PASSED) text += " " + getString(R.string.v3_guard_off_note); // resources trim leading spaces
            if (backupIndex > 0 && (uiState == S_RUNNING || uiState == S_VERIFIED || uiState == S_WARNING))
                text = getString(R.string.recovery_backup_active, backupIndex) + ". " + text;
            description.setText(text);
        }
        if (checksBox != null) fillChecks(checksBox, rows, screen == CHECKS);
        if (checkedAt != null) {
            checkedAt.setText(pathBlocked() != 0 ? getString(pathBlocked()) : pathFresh() ? getString(R.string.v3_checked_via, ago(pathAt), PATH_TARGET) : pathRunning() ? getString(R.string.v3_running_desc) : getString(R.string.v3_running_unchecked_desc));
            checkedAt.setVisibility(uiState == S_RUNNING || uiState == S_VERIFIED || uiState == S_WARNING ? View.VISIBLE : View.GONE);
        }
        if (stateChip != null) {
            stateChip.setText(headlineWord());
            stateChip.setTextColor(p.textFor(color));
            stateChip.setBackground(round(Color.argb(p.light ? 46 : 38, Color.red(color), Color.green(color), Color.blue(color)), dp(12)));
        }
        if (slider != null) paintSlider(color);
    }
    private String headlineWord() {
        switch (uiState) {
            case S_CONNECTING: return getString(R.string.v3_connecting_2);
            case S_RECONNECTING: return getString(R.string.v3_reconnecting_2);
            case S_RUNNING: return getString(R.string.v3_running_2);
            case S_VERIFIED: return getString(R.string.v3_verified_2);
            case S_WARNING: return getString(R.string.v3_warning_2);
            case S_ERROR: return getString(R.string.v3_error_2);
            default: return getString(R.string.v3_off_2);
        }
    }
    private void paintSlider(int color) {
        boolean ring = uiState == S_CONNECTING || uiState == S_RECONNECTING;
        int knob = p.light ? p.textFor(color) : color;
        int icon = ring ? knob : p.light ? Color.WHITE : 0xFF08090B;
        int label;
        if (TunnelService.active && TunnelService.alwaysOn) label = R.string.v3_always_on_locked;
        else if (ring) label = R.string.v3_slide_cancel;
        else if (TunnelService.active) label = R.string.v3_slide_disconnect;
        else if (uiState == S_ERROR) label = R.string.v3_slide_retry;
        else label = R.string.connect_selected_profile;
        // The idle label keeps the long wording for screen readers and tests; show the short one.
        String text = getString(label == R.string.connect_selected_profile ? R.string.v3_slide_connect : label);
        // Stopping a running or starting tunnel slides right to left; connecting slides left to right.
        slider.set(text, knob, icon, ring, TunnelService.active, p.card, p.cardStroke, p.muted);
        slider.setContentDescription(getString(label));
    }
    private float headlineMax = 44;
    /** The two-line headline shrinks until its longer line fits, from headlineMax down to 26 sp. */
    private void fitHeadline() {
        TextView view = headline;
        if (view == null) return;
        int width = view.getWidth() - view.getPaddingLeft() - view.getPaddingRight();
        if (width <= 0) { view.post(this::fitHeadline); return; }
        android.text.TextPaint paint = new android.text.TextPaint(view.getPaint());
        float size = headlineMax;
        for (; size > 26; size -= 2) {
            paint.setTextSize(android.util.TypedValue.applyDimension(android.util.TypedValue.COMPLEX_UNIT_SP, size, getResources().getDisplayMetrics()));
            float widest = 0;
            for (String line : view.getText().toString().split("\n")) widest = Math.max(widest, paint.measureText(line));
            if (widest <= width) break;
        }
        if (view.getTextSize() != android.util.TypedValue.applyDimension(android.util.TypedValue.COMPLEX_UNIT_SP, size, getResources().getDisplayMetrics())) view.setTextSize(size);
    }
    private void fillChecks(LinearLayout box, List<Row> rows, boolean notes) {
        box.removeAllViews();
        for (int i = 0; i < rows.size(); i++) {
            Row row = rows.get(i);
            int gap = !notes && screen == HOME && unfolded() ? 8 : 11; // the unfolded upper half must hold all five
            LinearLayout line = new LinearLayout(this); line.setGravity(notes ? Gravity.TOP : Gravity.CENTER_VERTICAL); line.setPadding(0, dp(gap), 0, dp(gap));
            View dot = new View(this); GradientDrawable shape = new GradientDrawable(); shape.setShape(GradientDrawable.OVAL);
            if (row.ring) shape.setStroke(dp(2), row.color); else shape.setColor(row.color);
            dot.setBackground(shape);
            LinearLayout.LayoutParams dotParams = new LinearLayout.LayoutParams(dp(10), dp(10)); dotParams.setMarginEnd(dp(12)); if (notes) dotParams.topMargin = dp(5);
            line.addView(dot, dotParams);
            LinearLayout column = new LinearLayout(this); column.setOrientation(LinearLayout.VERTICAL);
            LinearLayout head = new LinearLayout(this); head.setGravity(Gravity.CENTER_VERTICAL);
            head.addView(text(row.name, 15, p.text, true), new LinearLayout.LayoutParams(0, -2, 1));
            TextView value = text(row.value, 13, row.valueColor, true); head.addView(value);
            column.addView(head);
            if (notes) { TextView note = text(row.note, 12, p.muted, false); note.setPadding(0, dp(2), 0, 0); column.addView(note); }
            line.addView(column, new LinearLayout.LayoutParams(0, -2, 1));
            line.setContentDescription(row.name + ": " + row.value);
            box.addView(line);
            if (i < rows.size() - 1) { View rule = new View(this); rule.setBackgroundColor(p.rule); box.addView(rule, new LinearLayout.LayoutParams(-1, Math.max(1, dp(1) / 2))); }
        }
    }

    // ---- Home -------------------------------------------------------------------------

    private View homeScreen() {
        boolean split = unfolded();
        LinearLayout root = column(); root.setPadding(dp(20), dp(16), dp(20), dp(16));
        LinearLayout top = new LinearLayout(this); top.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout tag = new LinearLayout(this); tag.setGravity(Gravity.CENTER_VERTICAL); tag.setPadding(dp(12), dp(8), dp(12), dp(8)); tag.setBackground(glass(dp(16), p.chip));
        tagDot = new View(this); GradientDrawable dot = new GradientDrawable(); dot.setShape(GradientDrawable.OVAL); dot.setColor(stateColor()); tagDot.setBackground(dot);
        LinearLayout.LayoutParams dotParams = new LinearLayout.LayoutParams(dp(8), dp(8)); dotParams.setMarginEnd(dp(8)); tag.addView(tagDot, dotParams);
        tagText = text("", 12, p.muted, true); tagText.setLetterSpacing(0.08f); tagText.setMaxLines(1); tagText.setEllipsize(TextUtils.TruncateAt.END); tag.addView(tagText);
        LinearLayout.LayoutParams tagParams = new LinearLayout.LayoutParams(0, -2, 1); tagParams.setMarginEnd(dp(12));
        LinearLayout tagWrap = new LinearLayout(this); tagWrap.addView(tag); top.addView(tagWrap, tagParams);
        top.addView(circle(R.drawable.ic_settings, R.string.v3_settings, () -> show(ACTIONS)), new LinearLayout.LayoutParams(dp(44), dp(44)));

        headlineMax = split ? 34 : 44;
        headline = new TextView(this); headline.setTypeface(display()); headline.setTextSize(headlineMax); headline.setTextColor(p.text); headline.setLineSpacing(0, 0.95f); headline.setLetterSpacing(-0.02f);
        headline.addOnLayoutChangeListener((v, l, t, r, b, ol, ot, or, ob) -> { if (r - l != or - ol) v.post(this::fitHeadline); });
        description = text("", 14, p.muted, false); description.setLineSpacing(0, 1.2f); description.setPadding(0, dp(split ? 8 : 12), 0, dp(split ? 0 : 18));
        checksBox = column(); checksBox.setPadding(dp(16), dp(2), dp(16), dp(2)); checksBox.setBackground(rippled(glass(dp(24), p.card)));
        checksBox.setClickable(true); checksBox.setFocusable(true); checksBox.setOnClickListener(v -> show(CHECKS));
        LinearLayout header = new LinearLayout(this); header.setGravity(Gravity.CENTER_VERTICAL); header.setPadding(dp(4), split ? 0 : dp(20), 0, dp(10));
        TextView label = text(getString(R.string.v3_section_profiles).toUpperCase(Locale.getDefault()), 11, p.muted, true); label.setLetterSpacing(0.1f);
        header.addView(label, new LinearLayout.LayoutParams(0, -2, 1));
        TextView all = text(getString(R.string.v3_all_profiles) + "  →", 13, p.blueText, true); all.setPadding(dp(8), dp(6), 0, dp(6));
        all.setOnClickListener(v -> show(PROFILES)); header.addView(all);
        strip = column();
        slider = new SlideButton(this); slider.setAction(this::toggle);
        LinearLayout.LayoutParams sliderParams = new LinearLayout.LayoutParams(-1, dp(64)); sliderParams.topMargin = dp(12);

        if (!split) {
            root.addView(top);
            ScrollView scroll = new ScrollView(this); scroll.setVerticalScrollBarEnabled(false); scroll.setFillViewport(true);
            LinearLayout body = column(); body.setPadding(0, dp(18), 0, dp(8));
            body.addView(headline); body.addView(description); body.addView(checksBox); body.addView(header); body.addView(strip);
            scroll.addView(body); root.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
            root.addView(slider, sliderParams);
        } else {
            // Unfolded: one half holds the state and the five checks, the other the profiles
            // and the slider. The halves follow the fold: side by side when it runs top to
            // bottom, stacked when it runs across. The border sits on the screen's middle.
            boolean sideBySide = foldVertical();
            if (sideBySide) root.setOrientation(LinearLayout.HORIZONTAL);
            LinearLayout first = column(); first.addView(top);
            LinearLayout state = sideBySide ? column() : new LinearLayout(this); state.setPadding(0, dp(12), 0, 0);
            LinearLayout words = column(); words.addView(headline); words.addView(description);
            if (sideBySide) { state.addView(words); LinearLayout.LayoutParams checksParams = new LinearLayout.LayoutParams(-1, -2); checksParams.topMargin = dp(16); state.addView(checksBox, checksParams); }
            else { LinearLayout.LayoutParams wordsParams = new LinearLayout.LayoutParams(0, -2, 1); wordsParams.setMarginEnd(dp(16)); state.addView(words, wordsParams); state.addView(checksBox, new LinearLayout.LayoutParams(0, -2, 1)); }
            ScrollView firstScroll = new ScrollView(this); firstScroll.setVerticalScrollBarEnabled(false); firstScroll.addView(state);
            first.addView(firstScroll, new LinearLayout.LayoutParams(-1, 0, 1));
            LinearLayout second = column(); if (sideBySide) second.setPadding(dp(24), 0, 0, 0);
            ScrollView secondScroll = new ScrollView(this); secondScroll.setVerticalScrollBarEnabled(false);
            LinearLayout list = column(); list.setPadding(0, dp(sideBySide ? 4 : 24), 0, dp(8)); list.addView(header); list.addView(strip); secondScroll.addView(list);
            second.addView(secondScroll, new LinearLayout.LayoutParams(-1, 0, 1));
            second.addView(slider, sliderParams);
            root.addView(first, sideBySide ? new LinearLayout.LayoutParams(0, -1, 1) : new LinearLayout.LayoutParams(-1, 0, 1));
            root.addView(second, sideBySide ? new LinearLayout.LayoutParams(0, -1, 1) : new LinearLayout.LayoutParams(-1, 0, 1));
            root.addOnLayoutChangeListener((v, l, t, r, b, ol, ot, or, ob) -> alignToFold(root, first, sideBySide));
        }
        fillStrip();
        return root;
    }
    /** Ends the first half 12 dp before the screen's middle along the split axis. */
    private void alignToFold(View root, View first, boolean sideBySide) {
        int[] at = new int[2]; first.getLocationOnScreen(at);
        android.util.DisplayMetrics metrics = getResources().getDisplayMetrics();
        int middle = sideBySide ? metrics.widthPixels / 2 : metrics.heightPixels / 2;
        if (Build.VERSION.SDK_INT >= 30) {
            android.graphics.Rect bounds = getWindowManager().getCurrentWindowMetrics().getBounds();
            middle = sideBySide ? bounds.left + bounds.width() / 2 : bounds.top + bounds.height() / 2;
        }
        int size = middle - at[sideBySide ? 0 : 1] - dp(12);
        LinearLayout.LayoutParams params = (LinearLayout.LayoutParams) first.getLayoutParams();
        int current = sideBySide ? params.width : params.height;
        if (size <= dp(120) || current == size) return; // too small to split by the fold; keep equal weights
        if (sideBySide) params.width = size; else params.height = size;
        params.weight = 0;
        root.post(first::requestLayout);
    }
    /**
     * A book-style foldable (hinge sensor, large unfolded screen) has its fold top to
     * bottom in its natural orientation and across it when turned by 90 degrees.
     */
    private boolean foldVertical() {
        if (!getPackageManager().hasSystemFeature(android.content.pm.PackageManager.FEATURE_SENSOR_HINGE_ANGLE)) return false;
        int rotation = Build.VERSION.SDK_INT >= 30 ? getDisplay().getRotation() : getWindowManager().getDefaultDisplay().getRotation();
        return rotation == Surface.ROTATION_0 || rotation == Surface.ROTATION_180;
    }
    /**
     * Unfolded foldable or tablet: the window's shorter side is at least 600 dp. Folding
     * or unfolding recreates the activity, so the layout follows the posture.
     */
    private boolean unfolded() { return getResources().getConfiguration().smallestScreenWidthDp >= 600; }
    /** Up to this many profiles on Home; the rest are one tap away on the Profiles screen. */
    private static final int HOME_PROFILES = 5;
    /** Selected profile first, then its backups, then the rest; tap selects, long press opens actions. */
    private void fillStrip() {
        if (strip == null) return;
        strip.removeAllViews();
        if (profiles.isEmpty()) {
            LinearLayout empty = column(); empty.setPadding(dp(16), dp(14), dp(16), dp(14)); empty.setBackground(rippled(glass(dp(22), p.card)));
            empty.addView(text(getString(R.string.import_a_profile_to_get_started), 15, p.text, true));
            TextView hint = text(getString(R.string.empty_hint), 12, p.muted, false); hint.setPadding(0, dp(4), 0, 0); empty.addView(hint);
            empty.setClickable(true); empty.setOnClickListener(v -> show(ADD));
            strip.addView(empty, new LinearLayout.LayoutParams(-1, -2));
        }
        List<Info> ordered = new ArrayList<>();
        Info selected = info(selectedId); if (selected != null) ordered.add(selected);
        for (Info info : profiles) if (info != selected && backups.contains(info.id)) ordered.add(info);
        for (Info info : profiles) if (info != selected && !backups.contains(info.id)) ordered.add(info);
        for (Info info : ordered.subList(0, Math.min(HOME_PROFILES, ordered.size()))) {
            boolean isSelected = info == selected, live = info.id.equals(liveProfileId);
            LinearLayout card = new LinearLayout(this); card.setGravity(Gravity.CENTER_VERTICAL); card.setPadding(dp(12), dp(12), dp(14), dp(12));
            GradientDrawable bg = glass(dp(22), isSelected ? (p.light ? 0xB3FFFFFF : p.blueSoft) : p.card);
            if (isSelected) bg.setStroke(dp(1), Color.argb(140, Color.red(p.blueText), Color.green(p.blueText), Color.blue(p.blueText)));
            card.setBackground(rippled(bg)); card.setClickable(true); card.setFocusable(true);
            card.addView(badge(info), iconParams());
            LinearLayout texts = column();
            TextView title = text(info.name, 16, p.text, true); title.setMaxLines(1); title.setEllipsize(TextUtils.TruncateAt.END); texts.addView(title);
            TextView detail = text(info.protocol + (info.host.isEmpty() ? "" : " · " + info.host), 12, p.muted, false); detail.setMaxLines(1); detail.setEllipsize(TextUtils.TruncateAt.MIDDLE); detail.setPadding(0, dp(2), 0, 0); texts.addView(detail);
            card.addView(texts, new LinearLayout.LayoutParams(0, -2, 1));
            String label = live ? getString(R.string.v3_state_running) : isSelected ? getString(R.string.v3_state_selected) : backups.contains(info.id) ? getString(R.string.v3_label_backup).toLowerCase(Locale.getDefault()) : null;
            if (label != null) {
                TextView chip = text(label, 12, isSelected || live ? p.blueText : p.muted, true);
                chip.setPadding(dp(10), dp(5), dp(10), dp(5)); chip.setBackground(round(isSelected || live ? (p.light ? p.blueSoft : 0xFF1B3354) : p.chip, dp(12)));
                LinearLayout.LayoutParams chipParams = new LinearLayout.LayoutParams(-2, -2); chipParams.setMarginStart(dp(8)); card.addView(chip, chipParams);
            }
            card.setOnClickListener(v -> { selectedId = info.id; reload(); });
            card.setOnLongClickListener(v -> { profileActions(info); return true; });
            LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, -2); params.bottomMargin = dp(8);
            strip.addView(card, params);
        }
        if (ordered.size() > HOME_PROFILES) {
            TextView more = text(getResources().getQuantityString(R.plurals.v3_more_profiles, ordered.size() - HOME_PROFILES, ordered.size() - HOME_PROFILES), 14, p.blueText, true);
            more.setGravity(Gravity.CENTER); more.setPadding(0, dp(12), 0, dp(12)); more.setBackground(rippled(glass(dp(22), p.card)));
            more.setOnClickListener(v -> show(PROFILES));
            LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, -2); params.bottomMargin = dp(8); strip.addView(more, params);
        }
        LinearLayout add = row(R.drawable.ic_add, getString(R.string.add_profile), getString(R.string.v3_add_detail), () -> show(ADD), true);
        strip.addView(add, new LinearLayout.LayoutParams(-1, -2));
    }

    // ---- Profiles ---------------------------------------------------------------------

    private View profilesScreen() {
        LinearLayout root = column(); root.setPadding(dp(20), dp(16), dp(20), dp(16));
        LinearLayout header = header(getString(R.string.v3_profiles), false);
        TextView count = text(getString(R.string.v3_profiles_count, profiles.size()), 13, p.muted, true); header.addView(count);
        root.addView(header);
        search = field(getString(R.string.v3_profiles_search), false);
        LinearLayout.LayoutParams searchParams = new LinearLayout.LayoutParams(-1, dp(50)); searchParams.setMargins(0, dp(14), 0, dp(12));
        root.addView(search, searchParams);
        ScrollView scroll = new ScrollView(this); scroll.setVerticalScrollBarEnabled(false);
        list = column(); scroll.addView(list); root.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        search.addTextChangedListener(watcher(this::fillProfiles));
        TextView hint = text(getString(R.string.v3_profiles_hint), 12, p.muted, false); hint.setPadding(dp(4), dp(10), dp(4), dp(12)); root.addView(hint);
        root.addView(pill(getString(R.string.add_profile), R.drawable.ic_add, () -> show(ADD)), new LinearLayout.LayoutParams(-1, dp(58)));
        fillProfiles();
        return root;
    }
    private void fillProfiles() {
        if (list == null) return;
        list.removeAllViews();
        String query = search == null ? "" : search.getText().toString().trim();
        Info primary = info(selectedId);
        for (Info info : profiles) {
            if (!query.isEmpty() && !info.matches(query)) continue;
            LinearLayout card = new LinearLayout(this); card.setGravity(Gravity.CENTER_VERTICAL); card.setPadding(dp(14), dp(14), dp(6), dp(14));
            card.setBackground(rippled(glass(dp(24), p.card))); card.setClickable(true); card.setFocusable(true);
            card.addView(badge(info), new LinearLayout.LayoutParams(dp(44), dp(44)));
            LinearLayout texts = column(); texts.setPadding(dp(12), 0, dp(8), 0);
            LinearLayout titleRow = new LinearLayout(this); titleRow.setGravity(Gravity.CENTER_VERTICAL);
            TextView title = text(info.name, 16, p.text, true); title.setMaxLines(1); title.setEllipsize(TextUtils.TruncateAt.END);
            titleRow.addView(title, new LinearLayout.LayoutParams(0, -2, 1));
            if (info.isDefault) {
                ImageView star = new ImageView(this); star.setImageDrawable(tinted(R.drawable.ic_star, p.yellowText)); star.setContentDescription(getString(R.string.default_profile_label));
                LinearLayout.LayoutParams starParams = new LinearLayout.LayoutParams(dp(16), dp(16)); starParams.setMarginStart(dp(6)); titleRow.addView(star, starParams);
            }
            texts.addView(titleRow);
            TextView detail = text(info.protocol + (info.host.isEmpty() ? "" : " · " + info.host), 12, p.muted, false); detail.setMaxLines(1); detail.setEllipsize(TextUtils.TruncateAt.MIDDLE); detail.setPadding(0, dp(2), 0, dp(6));
            texts.addView(detail);
            MainActivity.Wrap tags = new MainActivity.Wrap(this, dp(6));
            tags.addView(tag(getString(info.server ? R.string.v3_tag_server : R.string.v3_tag_local)));
            if (primary != null && primary != info && backups.contains(info.id)) tags.addView(tag(getString(R.string.v3_tag_backup, primary.name)));
            if (info.managed != null) tags.addView(tag(info.managed));
            texts.addView(tags);
            card.addView(texts, new LinearLayout.LayoutParams(0, -2, 1));
            if (info.id.equals(liveProfileId) || info.id.equals(selectedId)) {
                boolean live = info.id.equals(liveProfileId);
                TextView chip = text(getString(live ? R.string.v3_state_running : R.string.v3_state_selected), 12, live ? p.blueText : p.muted, true);
                chip.setPadding(dp(10), dp(5), dp(10), dp(5)); chip.setBackground(round(live ? p.blueSoft : p.chip, dp(12)));
                card.addView(chip);
            }
            ImageButton more = new ImageButton(this); more.setImageDrawable(tinted(R.drawable.ic_more, p.muted)); more.setBackground(rippled(round(Color.TRANSPARENT, dp(22))));
            more.setContentDescription(getString(R.string.profile_menu)); more.setOnClickListener(v -> profileActions(info));
            card.addView(more, new LinearLayout.LayoutParams(dp(44), dp(44)));
            card.setOnClickListener(v -> { selectedId = info.id; reload(); home(); });
            card.setOnLongClickListener(v -> { profileActions(info); return true; });
            LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, -2); params.bottomMargin = dp(10);
            list.addView(card, params);
        }
        if (list.getChildCount() == 0) {
            TextView none = text(getString(profiles.isEmpty() ? R.string.import_a_profile_to_get_started : R.string.v3_no_match), 14, p.muted, false);
            none.setPadding(dp(4), dp(16), dp(4), dp(16)); list.addView(none);
        }
    }
    private View badge(Info info) {
        int fg, bgColor; String letters;
        if ("Hysteria 2".equals(info.protocol)) { letters = "H2"; fg = p.light ? 0xFF5B48C9 : 0xFFB9A6FF; bgColor = p.light ? 0xFFE6E0FF : 0xFF2A2340; }
        else if ("AmneziaWG".equals(info.protocol)) { letters = "AW"; fg = p.light ? 0xFF9A4A0C : 0xFFFFB27A; bgColor = p.light ? 0xFFFFE6D3 : 0xFF3A2A1C; }
        else { letters = "TT"; fg = p.blueText; bgColor = p.blueSoft; }
        TextView badge = text(letters, 13, fg, true); badge.setGravity(Gravity.CENTER); badge.setBackground(round(bgColor, dp(15)));
        badge.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        return badge;
    }
    private TextView tag(String value) {
        TextView tag = text(value, 12, p.muted, false); tag.setPadding(dp(10), dp(4), dp(10), dp(4)); tag.setBackground(round(p.chip, dp(10)));
        tag.setMaxLines(1); tag.setEllipsize(TextUtils.TruncateAt.END); return tag;
    }

    // ---- Add --------------------------------------------------------------------------

    private View addScreen() {
        LinearLayout root = column(); root.setPadding(dp(20), dp(16), dp(20), 0);
        root.addView(header(getString(R.string.v3_add_title), true));
        ScrollView scroll = new ScrollView(this); scroll.setVerticalScrollBarEnabled(false);
        LinearLayout body = column(); body.setPadding(0, dp(14), 0, dp(16));

        LinearLayout scan = column(); scan.setGravity(Gravity.CENTER); scan.setPadding(dp(16), dp(26), dp(16), dp(22));
        scan.setBackground(rippled(round(0xFF05070A, dp(28)))); scan.setClickable(true); scan.setFocusable(true); scan.setOnClickListener(v -> qrCamera());
        ImageView qr = new ImageView(this); qr.setImageDrawable(tinted(R.drawable.ic_qr, BUSY)); scan.addView(qr, new LinearLayout.LayoutParams(dp(72), dp(72)));
        TextView scanTitle = text(getString(R.string.v3_scan), 16, 0xFFF4F5F7, true); scanTitle.setPadding(0, dp(14), 0, dp(2)); scan.addView(scanTitle);
        scan.addView(text(getString(R.string.qr_camera_detail), 13, 0xFFC9D3E0, false));
        body.addView(scan);

        LinearLayout grid = new LinearLayout(this); grid.setPadding(0, dp(10), 0, dp(10));
        grid.addView(tile(R.drawable.ic_image, getString(R.string.v3_qr_photo), getString(R.string.qr_image_detail), false,
            () -> startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("image/*").addCategory(Intent.CATEGORY_OPENABLE), QR_IMAGE)), weight(true));
        grid.addView(tile(R.drawable.ic_file, getString(R.string.v3_file), getString(R.string.import_file_detail), false,
            () -> startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("*/*").addCategory(Intent.CATEGORY_OPENABLE), PICK)), weight(false));
        body.addView(grid);

        LinearLayout paste = column(); paste.setPadding(dp(14), dp(14), dp(14), dp(14)); paste.setBackground(glass(dp(22), p.card));
        paste.addView(text(getString(R.string.v3_paste_title), 15, p.text, true));
        EditText input = field(getString(R.string.v3_paste_hint), true);
        LinearLayout.LayoutParams inputParams = new LinearLayout.LayoutParams(-1, -2); inputParams.setMargins(0, dp(10), 0, dp(8)); paste.addView(input, inputParams);
        TextView note = text(getString(R.string.v3_paste_note), 12, p.muted, false); paste.addView(note);
        TextView previewButton = text(getString(R.string.preview), 14, p.onBlue, true); previewButton.setGravity(Gravity.CENTER);
        previewButton.setBackground(rippled(round(p.light ? p.blueText : p.blue, dp(14)))); previewButton.setPadding(dp(18), 0, dp(18), 0);
        previewButton.setOnClickListener(v -> { String raw = input.getText().toString(); input.setText(""); if (!raw.trim().isEmpty()) preview(raw); });
        LinearLayout.LayoutParams buttonParams = new LinearLayout.LayoutParams(-2, dp(44)); buttonParams.topMargin = dp(10); buttonParams.gravity = Gravity.END;
        paste.addView(previewButton, buttonParams);
        body.addView(paste);

        String portalDetail = portalHost == null ? getString(R.string.v3_portal_detail) : getString(R.string.portal_enrolled_detail, portalHost);
        LinearLayout portal = row(R.drawable.ic_cloud, getString(portalHost == null ? R.string.v3_portal : R.string.portal_title), portalDetail, () -> new PortalDialog(this, vault, this::reload).show());
        LinearLayout.LayoutParams portalParams = new LinearLayout.LayoutParams(-1, -2); portalParams.topMargin = dp(10);
        body.addView(portal, portalParams);

        LinearLayout footer = new LinearLayout(this); footer.setGravity(Gravity.CENTER_VERTICAL); footer.setPadding(dp(4), dp(16), dp(4), 0);
        ImageView lock = new ImageView(this); lock.setImageDrawable(tinted(R.drawable.ic_lock, p.muted));
        LinearLayout.LayoutParams lockParams = new LinearLayout.LayoutParams(dp(18), dp(18)); lockParams.setMarginEnd(dp(10)); footer.addView(lock, lockParams);
        footer.addView(text(getString(R.string.v3_encrypted_note), 12, p.muted, false), new LinearLayout.LayoutParams(0, -2, 1));
        body.addView(footer);
        scroll.addView(body); root.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        return root;
    }

    // ---- Checks -----------------------------------------------------------------------

    private View checksScreen() {
        LinearLayout root = column(); root.setPadding(dp(20), dp(16), dp(20), 0);
        LinearLayout header = header(getString(R.string.checks_title), false);
        stateChip = text("", 12, p.text, true); stateChip.setPadding(dp(10), dp(6), dp(10), dp(6)); header.addView(stateChip);
        root.addView(header);
        ScrollView scroll = new ScrollView(this); scroll.setVerticalScrollBarEnabled(false);
        LinearLayout body = column(); body.setPadding(0, dp(14), 0, dp(16));
        checksBox = column(); checksBox.setPadding(dp(16), dp(2), dp(16), dp(2)); checksBox.setBackground(glass(dp(24), p.card)); body.addView(checksBox);
        checkedAt = text("", 12, p.muted, false); checkedAt.setPadding(dp(4), dp(10), dp(4), 0); body.addView(checkedAt);
        String live = TunnelService.active ? null : getString(R.string.needs_connection);
        LinearLayout actions = column(); actions.setPadding(dp(4), dp(4), dp(4), dp(4)); actions.setBackground(glass(dp(24), p.card));
        actions.addView(row(R.drawable.ic_sync, getString(R.string.v3_recheck), live != null ? live : getString(R.string.v3_recheck_detail), this::recheck, false));
        actions.addView(row(R.drawable.ic_search, getString(R.string.diagnostics_title), live != null ? live : getString(R.string.diagnostics_detail), () -> live(DiagnosticsDialog::show), false));
        actions.addView(row(R.drawable.ic_eye, getString(R.string.flow_capture_title), live != null ? live : getString(R.string.flow_capture_detail), () -> live(FlowCaptureDialog::show), false));
        actions.addView(row(R.drawable.ic_tune, getString(R.string.flow_policy_title), live != null ? live : getString(R.string.flow_policy_detail), () -> live(FlowPolicyDialog::show), false));
        LinearLayout.LayoutParams actionsParams = new LinearLayout.LayoutParams(-1, -2); actionsParams.topMargin = dp(14); body.addView(actions, actionsParams);
        TextView note = text(getString(R.string.checks_note), 12, p.muted, false); note.setLineSpacing(0, 1.2f); note.setPadding(dp(4), dp(14), dp(4), 0); body.addView(note);
        scroll.addView(body); root.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        return root;
    }

    // ---- VPN apps ---------------------------------------------------------------------

    /** Unsaved selection; lives while the apps screen is open, including theme recreation. */
    private static final class Picker {
        boolean selectedOnly; final Set<String> selected = new TreeSet<>();
        List<String[]> apps; // {package, label}; null while loading
        int generation;
    }
    private Picker picker;
    private final Map<String, View> appRows = new HashMap<>();
    private TextView appsMessage, appsCount;
    private LinearLayout appsList;
    private void openApps() {
        try {
            AppRouting current = AppRouting.read(vault.read());
            picker = new Picker(); picker.selectedOnly = current.selectedOnly; picker.selected.addAll(current.packages);
            show(APPS);
        } catch (Exception error) { error(getString(R.string.app_selection_could_not_be_opened)); }
    }
    private View appsScreen() {
        if (picker == null) { openApps(); if (picker == null) return column(); }
        appRows.clear();
        LinearLayout root = column(); root.setPadding(dp(20), dp(16), dp(20), dp(16));
        root.addView(header(getString(R.string.apps_using_vpn), false));

        LinearLayout modes = new LinearLayout(this); modes.setPadding(dp(4), dp(4), dp(4), dp(4)); modes.setBackground(glass(dp(24), p.chip));
        TextView all = segment(getString(R.string.all_apps)), only = segment(getString(R.string.only_selected_apps));
        modes.addView(all, weight(false)); modes.addView(only, weight(false));
        LinearLayout.LayoutParams modesParams = new LinearLayout.LayoutParams(-1, dp(52)); modesParams.setMargins(0, dp(16), 0, dp(8));
        root.addView(modes, modesParams);
        TextView explain = text("", 12, p.muted, false); explain.setLineSpacing(0, 1.15f); explain.setPadding(dp(4), 0, dp(4), dp(12)); root.addView(explain);

        EditText query = field(getString(R.string.search_apps), false);
        root.addView(query, new LinearLayout.LayoutParams(-1, dp(50)));
        appsCount = text("", 12, p.muted, true); appsCount.setLetterSpacing(0.08f); appsCount.setPadding(dp(4), dp(14), 0, dp(8)); root.addView(appsCount);
        ScrollView scroll = new ScrollView(this); scroll.setVerticalScrollBarEnabled(false);
        appsList = column(); appsList.setPadding(dp(4), dp(4), dp(4), dp(4)); appsList.setBackground(glass(dp(24), p.card)); scroll.addView(appsList);
        root.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        appsMessage = text("", 13, p.muted, false); appsMessage.setPadding(dp(4), dp(10), dp(4), dp(10)); root.addView(appsMessage);
        root.addView(pill(getString(R.string.save), R.drawable.ic_check, this::saveApps), new LinearLayout.LayoutParams(-1, dp(58)));

        Runnable mode = () -> {
            boolean selected = picker.selectedOnly;
            styleSegment(all, !selected); styleSegment(only, selected);
            explain.setText(selected ? R.string.unselected_apps_connect_directly_or_have : R.string.v3_apps_all_detail);
            query.setEnabled(selected); query.setAlpha(selected ? 1f : 0.5f);
            appsList.setAlpha(selected ? 1f : 0.45f);
            for (View row : appRows.values()) row.setEnabled(selected);
            countApps();
        };
        all.setOnClickListener(v -> { picker.selectedOnly = false; mode.run(); });
        only.setOnClickListener(v -> { picker.selectedOnly = true; mode.run(); });
        query.addTextChangedListener(watcher(() -> filterApps(query.getText().toString())));
        if (TunnelService.active) { appsMessage.setText(R.string.disconnect_vpn_before_saving_changes_your); appsMessage.setTextColor(p.yellowText); }
        if (picker.apps == null) { loadApps(() -> { fillApps(); mode.run(); filterApps(query.getText().toString()); }); appsList.addView(text(getString(R.string.v3_apps_loading), 14, p.muted, false)); }
        else fillApps();
        mode.run();
        return root;
    }
    private TextView segment(String title) {
        TextView view = text(title, 14, p.muted, true); view.setGravity(Gravity.CENTER); view.setMaxLines(1); view.setEllipsize(TextUtils.TruncateAt.END);
        view.setClickable(true); view.setFocusable(true); return view;
    }
    private void styleSegment(TextView view, boolean on) {
        view.setTextColor(on ? p.blueText : p.muted);
        view.setBackground(rippled(round(on ? (p.light ? 0xE6FFFFFF : p.blueSoft) : Color.TRANSPARENT, dp(20))));
        view.setSelected(on);
    }
    /** Installed apps with Internet access, plus saved ones that are gone so they can be unchecked. */
    private void loadApps(Runnable done) {
        Picker target = picker; int generation = ++target.generation;
        android.content.pm.PackageManager pm = getPackageManager();
        String self = getPackageName();
        Set<String> chosen = new HashSet<>(target.selected);
        String unavailable = getString(R.string.unavailable_app);
        new Thread(() -> {
            List<String[]> apps = new ArrayList<>(); Set<String> known = new HashSet<>();
            for (android.content.pm.ApplicationInfo app : pm.getInstalledApplications(0)) {
                if (app.packageName.equals(self)) continue;
                if (pm.checkPermission("android.permission.INTERNET", app.packageName) != android.content.pm.PackageManager.PERMISSION_GRANTED && !chosen.contains(app.packageName)) continue;
                apps.add(new String[]{app.packageName, app.loadLabel(pm).toString()}); known.add(app.packageName);
            }
            for (String name : chosen) if (!known.contains(name)) apps.add(new String[]{name, unavailable});
            apps.sort(Comparator.comparing((String[] app) -> !chosen.contains(app[0])).thenComparing(app -> app[1], String.CASE_INSENSITIVE_ORDER).thenComparing(app -> app[0]));
            runOnUiThread(() -> {
                if (isDestroyed() || picker != target || target.generation != generation) return;
                target.apps = apps; if (screen == APPS) done.run();
            });
        }, "vpn-apps").start();
    }
    private void fillApps() {
        if (appsList == null || picker.apps == null) return;
        appsList.removeAllViews(); appRows.clear();
        for (String[] app : picker.apps) {
            String name = app[0];
            LinearLayout row = new LinearLayout(this); row.setGravity(Gravity.CENTER_VERTICAL); row.setPadding(dp(10), dp(8), dp(10), dp(8)); row.setMinimumHeight(dp(60));
            row.setBackground(rippled(round(Color.TRANSPARENT, dp(18))));
            ImageView icon = new ImageView(this); icon.setTag(name);
            icon.setImageDrawable(tinted(R.drawable.ic_apps, p.muted)); icon.setPadding(dp(8), dp(8), dp(8), dp(8)); icon.setBackground(round(p.chip, dp(12)));
            row.addView(icon, iconParams());
            LinearLayout texts = column();
            TextView label = text(app[1], 15, p.text, true); label.setMaxLines(1); label.setEllipsize(TextUtils.TruncateAt.END); texts.addView(label);
            TextView pkg = text(name, 12, p.muted, false); pkg.setMaxLines(1); pkg.setEllipsize(TextUtils.TruncateAt.MIDDLE); texts.addView(pkg);
            row.addView(texts, new LinearLayout.LayoutParams(0, -2, 1));
            ImageView check = new ImageView(this); check.setPadding(dp(4), dp(4), dp(4), dp(4));
            LinearLayout.LayoutParams checkParams = new LinearLayout.LayoutParams(dp(26), dp(26)); checkParams.setMarginStart(dp(10)); row.addView(check, checkParams);
            Runnable paint = () -> {
                boolean on = picker.selected.contains(name);
                GradientDrawable mark = new GradientDrawable(); mark.setShape(GradientDrawable.OVAL);
                if (on) mark.setColor(p.light ? p.blueText : p.blue); else mark.setStroke(dp(2), p.empty);
                check.setBackground(mark); check.setImageDrawable(on ? tinted(R.drawable.ic_check, p.light ? Color.WHITE : p.onBlue) : null);
                row.setContentDescription(app[1] + (on ? ", " + getString(R.string.v3_state_selected) : ""));
            };
            paint.run();
            row.setOnClickListener(v -> {
                if (!picker.selectedOnly) return;
                if (!picker.selected.remove(name)) picker.selected.add(name);
                paint.run(); countApps();
            });
            row.setEnabled(picker.selectedOnly);
            appRows.put(name, row); appsList.addView(row);
        }
        countApps(); loadIcons();
    }
    /** Icons arrive after the list, on one background thread, only for the open screen. */
    private void loadIcons() {
        Picker target = picker; int generation = target.generation;
        android.content.pm.PackageManager pm = getPackageManager();
        List<String> names = new ArrayList<>(appRows.keySet());
        new Thread(() -> {
            for (String name : names) {
                Drawable icon;
                try { icon = pm.getApplicationIcon(name); } catch (Exception missing) { continue; }
                runOnUiThread(() -> {
                    if (isDestroyed() || picker != target || target.generation != generation) return;
                    View row = appRows.get(name); if (row == null) return;
                    ImageView view = (ImageView) ((ViewGroup) row).getChildAt(0);
                    view.setPadding(0, 0, 0, 0); view.setBackground(null); view.setImageDrawable(icon);
                });
                if (isDestroyed() || picker != target) return;
            }
        }, "vpn-app-icons").start();
    }
    private void filterApps(String query) {
        String q = query.trim().toLowerCase(Locale.ROOT);
        if (picker == null || picker.apps == null) return;
        for (String[] app : picker.apps) {
            View row = appRows.get(app[0]); if (row == null) continue;
            row.setVisibility(q.isEmpty() || app[0].toLowerCase(Locale.ROOT).contains(q) || app[1].toLowerCase(Locale.ROOT).contains(q) ? View.VISIBLE : View.GONE);
        }
    }
    private void countApps() {
        if (appsCount != null) appsCount.setText(getString(R.string.selected_count, picker.selected.size()).toUpperCase(Locale.getDefault()));
    }
    private void saveApps() {
        if (TunnelService.active) { appsMessage.setText(R.string.disconnect_vpn_before_saving_changes_your); appsMessage.setTextColor(p.yellowText); return; }
        try {
            AppRouting next = new AppRouting(picker.selectedOnly, picker.selected);
            next.validateInstalled(getPackageManager());
            vault.saveAppRouting(next);
            picker = null; reload(); goBack();
        } catch (android.content.pm.PackageManager.NameNotFoundException error) { appsMessage.setText(R.string.a_selected_app_is_no_longer); appsMessage.setTextColor(p.redText); }
        catch (IllegalArgumentException error) { appsMessage.setText(R.string.select_at_least_one_installed_app); appsMessage.setTextColor(p.redText); }
        catch (Exception error) { appsMessage.setText(R.string.could_not_save_app_selection_existing); appsMessage.setTextColor(p.redText); }
    }

    // ---- Actions ----------------------------------------------------------------------

    private static final class Entry {
        final int icon; final String title, detail; final Runnable action; final boolean wide;
        Entry(int icon, String title, String detail, Runnable action, boolean wide) { this.icon = icon; this.title = title; this.detail = detail; this.action = action; this.wide = wide; }
    }
    private View actionsScreen() {
        LinearLayout root = column(); root.setPadding(dp(20), dp(16), dp(20), 0);
        LinearLayout top = new LinearLayout(this); top.setGravity(Gravity.CENTER_VERTICAL);
        top.addView(circle(R.drawable.ic_chevron_back, R.string.v3_back, this::goBack), new LinearLayout.LayoutParams(dp(44), dp(44)));
        search = field(getString(R.string.v3_actions_search), false);
        LinearLayout.LayoutParams searchParams = new LinearLayout.LayoutParams(0, dp(50), 1); searchParams.setMarginStart(dp(10));
        top.addView(search, searchParams);
        root.addView(top);
        ScrollView scroll = new ScrollView(this); scroll.setVerticalScrollBarEnabled(false);
        results = column(); results.setPadding(0, dp(8), 0, dp(16)); scroll.addView(results);
        root.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        search.addTextChangedListener(watcher(this::fillActions));
        fillActions();
        return root;
    }
    private void fillActions() {
        if (results == null) return;
        results.removeAllViews();
        String live = TunnelService.active ? null : getString(R.string.needs_connection);
        List<Entry> actions = Arrays.asList(
            new Entry(R.drawable.ic_search, getString(R.string.diagnostics_title), live != null ? live : getString(R.string.diagnostics_detail), () -> live(DiagnosticsDialog::show), false),
            new Entry(R.drawable.ic_eye, getString(R.string.flow_capture_title), live != null ? live : getString(R.string.flow_capture_detail), () -> live(FlowCaptureDialog::show), false),
            new Entry(R.drawable.ic_tune, getString(R.string.flow_policy_title), live != null ? live : getString(R.string.flow_policy_detail), () -> live(FlowPolicyDialog::show), false),
            new Entry(R.drawable.ic_restore, getString(R.string.recovery_menu), getString(R.string.recovery_menu_detail), () -> recovery(selectedId), false));
        String always = TunnelService.active ? getString(TunnelService.alwaysOn ? R.string.v3_on : R.string.v3_off) : getString(R.string.v3_android_settings);
        String mode = Palette.mode(this);
        String theme = getString(Palette.MODE_DARK.equals(mode) ? R.string.v3_theme_dark : Palette.MODE_LIGHT.equals(mode) ? R.string.v3_theme_light : R.string.v3_theme_system);
        List<Entry> rest = Arrays.asList(
            new Entry(R.drawable.ic_add, getString(R.string.add_profile), getString(R.string.v3_add_detail), () -> show(ADD), true),
            new Entry(R.drawable.ic_apps, getString(R.string.vpn_apps), routingSummary, this::openApps, false),
            new Entry(R.drawable.ic_lock, getString(R.string.v3_always_short), always, this::vpnSettings, false),
            new Entry(R.drawable.ic_cloud, getString(R.string.settings_server), portalHost == null ? getString(R.string.portal_not_enrolled) : portalHost, () -> new PortalDialog(this, vault, this::reload).show(), false),
            new Entry(R.drawable.ic_sync, getString(R.string.v3_traffic), getString(TunnelService.inheritMetering(this) ? R.string.metering_detail_inherit : R.string.metering_detail_always), this::meteringSettings, false),
            new Entry(R.drawable.ic_eye, getString(R.string.v3_theme), theme, this::themeSettings, false));
        String query = search == null ? "" : search.getText().toString().trim().toLowerCase(Locale.getDefault());
        if (query.isEmpty()) {
            results.addView(section(R.string.v3_section_actions));
            LinearLayout group = column(); group.setPadding(dp(4), dp(4), dp(4), dp(4)); group.setBackground(glass(dp(24), p.card));
            for (Entry entry : actions) group.addView(row(entry.icon, entry.title, entry.detail, entry.action, false));
            results.addView(group);
            results.addView(section(R.string.v3_section_rest));
            LinearLayout pair = null;
            for (Entry entry : rest) {
                if (entry.wide) {
                    LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, -2); params.bottomMargin = dp(10);
                    results.addView(tile(entry.icon, entry.title, entry.detail, true, entry.action), params); continue;
                }
                if (pair == null) { pair = new LinearLayout(this); LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, -2); params.bottomMargin = dp(10); results.addView(pair, params); pair.addView(tile(entry.icon, entry.title, entry.detail, false, entry.action), weight(true)); }
                else { pair.addView(tile(entry.icon, entry.title, entry.detail, false, entry.action), weight(false)); pair = null; }
            }
            String version = "";
            try { version = getPackageManager().getPackageInfo(getPackageName(), 0).versionName; } catch (Exception ignored) { /* Footer only. */ }
            TextView footer = text(getString(R.string.app_version, version), 12, p.muted, false); footer.setPadding(dp(4), dp(10), 0, 0); results.addView(footer);
            return;
        }
        List<Entry> matches = new ArrayList<>();
        for (List<Entry> group : Arrays.asList(actions, rest)) for (Entry entry : group)
            if ((entry.title + " " + entry.detail).toLowerCase(Locale.getDefault()).contains(query)) matches.add(entry);
        if (!matches.isEmpty()) {
            results.addView(section(R.string.v3_section_actions));
            LinearLayout group = column(); group.setPadding(dp(4), dp(4), dp(4), dp(4)); group.setBackground(glass(dp(24), p.card));
            for (Entry entry : matches) group.addView(row(entry.icon, entry.title, entry.detail, entry.action, false));
            results.addView(group);
        }
        LinearLayout found = column(); found.setPadding(dp(4), dp(4), dp(4), dp(4)); found.setBackground(glass(dp(24), p.card));
        for (Info info : profiles) if (info.matches(query)) {
            LinearLayout entry = row(0, info.name, info.protocol + (info.host.isEmpty() ? "" : " · " + info.host), () -> { selectedId = info.id; reload(); home(); }, false);
            ((ViewGroup) entry).removeViewAt(0); ((ViewGroup) entry).addView(badge(info), 0, iconParams());
            found.addView(entry);
        }
        if (found.getChildCount() > 0) { results.addView(section(R.string.v3_section_profiles)); results.addView(found); }
        if (results.getChildCount() == 0) { TextView none = text(getString(R.string.v3_no_match), 14, p.muted, false); none.setPadding(dp(4), dp(16), 0, 0); results.addView(none); }
    }
    private void themeSettings() {
        String mode = Palette.mode(this);
        String[] modes = {Palette.MODE_SYSTEM, Palette.MODE_DARK, Palette.MODE_LIGHT};
        int[] names = {R.string.v3_theme_system, R.string.v3_theme_dark, R.string.v3_theme_light};
        Sheet sheet = new Sheet(this, getString(R.string.v3_theme), null);
        for (int i = 0; i < modes.length; i++) {
            String next = modes[i];
            sheet.item(next.equals(mode) ? R.drawable.ic_check : 0, getString(names[i]), null, () -> { if (!next.equals(Palette.mode(this))) { Palette.setMode(this, next); recreate(); } });
        }
        sheet.show();
    }

    // ---- Building blocks --------------------------------------------------------------

    private int dp(int n) { return Math.round(n * getResources().getDisplayMetrics().density); }
    private static Typeface display() { return Typeface.create(Typeface.SANS_SERIF, 800, false); }
    private LinearLayout column() { LinearLayout column = new LinearLayout(this); column.setOrientation(LinearLayout.VERTICAL); return column; }
    private TextView text(String value, int size, int color, boolean bold) {
        TextView view = new TextView(this); view.setText(value); view.setTextSize(size); view.setTextColor(color);
        if (bold) view.setTypeface(Typeface.create(Typeface.SANS_SERIF, 700, false)); return view;
    }
    private GradientDrawable round(int fill, int radius) { GradientDrawable bg = new GradientDrawable(); bg.setColor(fill); bg.setCornerRadius(radius); return bg; }
    /** Card surface: opaque in the dark theme, translucent with a light rim in the light (glass) theme. */
    private GradientDrawable glass(int radius, int fill) { GradientDrawable bg = round(fill, radius); bg.setStroke(Math.max(1, dp(1)), p.cardStroke); return bg; }
    private Drawable rippled(Drawable content) { return new RippleDrawable(ColorStateList.valueOf(p.ripple), content, content); }
    private Drawable tinted(int id, int tint) { Drawable icon = getDrawable(id).mutate(); icon.setTint(tint); return icon; }
    private LinearLayout.LayoutParams weight(boolean gap) { LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(0, -1, 1); if (gap) params.setMarginEnd(dp(10)); return params; }
    private LinearLayout.LayoutParams iconParams() { LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(dp(40), dp(40)); params.setMarginEnd(dp(12)); return params; }
    private ImageButton circle(int icon, int description, Runnable click) {
        ImageButton button = new ImageButton(this); button.setImageDrawable(tinted(icon, p.text)); button.setBackground(rippled(glass(dp(22), p.chip)));
        button.setContentDescription(getString(description)); button.setOnClickListener(v -> click.run()); return button;
    }
    private LinearLayout header(String title, boolean close) {
        LinearLayout header = new LinearLayout(this); header.setGravity(Gravity.CENTER_VERTICAL);
        header.addView(circle(close ? R.drawable.ic_close : R.drawable.ic_chevron_back, close ? R.string.v3_close : R.string.v3_back, this::goBack), new LinearLayout.LayoutParams(dp(44), dp(44)));
        TextView text = new TextView(this); text.setText(title); text.setTypeface(display()); text.setTextSize(26); text.setTextColor(p.text); text.setMaxLines(1); text.setEllipsize(TextUtils.TruncateAt.END);
        text.setPadding(dp(12), 0, dp(8), 0); header.addView(text, new LinearLayout.LayoutParams(0, -2, 1));
        return header;
    }
    private TextView section(int title) {
        TextView label = text(getString(title).toUpperCase(Locale.getDefault()), 11, p.muted, true); label.setLetterSpacing(0.1f); label.setPadding(dp(4), dp(16), 0, dp(8));
        return label;
    }
    private EditText field(String hint, boolean multiline) {
        EditText input = new EditText(this); input.setHint(hint); input.setTextColor(p.text); input.setHintTextColor(p.muted); input.setTextSize(15);
        input.setBackground(glass(dp(multiline ? 14 : 25), multiline ? p.field : p.card)); input.setPadding(dp(16), dp(10), dp(16), dp(10));
        input.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        input.setImeOptions(android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING);
        if (multiline) {
            input.setMinLines(3); input.setMaxLines(8); input.setGravity(Gravity.TOP | Gravity.START);
            input.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE | android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
            input.setFilters(new android.text.InputFilter[]{new android.text.InputFilter.LengthFilter(1024 * 1024)});
        } else {
            input.setSingleLine(true); input.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        }
        return input;
    }
    private static TextWatcher watcher(Runnable changed) {
        return new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) { }
            public void onTextChanged(CharSequence s, int start, int before, int count) { changed.run(); }
            public void afterTextChanged(Editable value) { }
        };
    }
    private TextView pill(String title, int icon, Runnable click) {
        TextView pill = text(title, 16, p.light ? Color.WHITE : p.onBlue, true); pill.setGravity(Gravity.CENTER);
        pill.setCompoundDrawablesRelativeWithIntrinsicBounds(tinted(icon, p.light ? Color.WHITE : p.onBlue), null, null, null); pill.setCompoundDrawablePadding(dp(10));
        pill.setPadding(dp(20), 0, dp(20), 0); pill.setBackground(rippled(round(p.light ? p.blueText : p.blue, dp(29))));
        pill.setClickable(true); pill.setFocusable(true); pill.setOnClickListener(v -> click.run()); return pill;
    }
    private LinearLayout row(int icon, String title, String detail, Runnable click) { return row(icon, title, detail, click, true); }
    /** Icon tile, title and detail. As a standalone card it carries its own glass surface. */
    private LinearLayout row(int icon, String title, String detail, Runnable click, boolean card) {
        LinearLayout row = new LinearLayout(this); row.setGravity(Gravity.CENTER_VERTICAL); row.setMinimumHeight(dp(60));
        row.setPadding(dp(card ? 14 : 10), dp(10), dp(10), dp(10));
        row.setBackground(rippled(card ? glass(dp(22), p.card) : round(Color.TRANSPARENT, dp(18))));
        ImageView image = new ImageView(this); if (icon != 0) image.setImageDrawable(tinted(icon, p.blueText)); image.setPadding(dp(9), dp(9), dp(9), dp(9)); image.setBackground(round(p.blueSoft, dp(14)));
        row.addView(image, iconParams());
        LinearLayout texts = column();
        texts.addView(text(title, 15, p.text, true));
        if (detail != null && !detail.isEmpty()) { TextView sub = text(detail, 12, p.muted, false); sub.setPadding(0, dp(2), 0, 0); sub.setMaxLines(2); sub.setEllipsize(TextUtils.TruncateAt.END); texts.addView(sub); }
        row.addView(texts, new LinearLayout.LayoutParams(0, -2, 1));
        row.setClickable(true); row.setFocusable(true); row.setOnClickListener(v -> click.run());
        return row;
    }
    /** Bento tile; the wide one is the filled primary action. */
    private LinearLayout tile(int icon, String title, String detail, boolean primary, Runnable click) {
        LinearLayout tile = column(); tile.setPadding(dp(16), dp(16), dp(16), dp(16));
        int fg = primary ? (p.light ? Color.WHITE : p.onBlue) : p.text;
        tile.setBackground(rippled(primary ? round(p.light ? p.blueText : p.blue, dp(22)) : glass(dp(22), p.card)));
        if (primary) { tile.setOrientation(LinearLayout.HORIZONTAL); tile.setGravity(Gravity.CENTER_VERTICAL); }
        ImageView image = new ImageView(this); image.setImageDrawable(tinted(icon, fg));
        LinearLayout.LayoutParams imageParams = new LinearLayout.LayoutParams(dp(24), dp(24)); if (primary) imageParams.setMarginEnd(dp(12)); else imageParams.bottomMargin = dp(10);
        tile.addView(image, imageParams);
        TextView head = text(title, 15, fg, true); head.setMaxLines(2);
        if (primary) tile.addView(head, new LinearLayout.LayoutParams(0, -2, 1)); else tile.addView(head);
        TextView sub = text(detail, 12, primary ? fg : p.muted, false); sub.setMaxLines(2); sub.setEllipsize(TextUtils.TruncateAt.END); if (!primary) sub.setPadding(0, dp(4), 0, 0);
        tile.addView(sub);
        tile.setClickable(true); tile.setFocusable(true); tile.setOnClickListener(v -> click.run());
        return tile;
    }
    /** Left-to-right rows that wrap, for tags on narrow phones. */
    static final class Wrap extends ViewGroup {
        private final int gap;
        Wrap(Context context, int gap) { super(context); this.gap = gap; }
        @Override protected void onMeasure(int widthSpec, int heightSpec) {
            int width = MeasureSpec.getSize(widthSpec) - getPaddingLeft() - getPaddingRight(), x = 0, y = 0, line = 0;
            for (int i = 0; i < getChildCount(); i++) {
                View child = getChildAt(i); child.measure(MeasureSpec.makeMeasureSpec(width, MeasureSpec.AT_MOST), MeasureSpec.makeMeasureSpec(0, MeasureSpec.UNSPECIFIED));
                if (x > 0 && x + child.getMeasuredWidth() > width) { x = 0; y += line + gap; line = 0; }
                x += child.getMeasuredWidth() + gap; line = Math.max(line, child.getMeasuredHeight());
            }
            setMeasuredDimension(MeasureSpec.getSize(widthSpec), y + line + getPaddingTop() + getPaddingBottom());
        }
        @Override protected void onLayout(boolean changed, int l, int t, int r, int b) {
            int width = r - l - getPaddingLeft() - getPaddingRight(), x = 0, y = 0, line = 0;
            for (int i = 0; i < getChildCount(); i++) {
                View child = getChildAt(i);
                if (x > 0 && x + child.getMeasuredWidth() > width) { x = 0; y += line + gap; line = 0; }
                child.layout(getPaddingLeft() + x, getPaddingTop() + y, getPaddingLeft() + x + child.getMeasuredWidth(), getPaddingTop() + y + child.getMeasuredHeight());
                x += child.getMeasuredWidth() + gap; line = Math.max(line, child.getMeasuredHeight());
            }
        }
    }

    // ---- Data -------------------------------------------------------------------------

    /** The profile marked connected: only a connected primary, never while connecting, failing or on a backup. */
    static String badgeProfile(boolean connected, int backup, String requested) { return connected && backup == 0 ? requested : null; }
    /**
     * Lifecycle colour. A running tunnel is blue, never green: green needs every check
     * passed and fresh (ObservationStatus.level). Yellow is reserved for failed checks.
     */
    static int connectionColor(boolean active, int state, boolean problem) {
        if (problem || state == 4 || state < 0 || state > 4) return ERROR;
        if (!active) return IDLE;
        return state == 2 ? ON : BUSY;
    }
    /** Re-reads display data from the vault and refreshes the visible screen. */
    private void reload() {
        profiles.clear(); backups.clear(); portalHost = null;
        try {
            JSONObject data = vault.read(); JSONArray entries = data.getJSONArray("profiles");
            AppRouting selection = AppRouting.read(data);
            routingSummary = selection.selectedOnly ? getString(R.string.selected_count, selection.packages.size()) : getString(R.string.all_apps);
            routingExcludesSelf = selection.selectedOnly && !selection.packages.contains(getPackageName());
            JSONObject session = data.optJSONObject("portal");
            if (session != null) portalHost = Uri.parse(session.optString("origin")).getHost();
            boolean found = false;
            for (int i = 0; i < entries.length(); i++) if (entries.getJSONObject(i).getString("id").equals(selectedId)) found = true;
            if (!found) selectedId = data.optString("default");
            for (int i = 0; i < entries.length(); i++) {
                JSONObject item = entries.getJSONObject(i), profile = item.getJSONObject("profile");
                Info info = new Info(); info.id = item.getString("id");
                info.name = profile.optString("name"); if (info.name.trim().isEmpty()) info.name = "Profile " + (i + 1);
                info.protocol = protocolName(profile);
                info.host = profile.optJSONObject("endpoint") == null ? "" : profile.getJSONObject("endpoint").optString("hostname");
                info.isDefault = info.id.equals(data.getString("default"));
                info.server = item.has("remote_id");
                JSONObject managed = item.optJSONObject("managed_routing");
                if (managed != null) info.managed = getString(managed.getString("revision").startsWith("admin:") ? R.string.routing_admin : R.string.routing_user) + " · " + managed.getString("group");
                profiles.add(info);
            }
            JSONObject recovery = data.optJSONObject("mobile_recovery");
            if (recovery != null && Objects.equals(selectedId, recovery.optString("primary"))) {
                JSONArray ids = recovery.optJSONArray("backups");
                if (ids != null) for (int i = 0; i < ids.length(); i++) backups.add(ids.getString(i));
            }
        } catch (Exception e) { error(getString(R.string.encrypted_profiles_could_not_be_opened)); }
        if (host == null) return;
        renderKey = "";
        fillStrip(); fillProfiles(); fillActions();
        renderState();
    }
    private void setDefault(String id) {
        try {
            vault.edit(current -> {
                JSONArray latest = current.getJSONArray("profiles");
                for (int i = 0; i < latest.length(); i++) if (latest.getJSONObject(i).getString("id").equals(id)) { current.put("default", id); return; }
                throw new IOException("Profile removed during sync");
            }); reload();
        } catch (Exception e) { error(getString(R.string.could_not_save_profile_changes)); }
    }
    private void profileActions(Info info) {
        String detail = info.protocol + (info.host.isEmpty() ? "" : " · " + info.host);
        Sheet sheet = new Sheet(this, info.name, detail);
        if (info.isDefault) sheet.item(R.drawable.ic_star, getString(R.string.default_profile_label), getString(R.string.default_profile_detail), null);
        else sheet.item(R.drawable.ic_star, getString(R.string.make_default_profile), getString(R.string.default_profile_detail), () -> setDefault(info.id));
        sheet.item(R.drawable.ic_restore, getString(R.string.recovery_menu), getString(R.string.recovery_profile_detail), () -> recovery(info.id))
            .item(R.drawable.ic_upload, getString(R.string.export), getString(R.string.export_detail), () -> profileAction(info.id, true))
            .danger(R.drawable.ic_delete, getString(R.string.delete_text), getString(R.string.delete_detail), () -> profileAction(info.id, false))
            .show();
    }
    private void profileAction(String id, boolean export) {
            try {
                JSONObject data = vault.read(); JSONArray profiles = data.getJSONArray("profiles");
                if (export) {
                    for (int i = 0; i < profiles.length(); i++) if (profiles.getJSONObject(i).getString("id").equals(id)) export(profiles.getJSONObject(i).getJSONObject("profile").toString());
                } else new AlertDialog.Builder(this).setMessage(getString(R.string.delete_this_saved_profile)).setNegativeButton(getString(R.string.cancel), null).setPositiveButton(getString(R.string.delete_text), (d, w) -> {
                    try {
                        vault.edit(current -> { JSONArray old = current.getJSONArray("profiles"), kept = new JSONArray();
                        for (int i = 0; i < old.length(); i++) if (!old.getJSONObject(i).getString("id").equals(id)) kept.put(old.get(i));
                        current.put("profiles", kept);
                        if (id.equals(current.getString("default"))) current.put("default", kept.length() == 0 ? "" : kept.getJSONObject(0).getString("id"));
                        }); reload();
                    } catch (Exception e) { error(getString(R.string.could_not_save_profile_changes)); }
                }).show();
            } catch (Exception e) { error(getString(R.string.could_not_open_profile)); }
    }
    /** One live diagnostic dialog at a time; each explains itself when VPN is not connected. */
    private void live(java.util.function.Function<Activity, AlertDialog> open) {
        if (flowCapture != null) flowCapture.dismiss();
        stopPathCheck(false); // free the single diagnostic worker for the user's own check
        flowCapture = open.apply(this);
    }
    private void recovery(String profileId) {
        try { RecoveryDialog.show(this, vault, profileId); } catch (Exception e) { error(getString(R.string.recovery_invalid)); }
    }

    // ---- Lifecycle, import and export (unchanged behaviour) ---------------------------

    private void startSelectedConnection() {
        if (pendingConnectId == null || pendingConnectId.isEmpty()) { error(getString(R.string.import_and_select_a_profile)); return; }
        startForegroundService(new Intent(this, TunnelService.class).putExtra(TunnelService.PROFILE_ID, pendingConnectId));
    }
    @Override public void onResume() {
        super.onResume(); reload();
        // The service re-checks that this app is still the system Always-on VPN before connecting.
        if (TunnelService.alwaysOnSessionLost(this))
            try { startService(new Intent(this, TunnelService.class).setAction(TunnelService.RECOVER)); } catch (Exception ignored) { /* Retry on next resume. */ }
        recheck(); // every app open re-runs the checks on a live tunnel
        handler.post(poll);
    }
    @Override public void onPause() { if (flowCapture != null) {flowCapture.dismiss(); flowCapture=null;} stopPathCheck(false); handler.removeCallbacks(poll); super.onPause(); }
    @Override protected void onNewIntent(Intent intent) { super.onNewIntent(intent); setIntent(intent); incoming(intent); }
    private void incoming(Intent intent) {
        if (Intent.ACTION_VIEW.equals(intent.getAction()) && intent.getData() != null && java.util.Arrays.asList("tt", "hy2", "hysteria2").contains(intent.getData().getScheme())) {
            String raw = intent.getDataString(); intent.setData(null); preview(raw);
        }
    }
    private void error(String message) { new AlertDialog.Builder(this).setTitle("R-TrustTunnel").setMessage(message).setPositiveButton("OK", null).show(); }
    private void preview(String raw) {
        try {
            JSONObject parsed = new JSONObject(NativeCore.INSTANCE.parse(raw));
            if (!parsed.getBoolean("ok")) { error(getString(R.string.invalid_profile)); return; }
            JSONObject profile = parsed.getJSONObject("profile"), endpoint = profile.getJSONObject("endpoint");
            String existing = duplicateOf(vault.read(), profile);
            if (existing != null) { error(getString(R.string.v3_duplicate, existing)); return; }
            String warning = endpoint.optBoolean("skip_verification") ? getString(R.string.nwarning_certificate_verification_is_disabled_in) : "";
            new AlertDialog.Builder(this).setTitle(getString(R.string.import_profile_text)).setMessage(profile.optString("name", "") + "\n" + endpoint.getString("hostname") + " · " + protocolName(profile) + warning + getString(R.string.ncredentials_will_be_encrypted_on_this))
                .setNegativeButton(getString(R.string.cancel), null).setPositiveButton(getString(R.string.import_confirm), (d, w) -> {
                    try {
                        vault.edit(data -> { JSONArray list = data.getJSONArray("profiles");
                        if (list.length() >= 64) throw new IOException("Profile limit");
                        if (duplicateOf(data, profile) != null) throw new IOException("Duplicate profile");
                        String id = UUID.randomUUID().toString(); list.put(new JSONObject().put("id", id).put("profile", profile));
                        if (data.getString("default").isEmpty()) data.put("default", id);
                        }); reload();
                        if (screen == ADD) home();
                    } catch (Exception e) { error(getString(R.string.could_not_save_encrypted_profile)); }
                }).show();
        } catch (Exception e) { error(getString(R.string.invalid_or_oversized_profile)); }
    }
    /** Name of a saved profile identical to {@code profile} (key order ignored), or null. */
    static String duplicateOf(JSONObject vaultData, JSONObject profile) throws JSONException {
        String wanted = canonical(profile);
        JSONArray list = vaultData.getJSONArray("profiles");
        for (int i = 0; i < list.length(); i++) {
            JSONObject saved = list.getJSONObject(i).getJSONObject("profile");
            if (canonical(saved).equals(wanted)) { String name = saved.optString("name"); return name.trim().isEmpty() ? "Profile " + (i + 1) : name; }
        }
        return null;
    }
    private static String canonical(Object value) throws JSONException {
        if (value instanceof JSONObject) {
            JSONObject object = (JSONObject) value; List<String> keys = new ArrayList<>();
            for (Iterator<String> it = object.keys(); it.hasNext(); ) keys.add(it.next());
            Collections.sort(keys); StringBuilder out = new StringBuilder("{");
            for (String key : keys) out.append(JSONObject.quote(key)).append(':').append(canonical(object.get(key))).append(',');
            return out.append('}').toString();
        }
        if (value instanceof JSONArray) {
            JSONArray array = (JSONArray) value; StringBuilder out = new StringBuilder("[");
            for (int i = 0; i < array.length(); i++) out.append(canonical(array.get(i))).append(',');
            return out.append(']').toString();
        }
        return value instanceof String ? JSONObject.quote((String) value) : String.valueOf(value);
    }
    private static String protocolName(JSONObject profile) {
        String protocol = profile.optString("protocol");
        return "hysteria2".equals(protocol) ? "Hysteria 2" : "amneziawg".equals(protocol) ? "AmneziaWG" : "TrustTunnel";
    }
    private void export(String raw) {
        final String protocol;
        try {protocol=new JSONObject(raw).optString("protocol");}catch(Exception e){error(getString(R.string.could_not_export_this_profile));return;}
        final boolean hysteria="hysteria2".equals(protocol),amnezia="amneziawg".equals(protocol);
        String[] formats=hysteria?new String[]{"JSON",getString(R.string.tt_link)}:amnezia?new String[]{"JSON","AmneziaWG .conf"}:new String[]{"JSON",getString(R.string.endpoint_toml),getString(R.string.cli_toml),getString(R.string.tt_link)};
        Sheet sheet = new Sheet(this, getString(R.string.export_contains_credentials), getString(R.string.export_detail));
        for (int index = 0; index < formats.length; index++) { final int choice = index; sheet.item(R.drawable.ic_file, formats[index], null, () -> exportAs(raw, choice, hysteria, amnezia)); }
        sheet.show();
    }
    private void exportAs(String raw, int choice, boolean hysteria, boolean amnezia) {
        // Rust codec format indices: 3 is a link, 4 an AmneziaWG config.
        int format=choice==1?(hysteria?3:amnezia?4:1):choice;
        try {
            JSONObject output = new JSONObject(NativeCore.INSTANCE.export(raw, format));
            if (!output.getBoolean("ok")) { error(output.optString("message")); return; }
            new AlertDialog.Builder(this).setTitle(getString(R.string.save_unencrypted_credentials)).setMessage(getString(R.string.anyone_with_this_file_can_use) + output.getJSONArray("losses").toString())
                .setNegativeButton(getString(R.string.cancel), null).setPositiveButton(getString(R.string.choose_file), (confirm, which) -> {
                    try { vault.pendingExport(output.getString("content")); }
                    catch (Exception e) { error(getString(R.string.export_failed)); return; }
                    startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).setType(format == 0 ? "application/json" : format >= 3 ? "text/plain" : "application/toml").addCategory(Intent.CATEGORY_OPENABLE)
                        .putExtra(Intent.EXTRA_TITLE, "rtrust-profile." + (format == 0 ? "json" : format == 3 ? "txt" : format == 4 ? "conf" : "toml")), SAVE);
                }).show();
        } catch (Exception e) { error(getString(R.string.could_not_export_this_profile)); }
    }
    private void qrCamera() {
        new com.google.zxing.integration.android.IntentIntegrator(this).setCaptureActivity(QrCaptureActivity.class)
            .setDesiredBarcodeFormats(com.google.zxing.integration.android.IntentIntegrator.QR_CODE).setPrompt(getString(R.string.qr_prompt))
            .setBeepEnabled(false).setBarcodeImageEnabled(false).setOrientationLocked(false).initiateScan();
    }
    private void qrPayload(String raw) {
        try {
            JSONObject data=new JSONObject(raw);
            if (data.optString("kind").equals("rtrust_enrollment")) {
                new PortalDialog(this,vault,this::reload).enroll(raw);
                return;
            }
        } catch (JSONException ignored) { }
        preview(raw);
    }
    private void meteringSettings() {
        boolean current = TunnelService.inheritMetering(this);
        new Sheet(this, getString(R.string.metering_title), TunnelService.active ? getString(R.string.metering_next_connection) : null)
            .item(current ? 0 : R.drawable.ic_check, getString(R.string.metering_always), null, () -> setMetering(false))
            .item(current ? R.drawable.ic_check : 0, getString(R.string.metering_inherit), null, () -> setMetering(true))
            .show();
    }
    private void setMetering(boolean inherit) {
        if (inherit == TunnelService.inheritMetering(this)) return;
        TunnelService.setInheritMetering(this, inherit);
        if (TunnelService.active) Toast.makeText(this, R.string.metering_next_connection, Toast.LENGTH_LONG).show();
        fillActions();
    }
    private void vpnSettings() {
        String state = TunnelService.active ? getString(R.string.always_status, TunnelService.alwaysOn, TunnelService.lockdown) : getString(R.string.always_status_unknown);
        new AlertDialog.Builder(this).setTitle(R.string.always_on).setMessage(state + "\n\n" + getString(R.string.always_help))
            .setNegativeButton(android.R.string.cancel, null).setPositiveButton(R.string.open_settings, (d,w) -> {
                try { startActivity(new Intent(android.provider.Settings.ACTION_VPN_SETTINGS)); }
                catch (ActivityNotFoundException e) { startActivity(new Intent(android.provider.Settings.ACTION_WIRELESS_SETTINGS)); }
            }).show();
    }
    protected final void toggle() { toggle(false); }
    protected final void toggleDefaultProfile() { toggle(true); }
    private void toggle(boolean useDefault) {
        if (TunnelService.active && TunnelService.alwaysOn) { vpnSettings(); return; }
        if (TunnelService.active) { startService(new Intent(this, TunnelService.class).setAction(TunnelService.STOP)); return; }
        try {
            pendingConnectId = useDefault ? vault.read().getString("default") : selectedId;
            JSONObject profile = vault.profile(pendingConnectId);
            JSONObject prepared = new JSONObject(NativeCore.INSTANCE.plan(profile.toString()));
            if (!prepared.getBoolean("ok")) {
                error(getString(R.string.desktop_routing_policy_is_not_supported)); return;
            }
        } catch (Exception e) { error(getString(R.string.import_and_select_a_profile)); return; }
        try { AppRouting.read(vault.read()).validateInstalled(getPackageManager()); }
        catch (Exception error) { error(getString(R.string.check_vpn_apps_select_at_least)); return; }
        Intent consent = VpnService.prepare(this);
        if (consent != null) startActivityForResult(consent, CONSENT); else startSelectedConnection();
    }
    void saveDiagnostic(String report) {
        if (report.getBytes(StandardCharsets.UTF_8).length > 65536) { error("Report exceeds 64 KiB"); return; }
        diagnosticExport = report;
        startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/json")
            .addCategory(Intent.CATEGORY_OPENABLE).putExtra(Intent.EXTRA_TITLE,"vpn-diagnostic.json"), DIAGNOSTIC_SAVE);
    }
    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request == DIAGNOSTIC_SAVE) {
            String report = diagnosticExport; diagnosticExport = null;
            if (result == RESULT_OK && data != null && report != null) try (OutputStream out = getContentResolver().openOutputStream(data.getData(), "wt")) {
                if (out == null) throw new IOException(); out.write(report.getBytes(StandardCharsets.UTF_8));
            } catch (Exception ignored) { error(getString(R.string.could_not_write_export)); }
            return;
        }
        com.google.zxing.integration.android.IntentResult qr = com.google.zxing.integration.android.IntentIntegrator.parseActivityResult(request, result, data);
        if (qr != null) { if (qr.getContents() != null) qrPayload(qr.getContents()); return; }
        if (request == QR_IMAGE && result == RESULT_OK && data != null) {
            android.net.Uri uri = data.getData();
            new Thread(() -> {
                try (InputStream in = getContentResolver().openInputStream(uri)) {
                    if (in == null) throw new IOException(); String raw = QrImport.decode(in);
                    runOnUiThread(() -> { if (!isDestroyed()) qrPayload(raw); });
                } catch (Exception e) { runOnUiThread(() -> { if (!isDestroyed()) error(getString(R.string.qr_failed)); }); }
            }, "qr-import").start();
        }
        if (request == CONSENT && result == RESULT_OK) startSelectedConnection();
        if (request == SAVE) {
            String output;
            try { output = vault.takeExport(); }
            catch (Exception e) { error(getString(R.string.export_failed)); return; }
            if (result == RESULT_OK && output == null) { error(getString(R.string.export_expired)); return; }
            if (result == RESULT_OK && data != null && output != null) try (OutputStream out = getContentResolver().openOutputStream(data.getData(), "wt")) {
                if (out == null) throw new IOException(); out.write(output.getBytes(StandardCharsets.UTF_8));
            } catch (Exception e) { error(getString(R.string.could_not_write_export)); }
        }
        if (request == PICK && result == RESULT_OK && data != null) try (InputStream in = getContentResolver().openInputStream(data.getData())) {
            if (in == null) throw new IOException(); byte[] bytes = ProfileVault.readBounded(in, 1024 * 1024);
            if (bytes.length > 1024 * 1024) throw new IOException(); preview(new String(bytes, StandardCharsets.UTF_8));
            java.util.Arrays.fill(bytes, (byte) 0);
        } catch (Exception e) { error(getString(R.string.could_not_read_file_or_profile)); }
    }
}
