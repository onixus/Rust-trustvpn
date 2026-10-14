package org.rtrusttunnel.android;

import android.app.*;
import android.content.*;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.*;
import android.content.res.ColorStateList;
import android.net.*;
import android.os.*;
import android.view.*;
import android.widget.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.json.*;

/** Native Android widgets; no WebView and no remote UI code. */
public class MainActivity extends Activity {
    private static final int PICK = 10, SAVE = 11, CONSENT = 12, QR_IMAGE = 13, DIAGNOSTIC_SAVE = 14;
    private String diagnosticExport;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private LinearLayout rows;
    private String selectedId, pendingConnectId;
    private TextView status, statusDetail, selectedProfile, selectedProfileLabel, routingLabel, profilesHeader;
    private View statusDot;
    private LinearLayout hero;
    private Wrap checks;
    private Button connect;
    private int connectionColor;
    private String checksKey = "", connectedId;
    private JSONObject observations;
    /** Connection state palette. Amber is reserved for real warnings. */
    static final int IDLE = Color.rgb(107, 122, 140), BUSY = Color.rgb(77, 163, 255), ON = Color.rgb(43, 184, 154),
        VERIFIED = Color.rgb(61, 214, 140), WARNING = Color.rgb(224, 165, 38), ERROR = Color.rgb(229, 72, 77);
    private ProfileVault vault;
    private AlertDialog flowCapture;
    private final Runnable poll = new Runnable() {
        public void run() {
            try {
                JSONObject state = new JSONObject(NativeCore.INSTANCE.status());
                TunnelService.refreshPolicy();
                int nativeState = state.optInt("state", 0);
                boolean problem = !TunnelService.problem.isEmpty(), running = nativeState == 2 && !problem;
                observations = running ? ObservationStatus.snapshot(state.optJSONObject("observations")) : null;
                int level = running ? ObservationStatus.level(observations) : ObservationStatus.RUNNING;
                String headline, detail = "";
                if (problem) { headline = getString(R.string.state_problem); detail = TunnelService.problem; }
                else if (nativeState == 4) { headline = getString(R.string.state_problem); detail = getString(R.string.connection_failed); }
                else if (running) {
                    headline = getString(level == ObservationStatus.VERIFIED ? R.string.state_verified : level == ObservationStatus.WARNING ? R.string.state_warning : R.string.connected);
                    detail = getString(R.string.state_details_hint);
                    JSONObject recovery = state.optJSONObject("recovery");
                    if (recovery != null && recovery.optInt("selected_index") > 0) detail = getString(R.string.recovery_backup_active, recovery.optInt("selected_index"));
                }
                else if (nativeState == 1) headline = getString(R.string.connecting);
                else if (nativeState == 3) headline = getString(R.string.reconnecting);
                else headline = getString(TunnelService.active ? R.string.starting_vpn : R.string.state_off);
                setText(status, headline); setText(statusDetail, detail);
                statusDetail.setVisibility(detail.isEmpty() ? View.GONE : View.VISIBLE);
                showChecks(observations);
                String action = TunnelService.active ? getString(R.string.disconnect) : getString(R.string.connect_selected_profile);
                connect.setEnabled(!TunnelService.active || !TunnelService.alwaysOn); connect.setAlpha(connect.isEnabled() ? 1f : 0.5f);
                setText(connect, action);
                int color = connectionColor(TunnelService.active, state.optInt("state", -1), problem);
                if (running && level == ObservationStatus.VERIFIED) color = VERIFIED;
                if (running && level == ObservationStatus.WARNING) color = WARNING;
                paintConnection(color, TunnelService.active);
                if (!java.util.Objects.equals(TunnelService.connectedProfileId(), connectedId)) reload();
            } catch (Exception ignored) {
                paintConnection(connectionColor(false, 0, true), TunnelService.active);
                observations = null; showChecks(null);
                setText(status, getString(R.string.vpn_status_unavailable)); statusDetail.setVisibility(View.GONE);
            }
            handler.postDelayed(this, 500);
        }
    };
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        if (state != null) { selectedId = state.getString("selectedProfile"); pendingConnectId = state.getString("pendingConnectProfile"); }
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        vault = new ProfileVault(this);
        try { PortalSyncWorker.schedule(this); } catch (Exception ignored) { /* Reconcile again on next launch. */ }
        LinearLayout root = new LinearLayout(this); root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(20), dp(16), dp(20), dp(16));
        root.setOnApplyWindowInsetsListener((view, insets) -> {
            android.graphics.Insets bars = Build.VERSION.SDK_INT >= 30 ? insets.getInsets(WindowInsets.Type.systemBars()) : insets.getSystemWindowInsets();
            view.setPadding(dp(20) + bars.left, dp(16) + bars.top, dp(20) + bars.right, dp(16) + bars.bottom); return insets;
        });

        // Header
        TextView title = new TextView(this); title.setText("R-TrustTunnel"); title.setTextSize(26); title.setTypeface(null, Typeface.BOLD); title.setTextColor(color(R.color.text)); root.addView(title);
        TextView subtitle = new TextView(this); subtitle.setText(R.string.home_subtitle); subtitle.setTextSize(14); subtitle.setTextColor(color(R.color.text_muted)); subtitle.setPadding(0, dp(2), 0, dp(16)); root.addView(subtitle);

        // Status card: coloured dot + short state, detail line, check chips, profile in use.
        // Tapping it lists every check with its full outcome.
        hero = new LinearLayout(this); hero.setOrientation(LinearLayout.VERTICAL);
        hero.setPadding(dp(20), dp(18), dp(20), dp(18)); hero.setClickable(true); hero.setFocusable(true); hero.setOnClickListener(v -> checksSheet());
        LinearLayout stateRow = new LinearLayout(this); stateRow.setGravity(Gravity.CENTER_VERTICAL);
        statusDot = new View(this); GradientDrawable dot = new GradientDrawable(); dot.setShape(GradientDrawable.OVAL); dot.setColor(IDLE); statusDot.setBackground(dot);
        LinearLayout.LayoutParams dotParams = new LinearLayout.LayoutParams(dp(12), dp(12)); dotParams.setMarginEnd(dp(10)); stateRow.addView(statusDot, dotParams);
        status = new TextView(this); status.setTextSize(20); status.setTypeface(null, Typeface.BOLD); status.setTextColor(color(R.color.text));
        stateRow.addView(status, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
        hero.addView(stateRow);
        statusDetail = new TextView(this); statusDetail.setTextSize(13); statusDetail.setTextColor(color(R.color.text_muted)); statusDetail.setPadding(dp(22), dp(4), 0, 0); statusDetail.setVisibility(View.GONE); hero.addView(statusDetail);
        checks = new Wrap(this, dp(6)); checks.setPadding(0, dp(12), 0, 0); checks.setVisibility(View.GONE); hero.addView(checks);
        selectedProfileLabel = new TextView(this); selectedProfileLabel.setText(R.string.selected_profile_label); selectedProfileLabel.setTextSize(11); selectedProfileLabel.setLetterSpacing(0.08f); selectedProfileLabel.setTextColor(color(R.color.text_muted)); selectedProfileLabel.setPadding(0, dp(14), 0, dp(2)); hero.addView(selectedProfileLabel);
        selectedProfile = new TextView(this); selectedProfile.setTextSize(16); selectedProfile.setTextColor(color(R.color.text)); selectedProfile.setMaxLines(1); selectedProfile.setEllipsize(android.text.TextUtils.TruncateAt.END); hero.addView(selectedProfile);
        root.addView(hero);

        // Quick actions: Add · VPN apps · Settings
        LinearLayout actions = new LinearLayout(this);
        actions.addView(action(R.drawable.ic_add, getString(R.string.add_profile), null, this::importMenu), actionParams(true));
        LinearLayout routing = action(R.drawable.ic_apps, getString(R.string.vpn_apps), "", () -> {
            try { AppRoutingDialog.show(this, vault, this::reload); }
            catch (Exception error) { error(getString(R.string.app_selection_could_not_be_opened)); }
        }); routingLabel = (TextView) routing.getChildAt(2); actions.addView(routing, actionParams(true));
        actions.addView(action(R.drawable.ic_settings, getString(R.string.home_settings), null, this::settingsMenu), actionParams(false));
        LinearLayout.LayoutParams actionsRow = new LinearLayout.LayoutParams(-1, -2); actionsRow.setMargins(0, dp(14), 0, dp(20)); root.addView(actions, actionsRow);

        // Profiles
        profilesHeader = new TextView(this); profilesHeader.setTextSize(13); profilesHeader.setTypeface(null, Typeface.BOLD); profilesHeader.setLetterSpacing(0.06f); profilesHeader.setTextColor(color(R.color.text_muted)); profilesHeader.setPadding(dp(4), 0, 0, dp(8)); root.addView(profilesHeader);
        ScrollView scroll = new ScrollView(this); scroll.setVerticalScrollBarEnabled(false); rows = new LinearLayout(this); rows.setOrientation(LinearLayout.VERTICAL); scroll.addView(rows); root.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));

        // Connect: fixed at the bottom; its style shows the next action, not the state
        connect = button(getString(R.string.connect_selected_profile), () -> toggle());
        connect.setTextSize(16); connect.setCompoundDrawablesRelativeWithIntrinsicBounds(tinted(R.drawable.ic_power, Color.WHITE), null, null, null); connect.setCompoundDrawablePadding(dp(10)); connect.setPadding(dp(20), 0, dp(20), 0);
        LinearLayout.LayoutParams connectParams = new LinearLayout.LayoutParams(-1, dp(58)); connectParams.setMargins(0, dp(12), 0, 0); root.addView(connect, connectParams);
        connectionColor = 1; paintConnection(connectionColor(false, 0, false), false);
        setContentView(root); reload(); incoming(getIntent());
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission("android.permission.POST_NOTIFICATIONS") != android.content.pm.PackageManager.PERMISSION_GRANTED)
            requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, 20);
    }
    private void importMenu() {
        new Sheet(this, getString(R.string.add_profile), null)
            .item(R.drawable.ic_file, getString(R.string.import_file), getString(R.string.import_file_detail), () -> startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("*/*").addCategory(Intent.CATEGORY_OPENABLE), PICK))
            .item(R.drawable.ic_paste, getString(R.string.paste_config_or_tt_link), getString(R.string.paste_detail), this::paste)
            .item(R.drawable.ic_qr, getString(R.string.qr_camera), getString(R.string.qr_camera_detail), this::qrCamera)
            .item(R.drawable.ic_image, getString(R.string.qr_image), getString(R.string.qr_image_detail), () -> startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("image/*").addCategory(Intent.CATEGORY_OPENABLE), QR_IMAGE))
            .show();
    }
    @Override protected void onSaveInstanceState(Bundle state) {
        super.onSaveInstanceState(state);
        state.putString("selectedProfile", selectedId);
        state.putString("pendingConnectProfile", pendingConnectId);
    }
    private void startSelectedConnection() {
        if (pendingConnectId == null || pendingConnectId.isEmpty()) { error(getString(R.string.import_and_select_a_profile)); return; }
        startForegroundService(new Intent(this, TunnelService.class).putExtra(TunnelService.PROFILE_ID, pendingConnectId));
    }
    private void settingsMenu() {
        String portal = getString(R.string.portal_not_enrolled);
        try { JSONObject session = vault.read().optJSONObject("portal"); if (session != null) portal = getString(R.string.portal_enrolled_detail, Uri.parse(session.optString("origin")).getHost()); }
        catch (Exception ignored) { /* The portal entry reports its own errors. */ }
        String live = TunnelService.active ? null : getString(R.string.needs_connection);
        String version = "";
        try { version = getPackageManager().getPackageInfo(getPackageName(), 0).versionName; } catch (Exception ignored) { /* Footer only. */ }
        new Sheet(this, getString(R.string.home_settings), null)
            .section(R.string.settings_connection)
            .item(R.drawable.ic_lock, getString(R.string.always_on), getString(R.string.always_on_detail), this::vpnSettings)
            .item(R.drawable.ic_restore, getString(R.string.recovery_menu), getString(R.string.recovery_menu_detail), () -> recovery(selectedId))
            .item(R.drawable.ic_sync, getString(R.string.metering_title), getString(TunnelService.inheritMetering(this) ? R.string.metering_detail_inherit : R.string.metering_detail_always), this::meteringSettings)
            .section(R.string.settings_diagnostics)
            .item(R.drawable.ic_search, getString(R.string.diagnostics_title), live != null ? live : getString(R.string.diagnostics_detail), () -> live(DiagnosticsDialog::show))
            .item(R.drawable.ic_eye, getString(R.string.flow_capture_title), live != null ? live : getString(R.string.flow_capture_detail), () -> live(FlowCaptureDialog::show))
            .item(R.drawable.ic_tune, getString(R.string.flow_policy_title), live != null ? live : getString(R.string.flow_policy_detail), () -> live(FlowPolicyDialog::show))
            .section(R.string.settings_server)
            .item(R.drawable.ic_cloud, getString(R.string.portal_title), portal, () -> new PortalDialog(this, vault, this::reload).show())
            .footer(getString(R.string.app_version, version))
            .show();
    }
    /** One live diagnostic dialog at a time; each explains itself when VPN is not connected. */
    private void live(java.util.function.Function<Activity, AlertDialog> open) {
        if (flowCapture != null) flowCapture.dismiss();
        flowCapture = open.apply(this);
    }
    private void recovery(String profileId) {
        try { RecoveryDialog.show(this, vault, profileId); } catch (Exception e) { error(getString(R.string.recovery_invalid)); }
    }
    /** Every check with a result and its outcome; the card itself only shows short chips. */
    private void checksSheet() {
        JSONObject snapshot = observations;
        Sheet sheet = new Sheet(this, getString(R.string.checks_title), status.getText());
        if (snapshot != null) for (int i = 0; i < ObservationStatus.KEYS.length; i++) {
            String outcome = ObservationStatus.outcome(snapshot.optJSONObject(ObservationStatus.KEYS[i]));
            String label = ObservationStatus.label(this, outcome);
            if (label != null) sheet.status(ObservationStatus.color(outcome), getString(ObservationStatus.NAMES[i]), label);
        }
        sheet.item(R.drawable.ic_search, getString(R.string.diagnostics_title), TunnelService.active ? getString(R.string.diagnostics_detail) : getString(R.string.needs_connection), () -> live(DiagnosticsDialog::show))
            .footer(getString(R.string.checks_note)).show();
    }
    /** Checks that never produced a result are omitted, as in the text summary. */
    private void showChecks(JSONObject snapshot) {
        StringBuilder key = new StringBuilder();
        if (snapshot != null) for (String name : ObservationStatus.KEYS) key.append(ObservationStatus.outcome(snapshot.optJSONObject(name))).append(',');
        if (key.toString().equals(checksKey)) return;
        checksKey = key.toString(); checks.removeAllViews();
        if (snapshot != null) for (int i = 0; i < ObservationStatus.KEYS.length; i++) {
            String outcome = ObservationStatus.outcome(snapshot.optJSONObject(ObservationStatus.KEYS[i]));
            String label = ObservationStatus.label(this, outcome);
            if (label == null) continue;
            String name = getString(ObservationStatus.NAMES[i]);
            LinearLayout chip = new LinearLayout(this); chip.setGravity(Gravity.CENTER_VERTICAL); chip.setPadding(dp(8), dp(4), dp(10), dp(4));
            chip.setBackground(card(color(R.color.surface_raised), dp(12)));
            View dot = new View(this); GradientDrawable fill = new GradientDrawable(); fill.setShape(GradientDrawable.OVAL); fill.setColor(ObservationStatus.color(outcome)); dot.setBackground(fill);
            LinearLayout.LayoutParams dotParams = new LinearLayout.LayoutParams(dp(7), dp(7)); dotParams.setMarginEnd(dp(6)); chip.addView(dot, dotParams);
            TextView text = new TextView(this); text.setText(name); text.setTextSize(12); text.setTextColor(color(R.color.text)); chip.addView(text);
            chip.setContentDescription(name + ": " + label);
            checks.addView(chip);
        }
        checks.setVisibility(checks.getChildCount() == 0 ? View.GONE : View.VISIBLE);
    }
    private static void setText(TextView view, String text) { if (!view.getText().toString().equals(text)) view.setText(text); }
    /** Left-to-right rows that wrap, for chips on narrow phones. */
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
    private int dp(int n) { return Math.round(n * getResources().getDisplayMetrics().density); }
    private int color(int id) { return getColor(id); }
    private GradientDrawable card(int fill, int radius) { GradientDrawable bg = new GradientDrawable(); bg.setColor(fill); bg.setCornerRadius(radius); return bg; }
    private Drawable ripple(Drawable content) { return new RippleDrawable(ColorStateList.valueOf(color(R.color.ripple)), content, content); }
    private Drawable tinted(int id, int tint) { Drawable icon = getDrawable(id).mutate(); icon.setTint(tint); return icon; }
    private LinearLayout.LayoutParams actionParams(boolean gap) { LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(0, -1, 1); if (gap) p.setMarginEnd(dp(10)); return p; }
    /** Icon tile with a caption and optional second line (e.g. "All apps"). */
    private LinearLayout action(int icon, String caption, String detail, Runnable click) {
        LinearLayout tile = new LinearLayout(this); tile.setOrientation(LinearLayout.VERTICAL); tile.setGravity(Gravity.CENTER);
        tile.setPadding(dp(8), dp(14), dp(8), dp(12)); tile.setBackground(ripple(card(color(R.color.surface), dp(16)))); tile.setClickable(true); tile.setFocusable(true);
        ImageView image = new ImageView(this); image.setImageDrawable(tinted(icon, color(R.color.accent))); tile.addView(image, new LinearLayout.LayoutParams(dp(26), dp(26)));
        TextView text = new TextView(this); text.setText(caption); text.setTextSize(13); text.setTypeface(null, Typeface.BOLD); text.setTextColor(color(R.color.text)); text.setGravity(Gravity.CENTER); text.setMaxLines(2); text.setPadding(0, dp(8), 0, 0); tile.addView(text);
        TextView sub = new TextView(this); sub.setTextSize(11); sub.setTextColor(color(R.color.text_muted)); sub.setGravity(Gravity.CENTER); sub.setMaxLines(1); sub.setEllipsize(android.text.TextUtils.TruncateAt.END);
        if (detail == null) sub.setVisibility(View.INVISIBLE); else sub.setText(detail); tile.addView(sub);
        tile.setOnClickListener(v -> click.run()); return tile;
    }
    private Button button(String text, Runnable click) {
        Button button = new Button(this); button.setText(text); button.setAllCaps(false); button.setGravity(Gravity.CENTER); button.setTypeface(null, Typeface.BOLD); button.setTextColor(Color.WHITE); button.setBackgroundTintList(null);
        button.setBackground(ripple(card(color(R.color.surface_raised), dp(14)))); button.setStateListAnimator(null);
        button.setOnClickListener(v -> click.run()); return button;
    }
    /** Tapping selects the app profile; the menu separately assigns the widget default. */
    private View profileRow(String id, String name, String detail, boolean isDefault, boolean isSelected, boolean isConnected) {
        LinearLayout row = new LinearLayout(this); row.setGravity(Gravity.CENTER_VERTICAL); row.setPadding(dp(16), dp(14), dp(6), dp(14));
        GradientDrawable bg = card(color(isSelected ? R.color.accent_soft : R.color.surface), dp(16)); if (isSelected) bg.setStroke(dp(1), color(R.color.accent));
        row.setBackground(ripple(bg)); row.setClickable(true); row.setFocusable(true);
        ImageView mark = new ImageView(this); mark.setImageDrawable(tinted(R.drawable.ic_check, color(R.color.accent))); mark.setVisibility(isSelected ? View.VISIBLE : View.INVISIBLE);
        LinearLayout.LayoutParams markParams = new LinearLayout.LayoutParams(dp(22), dp(22)); markParams.setMarginEnd(dp(12)); row.addView(mark, markParams);
        LinearLayout text = new LinearLayout(this); text.setOrientation(LinearLayout.VERTICAL);
        LinearLayout titleRow = new LinearLayout(this); titleRow.setGravity(Gravity.CENTER_VERTICAL);
        TextView title = new TextView(this); title.setText(name); title.setTextSize(16); title.setTypeface(null, Typeface.BOLD); title.setTextColor(color(R.color.text)); title.setMaxLines(1); title.setEllipsize(android.text.TextUtils.TruncateAt.END); titleRow.addView(title, new LinearLayout.LayoutParams(0, -2, 1));
        if (isConnected) {
            TextView badge = new TextView(this); badge.setText(R.string.connected_badge); badge.setTextSize(11); badge.setTypeface(null, Typeface.BOLD); badge.setTextColor(ON);
            badge.setPadding(dp(8), dp(2), dp(8), dp(2)); badge.setBackground(card(Color.argb(38, Color.red(ON), Color.green(ON), Color.blue(ON)), dp(10)));
            LinearLayout.LayoutParams badgeParams = new LinearLayout.LayoutParams(-2, -2); badgeParams.setMarginStart(dp(8)); titleRow.addView(badge, badgeParams);
        }
        text.addView(titleRow);
        TextView sub = new TextView(this); sub.setText(detail + (isDefault ? " · " + getString(R.string.default_profile_label) : "")); sub.setTextSize(12); sub.setTextColor(color(R.color.text_muted)); sub.setMaxLines(1); sub.setEllipsize(android.text.TextUtils.TruncateAt.MIDDLE); text.addView(sub);
        row.addView(text, new LinearLayout.LayoutParams(0, -2, 1));
        ImageButton more = new ImageButton(this); more.setImageDrawable(tinted(R.drawable.ic_more, color(R.color.text_muted))); more.setBackground(ripple(card(Color.TRANSPARENT, dp(20)))); more.setContentDescription(getString(R.string.profile_menu));
        row.addView(more, new LinearLayout.LayoutParams(dp(40), dp(40)));
        row.setOnClickListener(v -> { selectedId = id; reload(); });
        more.setOnClickListener(v -> profileActions(id, name, detail, isDefault));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, -2); params.setMargins(0, 0, 0, dp(8)); row.setLayoutParams(params); return row;
    }
    /**
     * Lifecycle colour. A running tunnel is teal, never green: green needs every check
     * passed and fresh (ObservationStatus.level). Amber is reserved for failed checks.
     */
    static int connectionColor(boolean active, int state, boolean problem) {
        if (problem || state == 4 || state < 0 || state > 4) return ERROR;
        if (!active) return IDLE;
        return state == 2 ? ON : BUSY;
    }
    /** The dot and card edge carry the state; the button shows the next action. */
    private void paintConnection(int color, boolean active) {
        int key = color ^ (active ? 1 : 0);
        if (connectionColor == key) return;
        connectionColor = key;
        GradientDrawable heroBg = card(color(R.color.surface), dp(20));
        heroBg.setStroke(dp(1), color == IDLE ? color(R.color.outline) : Color.argb(110, Color.red(color), Color.green(color), Color.blue(color)));
        hero.setBackground(ripple(heroBg));
        ((GradientDrawable) statusDot.getBackground()).setColor(color);
        GradientDrawable button = card(color(active ? R.color.surface_raised : R.color.accent), dp(14));
        if (active) button.setStroke(dp(1), color(R.color.outline));
        connect.setBackground(ripple(button));
        connect.setCompoundDrawablesRelativeWithIntrinsicBounds(tinted(R.drawable.ic_power, active ? color(R.color.danger) : Color.WHITE), null, null, null);
        connect.setTextColor(active ? color(R.color.text) : Color.WHITE);
    }
    @Override public void onResume() {
        super.onResume(); reload();
        // The service re-checks that this app is still the system Always-on VPN before connecting.
        if (TunnelService.alwaysOnSessionLost(this))
            try { startService(new Intent(this, TunnelService.class).setAction(TunnelService.RECOVER)); } catch (Exception ignored) { /* Retry on next resume. */ }
        handler.post(poll);
    }
    @Override public void onPause() { if (flowCapture != null) {flowCapture.dismiss(); flowCapture=null;} handler.removeCallbacks(poll); super.onPause(); }
    @Override protected void onNewIntent(Intent intent) { super.onNewIntent(intent); setIntent(intent); incoming(intent); }
    private void incoming(Intent intent) {
        if (Intent.ACTION_VIEW.equals(intent.getAction()) && intent.getData() != null && java.util.Arrays.asList("tt", "hy2", "hysteria2").contains(intent.getData().getScheme())) {
            String raw = intent.getDataString(); intent.setData(null); preview(raw);
        }
    }
    private void error(String message) { new AlertDialog.Builder(this).setTitle("R-TrustTunnel").setMessage(message).setPositiveButton("OK", null).show(); }
    private void reload() {
        rows.removeAllViews();
        connectedId = TunnelService.connectedProfileId(); // before any failure, so polling cannot repeat it
        try {
            JSONObject data = vault.read(); JSONArray profiles = data.getJSONArray("profiles");
            AppRouting selection = AppRouting.read(data);
            routingLabel.setText(selection.selectedOnly ? getString(R.string.selected_count, selection.packages.size()) : getString(R.string.all_apps));
            boolean found = false;
            for (int i = 0; i < profiles.length(); i++) if (profiles.getJSONObject(i).getString("id").equals(selectedId)) found = true;
            if (!found) selectedId = data.optString("default");
            selectedProfile.setText(R.string.no_selected_profile);
            String connected = connectedId;
            String shown = connected != null ? connected : selectedId;
            selectedProfileLabel.setText(connected != null ? R.string.connected_profile_label : R.string.selected_profile_label);
            profilesHeader.setText(getString(R.string.profiles_header, profiles.length()));
            for (int i = 0; i < profiles.length(); i++) {
                JSONObject item = profiles.getJSONObject(i), profile = item.getJSONObject("profile"); String id = item.getString("id");
                String name = profile.optString("name"); if (name.trim().isEmpty()) name = "Profile " + (i + 1);
                boolean isDefault = id.equals(data.getString("default"));
                if (id.equals(shown)) selectedProfile.setText(name);
                String host = profile.optJSONObject("endpoint") == null ? "" : profile.getJSONObject("endpoint").optString("hostname");
                String detail = protocolName(profile) + (host.isEmpty() ? "" : " · " + host);
                JSONObject managed=item.optJSONObject("managed_routing");
                if (managed!=null) detail += " · " + getString(managed.getString("revision").startsWith("admin:") ? R.string.routing_admin : R.string.routing_user) + " · " + managed.getString("group");
                rows.addView(profileRow(id, name, detail, isDefault, id.equals(selectedId), id.equals(connected)));
            }
            if (profiles.length() == 0) {
                LinearLayout empty = new LinearLayout(this); empty.setOrientation(LinearLayout.VERTICAL); empty.setGravity(Gravity.CENTER); empty.setPadding(dp(20), dp(28), dp(20), dp(28));
                GradientDrawable bg = card(Color.TRANSPARENT, dp(16)); bg.setStroke(dp(1), color(R.color.outline), dp(6), dp(5)); empty.setBackground(bg);
                TextView head = new TextView(this); head.setText(R.string.import_a_profile_to_get_started); head.setTextSize(15); head.setTypeface(null, Typeface.BOLD); head.setTextColor(color(R.color.text)); head.setGravity(Gravity.CENTER); empty.addView(head);
                TextView hint = new TextView(this); hint.setText(R.string.empty_hint); hint.setTextSize(13); hint.setTextColor(color(R.color.text_muted)); hint.setGravity(Gravity.CENTER); hint.setPadding(0, dp(6), 0, 0); empty.addView(hint);
                rows.addView(empty);
            }
        } catch (Exception e) { error(getString(R.string.encrypted_profiles_could_not_be_opened)); }
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
    private void profileActions(String id, String name, String detail, boolean isDefault) {
        Sheet sheet = new Sheet(this, name, detail);
        if (isDefault) sheet.item(R.drawable.ic_star, getString(R.string.default_profile_label), getString(R.string.default_profile_detail), null);
        else sheet.item(R.drawable.ic_star, getString(R.string.make_default_profile), getString(R.string.default_profile_detail), () -> setDefault(id));
        sheet.item(R.drawable.ic_restore, getString(R.string.recovery_menu), getString(R.string.recovery_profile_detail), () -> recovery(id))
            .item(R.drawable.ic_upload, getString(R.string.export), getString(R.string.export_detail), () -> profileAction(id, true))
            .danger(R.drawable.ic_delete, getString(R.string.delete_text), getString(R.string.delete_detail), () -> profileAction(id, false))
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
    private void paste() {
        EditText input = new EditText(this); input.setHint("TOML, YAML, JSON, tt:// or hy2://"); input.setMinLines(4); input.setMaxLines(10);
        input.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE | android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        input.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        input.setImeOptions(android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING);
        input.setFilters(new android.text.InputFilter[]{new android.text.InputFilter.LengthFilter(1024 * 1024)});
        new AlertDialog.Builder(this).setTitle(getString(R.string.import_profile)).setView(input).setNegativeButton(getString(R.string.cancel), null).setPositiveButton(getString(R.string.preview), (d, w) -> { String raw = input.getText().toString(); input.setText(""); preview(raw); }).show();
    }
    private void preview(String raw) {
        try {
            JSONObject parsed = new JSONObject(NativeCore.INSTANCE.parse(raw));
            if (!parsed.getBoolean("ok")) { error(getString(R.string.invalid_profile)); return; }
            JSONObject profile = parsed.getJSONObject("profile"), endpoint = profile.getJSONObject("endpoint");
            String warning = endpoint.optBoolean("skip_verification") ? getString(R.string.nwarning_certificate_verification_is_disabled_in) : "";
            new AlertDialog.Builder(this).setTitle(getString(R.string.import_profile_text)).setMessage(profile.optString("name", "") + "\n" + endpoint.getString("hostname") + " · " + protocolName(profile) + warning + getString(R.string.ncredentials_will_be_encrypted_on_this))
                .setNegativeButton(getString(R.string.cancel), null).setPositiveButton(getString(R.string.import_confirm), (d, w) -> {
                    try {
                        vault.edit(data -> { JSONArray list = data.getJSONArray("profiles");
                        if (list.length() >= 64) throw new IOException("Profile limit");
                        String id = UUID.randomUUID().toString(); list.put(new JSONObject().put("id", id).put("profile", profile));
                        if (data.getString("default").isEmpty()) data.put("default", id);
                        }); reload();
                    } catch (Exception e) { error(getString(R.string.could_not_save_encrypted_profile)); }
                }).show();
        } catch (Exception e) { error(getString(R.string.invalid_or_oversized_profile)); }
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
        {
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
