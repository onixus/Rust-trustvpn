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
    private TextView status, selectedProfile, routingLabel, profilesHeader;
    private View statusDot;
    private Button connect;
    private int connectionColor;
    private ProfileVault vault;
    private AlertDialog flowCapture;
    private final Runnable poll = new Runnable() {
        public void run() {
            try {
                JSONObject state = new JSONObject(NativeCore.INSTANCE.status());
                TunnelService.refreshPolicy();
                int nativeState = state.optInt("state", 0);
                CharSequence message = !TunnelService.problem.isEmpty() ? TunnelService.problem : nativeState == 2 ? getString(R.string.connected) : nativeState == 1 ? getString(R.string.connecting) : nativeState == 3 ? getString(R.string.reconnecting) : nativeState == 4 ? getString(R.string.connection_failed) : "";
                boolean detailed = nativeState == 2 && TunnelService.problem.isEmpty();
                if (detailed) message = ObservationStatus.summary(MainActivity.this, state.optJSONObject("observations"));
                JSONObject recovery=state.optJSONObject("recovery");if(nativeState==2 && recovery!=null && recovery.optInt("selected_index")>0)message=android.text.TextUtils.concat(message," · "+getString(R.string.recovery_backup_active,recovery.optInt("selected_index")));
                if (message.length() == 0) message = TunnelService.active ? getString(R.string.starting_vpn) : getString(R.string.disconnected);
                showStatus(message, detailed);
                String action = TunnelService.active ? getString(R.string.disconnect) : getString(R.string.connect_selected_profile);
                connect.setEnabled(!TunnelService.active || !TunnelService.alwaysOn);
                if (!connect.getText().toString().equals(action)) connect.setText(action);
                paintConnection(connectionColor(TunnelService.active, state.optInt("state", -1), !TunnelService.problem.isEmpty()), TunnelService.active || !TunnelService.problem.isEmpty());
            } catch (Exception ignored) {
                paintConnection(connectionColor(false, 0, true), true);
                showStatus(getString(R.string.vpn_status_unavailable), false);
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

        // Status card: colored dot + state + selected profile
        LinearLayout hero = new LinearLayout(this); hero.setOrientation(LinearLayout.VERTICAL); hero.setBackground(card(color(R.color.surface), dp(20)));
        hero.setPadding(dp(20), dp(18), dp(20), dp(18));
        LinearLayout stateRow = new LinearLayout(this); stateRow.setGravity(Gravity.CENTER_VERTICAL);
        statusDot = new View(this); GradientDrawable dot = new GradientDrawable(); dot.setShape(GradientDrawable.OVAL); dot.setColor(color(R.color.text_muted)); statusDot.setBackground(dot);
        LinearLayout.LayoutParams dotParams = new LinearLayout.LayoutParams(dp(12), dp(12)); dotParams.setMarginEnd(dp(10)); stateRow.addView(statusDot, dotParams);
        status = new TextView(this); status.setTextSize(20); status.setTypeface(null, Typeface.BOLD); status.setTextColor(color(R.color.text)); stateRow.addView(status);
        hero.addView(stateRow);
        TextView label = new TextView(this); label.setText(R.string.selected_profile_label); label.setTextSize(11); label.setLetterSpacing(0.08f); label.setTextColor(color(R.color.text_muted)); label.setPadding(0, dp(14), 0, dp(2)); hero.addView(label);
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

        // Connect: fixed at the bottom, colored by connection state
        connect = button(getString(R.string.connect_selected_profile), () -> toggle());
        connect.setTextSize(16); connect.setCompoundDrawablesRelativeWithIntrinsicBounds(tinted(R.drawable.ic_power, Color.WHITE), null, null, null); connect.setCompoundDrawablePadding(dp(10)); connect.setPadding(dp(20), 0, dp(20), 0);
        LinearLayout.LayoutParams connectParams = new LinearLayout.LayoutParams(-1, dp(58)); connectParams.setMargins(0, dp(12), 0, 0); root.addView(connect, connectParams);
        paintConnection(connectionColor(false, 0, false), false);
        setContentView(root); reload(); incoming(getIntent());
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission("android.permission.POST_NOTIFICATIONS") != android.content.pm.PackageManager.PERMISSION_GRANTED)
            requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, 20);
    }
    private void importMenu() {
        new AlertDialog.Builder(this).setTitle(R.string.add_profile).setItems(new String[]{getString(R.string.import_file), getString(R.string.paste_config_or_tt_link), getString(R.string.qr_import)}, (dialog, which) -> {
            if (which == 0) startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("*/*").addCategory(Intent.CATEGORY_OPENABLE), PICK);
            else if (which == 1) paste(); else qr();
        }).show();
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
    /** A short state is a large bold headline; the per-check summary is smaller and styles itself. */
    private void showStatus(CharSequence message, boolean detailed) {
        if (detailed != statusDetailed) {
            statusDetailed = detailed;
            status.setTextSize(detailed ? 14 : 20); status.setTypeface(null, detailed ? Typeface.NORMAL : Typeface.BOLD);
            status.setText(message);
        } else if (!status.getText().toString().equals(message.toString())) status.setText(message);
    }
    private boolean statusDetailed;
    private void settingsMenu() {
        new AlertDialog.Builder(this).setTitle(R.string.home_settings).setItems(new String[]{getString(R.string.portal_title), getString(R.string.always_on), java.util.Locale.getDefault().getLanguage().equals("ru") ? "Наблюдать решения маршрутизации" : "Observe local flow decisions", java.util.Locale.getDefault().getLanguage().equals("ru") ? "Проверить путь VPN" : "Check VPN path", java.util.Locale.getDefault().getLanguage().equals("ru") ? "Правила текущего подключения" : "Current connection rules",getString(R.string.recovery_title),getString(R.string.metering_title)}, (dialog, which) -> {
            if (which == 0) new PortalDialog(this, vault, this::reload).show();
            else if (which == 1) vpnSettings();
            else if(which==6)meteringSettings();
            else if(which==5){try{RecoveryDialog.show(this,vault,selectedId);}catch(Exception e){error(getString(R.string.recovery_invalid));}}
            else { if (flowCapture != null) flowCapture.dismiss(); flowCapture = which == 2 ? FlowCaptureDialog.show(this) : which == 3 ? DiagnosticsDialog.show(this) : FlowPolicyDialog.show(this); }
        }).show();
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
    private View profileRow(String id, String name, String detail, boolean isDefault, boolean isSelected) {
        LinearLayout row = new LinearLayout(this); row.setGravity(Gravity.CENTER_VERTICAL); row.setPadding(dp(16), dp(14), dp(6), dp(14));
        GradientDrawable bg = card(color(isSelected ? R.color.accent_soft : R.color.surface), dp(16)); if (isSelected) bg.setStroke(dp(1), color(R.color.accent));
        row.setBackground(ripple(bg)); row.setClickable(true); row.setFocusable(true);
        ImageView mark = new ImageView(this); mark.setImageDrawable(tinted(R.drawable.ic_check, color(R.color.accent))); mark.setVisibility(isSelected ? View.VISIBLE : View.INVISIBLE);
        LinearLayout.LayoutParams markParams = new LinearLayout.LayoutParams(dp(22), dp(22)); markParams.setMarginEnd(dp(12)); row.addView(mark, markParams);
        LinearLayout text = new LinearLayout(this); text.setOrientation(LinearLayout.VERTICAL);
        TextView title = new TextView(this); title.setText(name); title.setTextSize(16); title.setTypeface(null, Typeface.BOLD); title.setTextColor(color(R.color.text)); title.setMaxLines(1); title.setEllipsize(android.text.TextUtils.TruncateAt.END); text.addView(title);
        TextView sub = new TextView(this); sub.setText(detail + (isDefault ? " · " + getString(R.string.default_profile_label) : "")); sub.setTextSize(12); sub.setTextColor(color(R.color.text_muted)); sub.setMaxLines(1); sub.setEllipsize(android.text.TextUtils.TruncateAt.MIDDLE); text.addView(sub);
        row.addView(text, new LinearLayout.LayoutParams(0, -2, 1));
        ImageButton more = new ImageButton(this); more.setImageDrawable(tinted(R.drawable.ic_more, color(R.color.text_muted))); more.setBackground(ripple(card(Color.TRANSPARENT, dp(20)))); more.setContentDescription(getString(R.string.profile_menu));
        row.addView(more, new LinearLayout.LayoutParams(dp(40), dp(40)));
        row.setOnClickListener(v -> { selectedId = id; reload(); });
        more.setOnClickListener(v -> profileActions(v, id));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, -2); params.setMargins(0, 0, 0, dp(8)); row.setLayoutParams(params); return row;
    }
    static int connectionColor(boolean active, int state, boolean problem) {
        if (problem || state == 4 || state < 0 || state > 4) return Color.rgb(229, 72, 77);
        if (!active) return Color.rgb(77, 163, 255);
        return Color.rgb(224, 165, 38); // Lifecycle is not verified network availability.
    }
    /** {@code lit} colors the status dot; an idle tunnel keeps it neutral. */
    private void paintConnection(int color, boolean lit) {
        if (connectionColor == color) return;
        connectionColor = color;
        connect.setBackground(ripple(card(color, dp(14))));
        ((GradientDrawable) statusDot.getBackground()).setColor(lit ? color : color(R.color.text_muted));
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
        try {
            JSONObject data = vault.read(); JSONArray profiles = data.getJSONArray("profiles");
            AppRouting selection = AppRouting.read(data);
            routingLabel.setText(selection.selectedOnly ? getString(R.string.selected_count, selection.packages.size()) : getString(R.string.all_apps));
            boolean found = false;
            for (int i = 0; i < profiles.length(); i++) if (profiles.getJSONObject(i).getString("id").equals(selectedId)) found = true;
            if (!found) selectedId = data.optString("default");
            selectedProfile.setText(R.string.no_selected_profile);
            profilesHeader.setText(getString(R.string.profiles_header, profiles.length()));
            for (int i = 0; i < profiles.length(); i++) {
                JSONObject item = profiles.getJSONObject(i), profile = item.getJSONObject("profile"); String id = item.getString("id");
                String name = profile.optString("name"); if (name.trim().isEmpty()) name = "Profile " + (i + 1);
                boolean isDefault = id.equals(data.getString("default"));
                if (id.equals(selectedId)) selectedProfile.setText(name);
                String host = profile.optJSONObject("endpoint") == null ? "" : profile.getJSONObject("endpoint").optString("hostname");
                String detail = protocolName(profile) + (host.isEmpty() ? "" : " · " + host);
                JSONObject managed=item.optJSONObject("managed_routing");
                if (managed!=null) detail += " · " + getString(managed.getString("revision").startsWith("admin:") ? R.string.routing_admin : R.string.routing_user) + " · " + managed.getString("group");
                rows.addView(profileRow(id, name, detail, isDefault, id.equals(selectedId)));
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
    private void profileActions(View anchor, String id) {
        PopupMenu menu = new PopupMenu(this, anchor, Gravity.END);
        menu.getMenu().add(0, 3, 0, R.string.make_default_profile); menu.getMenu().add(0, 1, 1, R.string.export); menu.getMenu().add(0, 2, 1, R.string.delete);
        menu.setOnMenuItemClickListener(item -> {
            if (item.getItemId() == 3) { setDefault(id); return true; }
            try {
                JSONObject data = vault.read(); JSONArray profiles = data.getJSONArray("profiles");
                if (item.getItemId() == 1) {
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
            return true;
        });
        menu.show();
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
        new AlertDialog.Builder(this).setTitle(getString(R.string.export_contains_credentials)).setItems(formats, (d, choice) -> {
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
        }).show();
    }
    private void qr() {
        new AlertDialog.Builder(this).setTitle(R.string.qr_import).setItems(new String[]{getString(R.string.qr_camera), getString(R.string.qr_image)}, (d,w) -> {
            if (w == 0) new com.google.zxing.integration.android.IntentIntegrator(this).setCaptureActivity(QrCaptureActivity.class)
                .setDesiredBarcodeFormats(com.google.zxing.integration.android.IntentIntegrator.QR_CODE).setPrompt(getString(R.string.qr_prompt))
                .setBeepEnabled(false).setBarcodeImageEnabled(false).setOrientationLocked(false).initiateScan();
            else startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("image/*").addCategory(Intent.CATEGORY_OPENABLE), QR_IMAGE);
        }).show();
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
        int[] choice = {TunnelService.inheritMetering(this) ? 1 : 0};
        new AlertDialog.Builder(this).setTitle(R.string.metering_title)
            .setSingleChoiceItems(new String[]{getString(R.string.metering_always), getString(R.string.metering_inherit)}, choice[0], (d, w) -> choice[0] = w)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(android.R.string.ok, (d, w) -> {
                boolean inherit = choice[0] == 1;
                if (inherit == TunnelService.inheritMetering(this)) return;
                TunnelService.setInheritMetering(this, inherit);
                if (TunnelService.active) Toast.makeText(this, R.string.metering_next_connection, Toast.LENGTH_LONG).show();
            }).show();
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
