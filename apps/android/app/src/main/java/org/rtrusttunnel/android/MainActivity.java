package org.rtrusttunnel.android;

import android.app.*;
import android.content.*;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.*;
import android.os.*;
import android.view.*;
import android.widget.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.json.*;

/** Native Android widgets; no WebView and no remote UI code. */
public final class MainActivity extends Activity {
    private static final int PICK = 10, SAVE = 11, CONSENT = 12, QR_IMAGE = 13;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private LinearLayout rows;
    private TextView status;
    private Button connect, routing;
    private int connectionColor;
    private ProfileVault vault;
    private final Runnable poll = new Runnable() {
        public void run() {
            try {
                JSONObject state = new JSONObject(NativeCore.INSTANCE.status());
                TunnelService.refreshPolicy();
                int nativeState = state.optInt("state", 0);
                String message = !TunnelService.problem.isEmpty() ? TunnelService.problem : nativeState == 2 ? getString(R.string.connected) : nativeState == 1 ? getString(R.string.connecting) : nativeState == 3 ? getString(R.string.reconnecting) : nativeState == 4 ? getString(R.string.connection_failed) : "";
                if (message.isEmpty()) message = TunnelService.active ? getString(R.string.starting_vpn) : getString(R.string.disconnected);
                if (!status.getText().toString().equals(message)) status.setText(message);
                String action = TunnelService.active ? getString(R.string.disconnect) : getString(R.string.connect_default_profile);
                connect.setEnabled(!TunnelService.active || !TunnelService.alwaysOn);
                if (!connect.getText().toString().equals(action)) connect.setText(action);
                paintConnection(connectionColor(TunnelService.active, state.optInt("state", -1), !TunnelService.problem.isEmpty()));
            } catch (Exception ignored) {
                paintConnection(Color.rgb(166, 53, 58));
                if (!status.getText().toString().equals(getString(R.string.vpn_status_unavailable))) status.setText(getString(R.string.vpn_status_unavailable));
            }
            handler.postDelayed(this, 500);
        }
    };
    @Override public void onCreate(Bundle state) {
        super.onCreate(state); getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        vault = new ProfileVault(this);
        try { PortalSyncWorker.schedule(this); } catch (Exception ignored) { /* Reconcile again on next launch. */ }
        LinearLayout root = new LinearLayout(this); root.setOrientation(LinearLayout.VERTICAL); root.setPadding(dp(16), dp(16), dp(16), dp(12));
        root.setBackgroundColor(Color.rgb(39, 47, 59));
        root.setOnApplyWindowInsetsListener((view, insets) -> {
            android.graphics.Insets bars = Build.VERSION.SDK_INT >= 30 ? insets.getInsets(WindowInsets.Type.systemBars()) : insets.getSystemWindowInsets();
            view.setPadding(dp(16) + bars.left, dp(12) + bars.top, dp(16) + bars.right, dp(12) + bars.bottom); return insets;
        });
        TextView title = new TextView(this); title.setText("R-TrustTunnel"); title.setTextSize(23); title.setTypeface(null, Typeface.BOLD); root.addView(title);
        root.addView(button(getString(R.string.import_file), () -> startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("*/*").addCategory(Intent.CATEGORY_OPENABLE), PICK)));
        root.addView(button(getString(R.string.paste_config_or_tt_link), () -> paste()));
        root.addView(button(getString(R.string.qr_import), this::qr));
        root.addView(button(getString(R.string.portal_title), () -> new PortalDialog(this, vault, this::reload).show()));
        root.addView(button(getString(R.string.always_on), this::vpnSettings));
        routing = button(getString(R.string.vpn_apps), () -> {
            try { AppRoutingDialog.show(this, vault, this::reload); }
            catch (Exception error) { error(getString(R.string.app_selection_could_not_be_opened)); }
        }); root.addView(routing);
        ScrollView scroll = new ScrollView(this); rows = new LinearLayout(this); rows.setOrientation(LinearLayout.VERTICAL); scroll.addView(rows); root.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        TextView note = new TextView(this); note.setText(getString(R.string.vpn_uses_http_for_protection_after)); note.setTextSize(12); root.addView(note);
        status = new TextView(this); status.setTextSize(14); status.setPadding(0, dp(8), 0, dp(8)); root.addView(status);
        connect = button(getString(R.string.connect_default_profile), () -> toggle()); root.addView(connect, new LinearLayout.LayoutParams(-1, dp(60)));
        setContentView(root); reload(); incoming(getIntent());
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission("android.permission.POST_NOTIFICATIONS") != android.content.pm.PackageManager.PERMISSION_GRANTED)
            requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, 20);
    }
    private int dp(int n) { return Math.round(n * getResources().getDisplayMetrics().density); }
    private Button button(String text, Runnable click) {
        Button button = new Button(this); button.setText(text); button.setAllCaps(false); button.setGravity(Gravity.CENTER); button.setTypeface(null, Typeface.BOLD); button.setTextColor(Color.WHITE); button.setBackgroundTintList(null);
        GradientDrawable bg = new GradientDrawable(); bg.setColor(Color.rgb(68, 83, 102)); bg.setCornerRadius(dp(7)); button.setBackground(bg);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, dp(44)); params.setMargins(0, dp(4), 0, dp(4)); button.setLayoutParams(params);
        button.setOnClickListener(v -> click.run()); return button;
    }
    static int connectionColor(boolean active, int state, boolean problem) {
        if (problem || state == 4 || state < 0 || state > 4) return Color.rgb(166, 53, 58);
        if (!active) return Color.rgb(68, 83, 102);
        return state == 2 ? Color.rgb(36, 112, 68) : Color.rgb(138, 89, 0);
    }
    private void paintConnection(int color) {
        if (connectionColor == color) return;
        connectionColor = color;
        GradientDrawable background = new GradientDrawable(); background.setColor(color); background.setCornerRadius(dp(7)); connect.setBackground(background);
    }
    @Override public void onResume() { super.onResume(); reload(); handler.post(poll); }
    @Override public void onPause() { handler.removeCallbacks(poll); super.onPause(); }
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
            routing.setText(selection.selectedOnly ? getString(R.string.apps_summary, selection.packages.size()) : getString(R.string.apps_all_summary));
            for (int i = 0; i < profiles.length(); i++) {
                JSONObject item = profiles.getJSONObject(i), profile = item.getJSONObject("profile"); String id = item.getString("id");
                String name = profile.optString("name"); if (name.trim().isEmpty()) name = "Profile " + (i + 1);
                rows.addView(button((id.equals(data.getString("default")) ? "★ " : "") + name, () -> profileActions(id)));
            }
            if (profiles.length() == 0) { TextView empty = new TextView(this); empty.setText(getString(R.string.import_a_profile_to_get_started)); rows.addView(empty); }
        } catch (Exception e) { error(getString(R.string.encrypted_profiles_could_not_be_opened)); }
    }
    private void profileActions(String id) {
        new AlertDialog.Builder(this).setItems(new String[]{getString(R.string.use_as_default), getString(R.string.export), getString(R.string.delete)}, (dialog, which) -> {
            try {
                JSONObject data = vault.read(); JSONArray profiles = data.getJSONArray("profiles");
                if (which == 0) { vault.edit(current -> {
                    JSONArray latest = current.getJSONArray("profiles");
                    for (int i = 0; i < latest.length(); i++) if (latest.getJSONObject(i).getString("id").equals(id)) { current.put("default", id); return; }
                    throw new IOException("Profile removed during sync");
                }); reload(); }
                else if (which == 1) {
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
        }).show();
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
            new AlertDialog.Builder(this).setTitle(getString(R.string.import_profile_text)).setMessage(profile.optString("name", "") + "\n" + endpoint.getString("hostname") + " · " + ("hysteria2".equals(profile.optString("protocol")) ? "Hysteria 2" : "TrustTunnel") + warning + getString(R.string.ncredentials_will_be_encrypted_on_this))
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
    private void export(String raw) {
        final boolean hysteria;
        try {hysteria="hysteria2".equals(new JSONObject(raw).optString("protocol"));}catch(Exception e){error(getString(R.string.could_not_export_this_profile));return;}
        String[] formats=hysteria?new String[]{"JSON",getString(R.string.tt_link)}:new String[]{"JSON",getString(R.string.endpoint_toml),getString(R.string.cli_toml),getString(R.string.tt_link)};
        new AlertDialog.Builder(this).setTitle(getString(R.string.export_contains_credentials)).setItems(formats, (d, choice) -> {
            int format=hysteria&&choice==1?3:choice;
            try {
                JSONObject output = new JSONObject(NativeCore.INSTANCE.export(raw, format));
                if (!output.getBoolean("ok")) { error(output.optString("message")); return; }
                new AlertDialog.Builder(this).setTitle(getString(R.string.save_unencrypted_credentials)).setMessage(getString(R.string.anyone_with_this_file_can_use) + output.getJSONArray("losses").toString())
                    .setNegativeButton(getString(R.string.cancel), null).setPositiveButton(getString(R.string.choose_file), (confirm, which) -> {
                        try { vault.pendingExport(output.getString("content")); }
                        catch (Exception e) { error(getString(R.string.export_failed)); return; }
                        startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).setType(format == 0 ? "application/json" : format == 3 ? "text/plain" : "application/toml").addCategory(Intent.CATEGORY_OPENABLE)
                            .putExtra(Intent.EXTRA_TITLE, "rtrust-profile." + (format == 0 ? "json" : format == 3 ? "txt" : "toml")), SAVE);
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
    private void vpnSettings() {
        String state = TunnelService.active ? getString(R.string.always_status, TunnelService.alwaysOn, TunnelService.lockdown) : getString(R.string.always_status_unknown);
        new AlertDialog.Builder(this).setTitle(R.string.always_on).setMessage(state + "\n\n" + getString(R.string.always_help))
            .setNegativeButton(android.R.string.cancel, null).setPositiveButton(R.string.open_settings, (d,w) -> {
                try { startActivity(new Intent(android.provider.Settings.ACTION_VPN_SETTINGS)); }
                catch (ActivityNotFoundException e) { startActivity(new Intent(android.provider.Settings.ACTION_WIRELESS_SETTINGS)); }
            }).show();
    }
    private void toggle() {
        if (TunnelService.active && TunnelService.alwaysOn) { vpnSettings(); return; }
        if (TunnelService.active) { startService(new Intent(this, TunnelService.class).setAction(TunnelService.STOP)); return; }
        try {
            JSONObject profile = vault.selected();
            JSONObject prepared = new JSONObject(NativeCore.INSTANCE.plan(profile.toString()));
            if (!prepared.getBoolean("ok")) {
                error(getString(R.string.desktop_routing_policy_is_not_supported)); return;
            }
        } catch (Exception e) { error(getString(R.string.import_and_select_a_default_profile)); return; }
        try { AppRouting.read(vault.read()).validateInstalled(getPackageManager()); }
        catch (Exception error) { error(getString(R.string.check_vpn_apps_select_at_least)); return; }
        Intent consent = VpnService.prepare(this);
        if (consent != null) startActivityForResult(consent, CONSENT); else startForegroundService(new Intent(this, TunnelService.class));
    }
    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        com.google.zxing.integration.android.IntentResult qr = com.google.zxing.integration.android.IntentIntegrator.parseActivityResult(request, result, data);
        if (qr != null) { if (qr.getContents() != null) preview(qr.getContents()); return; }
        if (request == QR_IMAGE && result == RESULT_OK && data != null) {
            android.net.Uri uri = data.getData();
            new Thread(() -> {
                try (InputStream in = getContentResolver().openInputStream(uri)) {
                    if (in == null) throw new IOException(); String raw = QrImport.decode(in);
                    runOnUiThread(() -> { if (!isDestroyed()) preview(raw); });
                } catch (Exception e) { runOnUiThread(() -> { if (!isDestroyed()) error(getString(R.string.qr_failed)); }); }
            }, "qr-import").start();
        }
        if (request == CONSENT && result == RESULT_OK) startForegroundService(new Intent(this, TunnelService.class));
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
