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
    private static final int PICK = 10, SAVE = 11, CONSENT = 12;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private LinearLayout rows;
    private TextView status;
    private Button connect;
    private String pendingExport;
    private ProfileVault vault;
    private final Runnable poll = new Runnable() {
        public void run() {
            try {
                JSONObject state = new JSONObject(NativeCore.INSTANCE.status());
                status.setText(!TunnelService.problem.isEmpty() ? TunnelService.problem : state.optString("message", ""));
                if (status.length() == 0) status.setText(TunnelService.active ? "Starting VPN…" : "Disconnected");
                connect.setText(TunnelService.active ? "Disconnect" : "Connect default profile");
            } catch (Exception ignored) { status.setText("VPN status unavailable"); }
            handler.postDelayed(this, 500);
        }
    };
    @Override public void onCreate(Bundle state) {
        super.onCreate(state); getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        vault = new ProfileVault(this);
        LinearLayout root = new LinearLayout(this); root.setOrientation(LinearLayout.VERTICAL); root.setPadding(dp(16), dp(16), dp(16), dp(12));
        root.setBackgroundColor(Color.rgb(39, 47, 59));
        root.setOnApplyWindowInsetsListener((view, insets) -> {
            android.graphics.Insets bars = Build.VERSION.SDK_INT >= 30 ? insets.getInsets(WindowInsets.Type.systemBars()) : insets.getSystemWindowInsets();
            view.setPadding(dp(16) + bars.left, dp(12) + bars.top, dp(16) + bars.right, dp(12) + bars.bottom); return insets;
        });
        TextView title = new TextView(this); title.setText("R-TrustTunnel"); title.setTextSize(23); title.setTypeface(null, Typeface.BOLD); root.addView(title);
        connect = button("Connect default profile", () -> toggle()); root.addView(connect, new LinearLayout.LayoutParams(-1, dp(60)));
        status = new TextView(this); status.setTextSize(14); status.setPadding(0, dp(8), 0, dp(8)); root.addView(status);
        root.addView(button("Import file", () -> startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("*/*").addCategory(Intent.CATEGORY_OPENABLE), PICK)));
        root.addView(button("Paste config or tt:// link", () -> paste()));
        ScrollView scroll = new ScrollView(this); rows = new LinearLayout(this); rows.setOrientation(LinearLayout.VERTICAL); scroll.addView(rows); root.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        TextView note = new TextView(this); note.setText("System VPN uses HTTP/2. HTTP/3 remains saved in your profile. Traffic is blocked during reconnection; protection ends when you disconnect."); note.setTextSize(12); root.addView(note);
        setContentView(root); reload(); incoming(getIntent());
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission("android.permission.POST_NOTIFICATIONS") != android.content.pm.PackageManager.PERMISSION_GRANTED)
            requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, 20);
    }
    private int dp(int n) { return Math.round(n * getResources().getDisplayMetrics().density); }
    private Button button(String text, Runnable click) {
        Button button = new Button(this); button.setText(text); button.setAllCaps(false); button.setGravity(Gravity.CENTER); button.setTypeface(null, Typeface.BOLD);
        GradientDrawable bg = new GradientDrawable(); bg.setColor(Color.rgb(68, 83, 102)); bg.setCornerRadius(dp(7)); button.setBackground(bg);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, dp(44)); params.setMargins(0, dp(4), 0, dp(4)); button.setLayoutParams(params);
        button.setOnClickListener(v -> click.run()); return button;
    }
    @Override public void onResume() { super.onResume(); handler.post(poll); }
    @Override public void onPause() { handler.removeCallbacks(poll); super.onPause(); }
    @Override protected void onNewIntent(Intent intent) { super.onNewIntent(intent); setIntent(intent); incoming(intent); }
    private void incoming(Intent intent) {
        if (Intent.ACTION_VIEW.equals(intent.getAction()) && intent.getData() != null && "tt".equals(intent.getData().getScheme())) {
            String raw = intent.getDataString(); intent.setData(null); preview(raw);
        }
    }
    private void error(String message) { new AlertDialog.Builder(this).setTitle("R-TrustTunnel").setMessage(message).setPositiveButton("OK", null).show(); }
    private void reload() {
        rows.removeAllViews();
        try {
            JSONObject data = vault.read(); JSONArray profiles = data.getJSONArray("profiles");
            for (int i = 0; i < profiles.length(); i++) {
                JSONObject item = profiles.getJSONObject(i), profile = item.getJSONObject("profile"); String id = item.getString("id");
                String name = profile.optString("name"); if (name.trim().isEmpty()) name = "Profile " + (i + 1);
                rows.addView(button((id.equals(data.getString("default")) ? "★ " : "") + name, () -> profileActions(id)));
            }
            if (profiles.length() == 0) { TextView empty = new TextView(this); empty.setText("Import a profile to get started."); rows.addView(empty); }
        } catch (Exception e) { error("Encrypted profiles could not be opened. Existing data has been preserved."); }
    }
    private void profileActions(String id) {
        new AlertDialog.Builder(this).setItems(new String[]{"Use as default", "Export…", "Delete…"}, (dialog, which) -> {
            try {
                JSONObject data = vault.read(); JSONArray profiles = data.getJSONArray("profiles");
                if (which == 0) { data.put("default", id); vault.write(data); reload(); }
                else if (which == 1) {
                    for (int i = 0; i < profiles.length(); i++) if (profiles.getJSONObject(i).getString("id").equals(id)) export(profiles.getJSONObject(i).getJSONObject("profile").toString());
                } else new AlertDialog.Builder(this).setMessage("Delete this saved profile?").setNegativeButton("Cancel", null).setPositiveButton("Delete", (d, w) -> {
                    try {
                        JSONObject current = vault.read(); JSONArray old = current.getJSONArray("profiles"), kept = new JSONArray();
                        for (int i = 0; i < old.length(); i++) if (!old.getJSONObject(i).getString("id").equals(id)) kept.put(old.get(i));
                        current.put("profiles", kept);
                        if (id.equals(current.getString("default"))) current.put("default", kept.length() == 0 ? "" : kept.getJSONObject(0).getString("id"));
                        vault.write(current); reload();
                    } catch (Exception e) { error("Could not save profile changes."); }
                }).show();
            } catch (Exception e) { error("Could not open profile."); }
        }).show();
    }
    private void paste() {
        EditText input = new EditText(this); input.setHint("TOML, JSON or tt://"); input.setMinLines(4); input.setMaxLines(10);
        input.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE | android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        input.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        input.setImeOptions(android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING);
        input.setFilters(new android.text.InputFilter[]{new android.text.InputFilter.LengthFilter(1024 * 1024)});
        new AlertDialog.Builder(this).setTitle("Import profile").setView(input).setNegativeButton("Cancel", null).setPositiveButton("Preview", (d, w) -> { String raw = input.getText().toString(); input.setText(""); preview(raw); }).show();
    }
    private void preview(String raw) {
        try {
            JSONObject parsed = new JSONObject(NativeCore.INSTANCE.parse(raw));
            if (!parsed.getBoolean("ok")) { error(parsed.optString("message", "Invalid profile")); return; }
            JSONObject profile = parsed.getJSONObject("profile"), endpoint = profile.getJSONObject("endpoint");
            String warning = endpoint.optBoolean("skip_verification") ? "\nWARNING: certificate verification is disabled in this profile." : "";
            new AlertDialog.Builder(this).setTitle("Import profile?").setMessage(profile.optString("name", "") + "\n" + endpoint.getString("hostname") + warning + "\nCredentials will be encrypted on this device.")
                .setNegativeButton("Cancel", null).setPositiveButton("Import", (d, w) -> {
                    try {
                        JSONObject data = vault.read(); JSONArray list = data.getJSONArray("profiles");
                        if (list.length() >= 64) throw new IOException("Profile limit");
                        String id = UUID.randomUUID().toString(); list.put(new JSONObject().put("id", id).put("profile", profile));
                        if (data.getString("default").isEmpty()) data.put("default", id);
                        vault.write(data); reload();
                    } catch (Exception e) { error("Could not save encrypted profile."); }
                }).show();
        } catch (Exception e) { error("Invalid or oversized profile."); }
    }
    private void export(String raw) {
        new AlertDialog.Builder(this).setTitle("Export contains credentials").setItems(new String[]{"JSON", "Endpoint TOML", "CLI TOML", "tt:// link"}, (d, format) -> {
            try {
                JSONObject output = new JSONObject(NativeCore.INSTANCE.export(raw, format));
                if (!output.getBoolean("ok")) { error(output.optString("message")); return; }
                new AlertDialog.Builder(this).setTitle("Save unencrypted credentials?").setMessage("Anyone with this file can use the profile. " + output.getJSONArray("losses").toString())
                    .setNegativeButton("Cancel", null).setPositiveButton("Choose file", (confirm, which) -> {
                        pendingExport = output.optString("content");
                        startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).setType("text/plain").addCategory(Intent.CATEGORY_OPENABLE)
                            .putExtra(Intent.EXTRA_TITLE, "rtrust-profile." + (format == 0 ? "json" : format == 3 ? "txt" : "toml")), SAVE);
                    }).show();
            } catch (Exception e) { error("Could not export this profile."); }
        }).show();
    }
    private void toggle() {
        if (TunnelService.active) { startService(new Intent(this, TunnelService.class).setAction(TunnelService.STOP)); return; }
        try {
            JSONObject profile = vault.selected();
            if ((profile.has("original_cli") && !profile.isNull("original_cli")) || (!profile.isNull("policy") && !profile.opt("policy").toString().equals("{}"))) {
                error("Desktop routing policy is not supported on Android yet. Export this profile as Endpoint TOML and import it to explicitly use full-tunnel routing."); return;
            }
        } catch (Exception e) { error("Import and select a default profile first."); return; }
        Intent consent = VpnService.prepare(this);
        if (consent != null) startActivityForResult(consent, CONSENT); else startForegroundService(new Intent(this, TunnelService.class));
    }
    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request == CONSENT && result == RESULT_OK) startForegroundService(new Intent(this, TunnelService.class));
        if (request == SAVE) {
            String output = pendingExport; pendingExport = null;
            if (result == RESULT_OK && data != null && output != null) try (OutputStream out = getContentResolver().openOutputStream(data.getData(), "wt")) {
                if (out == null) throw new IOException(); out.write(output.getBytes(StandardCharsets.UTF_8));
            } catch (Exception e) { error("Could not write export."); }
        }
        if (request == PICK && result == RESULT_OK && data != null) try (InputStream in = getContentResolver().openInputStream(data.getData())) {
            if (in == null) throw new IOException(); byte[] bytes = ProfileVault.readBounded(in, 1024 * 1024);
            if (bytes.length > 1024 * 1024) throw new IOException(); preview(new String(bytes, StandardCharsets.UTF_8));
            java.util.Arrays.fill(bytes, (byte) 0);
        } catch (Exception e) { error("Could not read file, or profile exceeds 1 MiB."); }
    }
}
