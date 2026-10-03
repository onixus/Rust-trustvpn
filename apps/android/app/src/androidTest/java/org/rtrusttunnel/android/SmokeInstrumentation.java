package org.rtrusttunnel.android;

import android.app.Instrumentation;
import android.os.Bundle;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import org.json.*;

/** Runs only in the separately installed test APK. No test endpoints in the product. */
public final class SmokeInstrumentation extends Instrumentation {
    private Bundle arguments;
    @Override public void onCreate(Bundle args) { super.onCreate(args); arguments = args; start(); }
    private void check(boolean result, String message) { if (!result) throw new AssertionError(message); }
    @Override public void onStart() {
        Bundle result = new Bundle();
        try {
            String upgrade = arguments.getString("upgrade");
            if (upgrade != null) {
                ProfileVault vault = new ProfileVault(getTargetContext()); JSONObject data = vault.read();
                if (upgrade.equals("seed")) {
                    JSONObject profile = new JSONObject(NativeCore.INSTANCE.parse("hostname='upgrade.example'\naddresses=['192.0.2.1:443']\nusername='synthetic'\npassword='upgrade-synthetic-canary'\n")).getJSONObject("profile");
                    data.put("test_previous_default", data.getString("default"));
                    data.put("test_previous_routing", data.opt("app_routing"));
                    data.put("app_routing", new AppRouting(true, java.util.Collections.singletonList(getTargetContext().getPackageName())).json());
                    data.getJSONArray("profiles").put(new JSONObject().put("id", "upgrade-test").put("profile", profile));
                    data.put("default", "upgrade-test"); vault.write(data);
                } else {
                    check(data.getString("default").equals("upgrade-test"), "Default survives upgrade");
                    check(AppRouting.read(data).selectedOnly && AppRouting.read(data).packages.contains(getTargetContext().getPackageName()), "App routing survives upgrade");
                    check(vault.selected().getJSONObject("endpoint").getString("password").equals("upgrade-synthetic-canary"), "Keystore survives upgrade");
                    if (upgrade.equals("finish")) {
                        JSONArray old = data.getJSONArray("profiles"), kept = new JSONArray();
                        for (int i = 0; i < old.length(); i++) if (!old.getJSONObject(i).getString("id").equals("upgrade-test")) kept.put(old.get(i));
                        data.put("profiles", kept).put("default", data.getString("test_previous_default")); data.remove("test_previous_default");
                        if (data.has("test_previous_routing")) data.put("app_routing", data.get("test_previous_routing")); else data.remove("app_routing");
                        data.remove("test_previous_routing"); vault.write(data);
                    }
                }
                result.putString("stream", "PASS: upgrade " + upgrade + "\n"); finish(-1, result); return;
            }
            if ("true".equals(arguments.getString("network"))) {
                NetworkAcceptance.run(this);
                result.putString("stream", "PASS: VPN IPv4/IPv6 TCP512KiB, UDP1/1472/5000/60000, system DNS, outage guard, reconnect, Activity close, Stop, unavailable startup DNS guard\n");
                finish(-1, result); return;
            }
            MobileFeaturesAcceptance.run(this);
            AppRoutingAcceptance.smoke(this);
            String secret = "android-test-synthetic-password";
            String raw = "hostname='test.example'\naddresses=['192.0.2.1:443']\nusername='synthetic'\npassword='" + secret + "'\n";
            JSONObject parsed = new JSONObject(NativeCore.INSTANCE.parse(raw));
            check(parsed.getBoolean("ok"), "JNI import");
            JSONObject profile = parsed.getJSONObject("profile");
            for (int format = 0; format < 4; format++) {
                JSONObject exported = new JSONObject(NativeCore.INSTANCE.export(profile.toString(), format));
                check(exported.getBoolean("ok"), "JNI export");
                JSONObject imported = new JSONObject(NativeCore.INSTANCE.parse(exported.getString("content")));
                check(imported.getJSONObject("profile").getJSONObject("endpoint").getString("password").equals(secret), "Round trip");
            }
            check(!new JSONObject(NativeCore.INSTANCE.parse("password='" + secret + "'")).toString().contains(secret), "Error redaction");
            ProfileVault vault = new ProfileVault(getTargetContext());
            JSONObject original = vault.read();
            try {
                vault.write(new JSONObject().put("default", "test").put("profiles", new JSONArray().put(new JSONObject().put("id", "test").put("profile", profile))));
                check(new ProfileVault(getTargetContext()).selected().getJSONObject("endpoint").getString("password").equals(secret), "Keystore persistence");
                java.io.File file = new java.io.File(getTargetContext().getNoBackupFilesDir(), "profiles.enc");
                byte[] encrypted = Files.readAllBytes(file.toPath());
                check(!new String(encrypted, StandardCharsets.ISO_8859_1).contains(secret), "No plaintext credentials");
                encrypted[encrypted.length - 1] ^= 1; Files.write(file.toPath(), encrypted);
                boolean rejected = false; try { vault.read(); } catch (Exception expected) { rejected = true; }
                check(rejected, "Tamper rejection");
            } finally { vault.write(original); }
            check(new JSONObject(NativeCore.INSTANCE.status()).getInt("state") == 0, "Initial disconnected state");
            check(!NativeCore.INSTANCE.start(profile.toString(), -1, this), "Invalid TUN rejected");
            NativeCore.INSTANCE.stop();
            result.putString("stream", "PASS: JNI codec, four formats, redaction, Keystore persistence, encrypted file, tamper rejection, invalid FD, portal sync, QR camera/image, Russian resources, export recreation, Always-on declaration\n");
            finish(-1, result);
        } catch (Throwable error) {
            // Exception messages may carry addresses or profile data; the failing test
            // lines are safe and tell which step failed.
            StringBuilder where = new StringBuilder(); int frames = 0;
            for (StackTraceElement frame : error.getStackTrace()) {
                if (!frame.getClassName().startsWith("org.rtrusttunnel.android.") || frames == 3) continue;
                where.append(frames++ == 0 ? " at " : " < ").append(frame.getFileName()).append(':').append(frame.getLineNumber());
            }
            result.putString("stream", "FAIL: " + error.getClass().getSimpleName() + (error instanceof AssertionError ? ": " + error.getMessage() : "") + where + "\n"); finish(1, result);
        }
    }
}
