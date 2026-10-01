package org.rtrusttunnel.android;

import android.app.Instrumentation;
import android.content.*;
import android.content.res.Configuration;
import android.graphics.Bitmap;
import java.io.*;
import java.util.Locale;
import org.json.*;
import com.google.zxing.*;
import com.google.zxing.common.BitMatrix;

final class MobileFeaturesAcceptance {
    private static void check(boolean value, String message) { if (!value) throw new AssertionError(message); }
    static void run(Instrumentation test) throws Exception {
        Context context = test.getTargetContext();
        android.app.Activity camera = test.startActivitySync(new Intent(context, QrCaptureActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
        try { test.waitForIdleSync(); check(!camera.isFinishing(), "Camera scanner starts without missing runtime classes"); }
        finally { test.runOnMainSync(camera::finish); }
        for (String invalid : new String[]{"http://vpn.example", "https://user:pass@vpn.example", "https://vpn.example/path", "https://vpn.example?token=x", "https://vpn.example/#fragment", "https://vpn.example:0"}) {
            boolean rejected = false; try { PortalClient.origin(invalid); } catch (Exception expected) { rejected = true; }
            check(rejected, "Unsafe portal origin rejected");
        }
        check(PortalClient.origin("https://vpn.example:8443/").equals("https://vpn.example:8443"), "HTTPS port retained");
        boolean rejected = false; try { PortalClient.id("../export"); } catch (Exception expected) { rejected = true; }
        check(rejected, "Untrusted server identifier rejected");
        Configuration config = new Configuration(context.getResources().getConfiguration()); config.setLocale(new Locale("ru"));
        Context russian = context.createConfigurationContext(config);
        check(russian.getString(R.string.qr_import).equals("Импорт QR-кода"), "Russian resources loaded");
        android.content.pm.ServiceInfo service = context.getPackageManager().getServiceInfo(new ComponentName(context, TunnelService.class), android.content.pm.PackageManager.GET_META_DATA);
        check(service.metaData.getBoolean("android.net.VpnService.SUPPORTS_ALWAYS_ON"), "Always-on advertised to Android");
        String raw = "hostname='qr.example'\naddresses=['192.0.2.1:443']\nusername='synthetic'\npassword='mobile-test-canary'\n";
        JSONObject profile = new JSONObject(NativeCore.INSTANCE.parse(raw)).getJSONObject("profile");
        String link = new JSONObject(NativeCore.INSTANCE.export(profile.toString(), 3)).getString("content");
        BitMatrix matrix = new MultiFormatWriter().encode(link, BarcodeFormat.QR_CODE, 700, 700);
        Bitmap bitmap = Bitmap.createBitmap(700, 700, Bitmap.Config.ARGB_8888);
        for (int y = 0; y < 700; y++) for (int x = 0; x < 700; x++) bitmap.setPixel(x, y, matrix.get(x,y) ? 0xff000000 : 0xffffffff);
        ByteArrayOutputStream encoded = new ByteArrayOutputStream(); bitmap.compress(Bitmap.CompressFormat.PNG, 100, encoded); bitmap.recycle();
        String decoded = QrImport.decode(new ByteArrayInputStream(encoded.toByteArray()));
        check(decoded.equals(link), "Offline image QR preserves profile bytes");
        check(new JSONObject(NativeCore.INSTANCE.parse(decoded)).getBoolean("ok"), "QR uses shared profile parser");
        rejected = false; try { QrImport.decode(new ByteArrayInputStream(new byte[]{0,1,2})); } catch (Exception expected) { rejected = true; }
        check(rejected, "Invalid QR image rejected");
        ProfileVault vault = new ProfileVault(context); JSONObject original = vault.read();
        try {
            vault.write(new JSONObject().put("profiles", new JSONArray().put(new JSONObject().put("id", "local").put("profile", profile))).put("default", "local"));
            JSONObject session = new JSONObject().put("origin", "https://vpn.example").put("token", "a".repeat(43));
            vault.savePortal(session);
            JSONArray remote = new JSONArray().put(new JSONObject().put("id", "portal:one").put("remote_id", "one").put("revision", "1").put("profile", profile));
            vault.syncPortal(session, remote);
            check(vault.read().getJSONArray("profiles").length() == 2, "Sync preserves local profiles");
            check(vault.read().getString("default").equals("local"), "Sync preserves default");
            JSONObject changed = vault.read(); changed.put("default", "portal:one"); vault.write(changed);
            vault.syncPortal(session, new JSONArray());
            check(vault.read().getJSONArray("profiles").length() == 1 && vault.read().getString("default").equals("local"), "Withdrawn grant removed and default repaired");
            vault.pendingExport("export-secret");
            check(new ProfileVault(context).takeExport().equals("export-secret"), "Pending export survives Activity recreation");
            check(vault.takeExport() == null, "Pending export consumed once");
            vault.forgetPortal();
            check(!vault.read().has("portal") && vault.read().getJSONArray("profiles").length() == 1, "Forget removes token but preserves local profile");
        } finally { vault.write(original); }
    }
}
