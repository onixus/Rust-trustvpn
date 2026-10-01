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
        JSONObject planned = new JSONObject(NativeCore.INSTANCE.plan(profile.toString()));
        check(planned.getBoolean("ok"), "Default native policy plan");
        JSONObject secureDns = new JSONObject(profile.toString());
        secureDns.put("policy", new JSONObject().put("mode", "selective").put("exclusions", new JSONArray().put("192.0.2.0/24"))
            .put("dns_upstreams", new JSONArray().put("tls://1.1.1.1")));
        planned = new JSONObject(NativeCore.INSTANCE.plan(secureDns.toString()));
        check(planned.getBoolean("ok") && planned.getJSONObject("plan").getJSONArray("dns").getString(0).equals("198.18.0.53"), "Encrypted DNS plan uses intercepted address");
        JSONArray plannedRoutes = planned.getJSONObject("plan").getJSONArray("routes");
        boolean selectedRoute = false;
        for (int i = 0; i < plannedRoutes.length(); i++) selectedRoute |= plannedRoutes.getString(i).equals("0.0.0.0/0");
        check(selectedRoute, "Flow routing captures traffic for per-destination decisions");
        secureDns.getJSONObject("policy").put("fallback", "direct");
        check(!new JSONObject(NativeCore.INSTANCE.plan(secureDns.toString())).getBoolean("ok"), "Unsupported policy fails closed");
        JSONObject hysteria = new JSONObject(NativeCore.INSTANCE.parse("hy2://test@vpn.example/?obfs=salamander&obfs-password=test")).getJSONObject("profile");
        check("hysteria2".equals(hysteria.getString("protocol")), "Hysteria protocol auto-detection");
        check(new JSONObject(NativeCore.INSTANCE.plan(hysteria.toString())).getBoolean("ok"), "Hysteria mobile plan supported");
        check(new JSONObject(NativeCore.INSTANCE.export(hysteria.toString(),3)).getString("content").startsWith("hysteria2://"), "Hysteria link auto-export");
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
            vault.syncPortalBackground(session, new JSONArray());
            check(vault.read().getJSONArray("profiles").length() == 2, "Background sync is opt-in");
            vault.setPortalSync(true);
            vault.syncPortalBackground(session, new JSONArray());
            check(vault.read().getJSONArray("profiles").length() == 1, "Enabled background sync applies withdrawal");
            vault.setPortalSync(false);
            vault.syncPortalBackground(session, remote);
            check(vault.read().getJSONArray("profiles").length() == 1, "Disabled sync rejects an in-flight result");
            vault.setPortalSync(true);
            JSONObject stale = new JSONObject(session.toString()).put("token", "b".repeat(43));
            vault.syncPortalBackground(stale, remote);
            check(vault.read().getJSONArray("profiles").length() == 1, "Replaced registration cannot overwrite profiles");
            vault.expirePortalSync(stale);
            check(vault.read().getJSONObject("portal").getBoolean("background_sync"), "Stale auth failure cannot disable current sync");
            vault.expirePortalSync(session);
            check(!vault.read().getJSONObject("portal").getBoolean("background_sync"), "Expired authorization pauses background sync");
            vault.syncPortal(session, remote);
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
