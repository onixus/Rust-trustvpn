package org.rtrusttunnel.android;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import androidx.core.content.FileProvider;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.util.Locale;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * GitHub Release lookup for the Android package. SHA256SUMS is unsigned, so a
 * match only proves the APK equals that list. Nothing here installs the APK:
 * the verified file is handed to the system installer, which asks the user.
 */
final class GithubUpdate {
    static final String REPOSITORY = "onixus/Rust-trustvpn";
    private static final String ASSET = "R-TrustTunnel-Android.apk";
    private static final String HOST = "github.com";
    private static final int LIMIT = 256 * 1024 * 1024;

    static final class Release {
        final String tag, version, page, sha256;
        final boolean newer;
        final long size;
        Release(String tag, String version, String page, String sha256, boolean newer, long size) {
            this.tag = tag; this.version = version; this.page = page;
            this.sha256 = sha256; this.newer = newer; this.size = size;
        }
    }

    private GithubUpdate() {}

    /** Latest stable release bound to the Android asset through SHA256SUMS. */
    static Release check(String current) throws Exception {
        JSONObject release = getJson("https://api.github.com/repos/" + REPOSITORY + "/releases/latest");
        if (release.optBoolean("draft") || release.optBoolean("prerelease"))
            throw new IllegalStateException("draft");
        String tag = release.getString("tag_name");
        if (!safe(tag)) throw new IllegalStateException("tag");
        String sums = getText(assetUrl(tag, "SHA256SUMS"), 256 * 1024, true);
        String hash = hashOf(sums, ASSET);
        if (hash == null) throw new IllegalStateException("sums");
        long size = assetSize(release, ASSET);
        return new Release(tag, tag.startsWith("v") ? tag.substring(1) : tag,
            "https://" + HOST + "/" + REPOSITORY + "/releases/tag/" + tag,
            hash, newer(tag, current), size);
    }

    /** Download the asset and reject it unless its bytes match SHA256SUMS. */
    static File download(Activity activity, Release release) throws Exception {
        if (!release.newer || release.size <= 0 || release.size > LIMIT) throw new IllegalStateException("asset");
        File dir = new File(activity.getCacheDir(), "updates");
        if (!dir.isDirectory() && !dir.mkdirs()) throw new IllegalStateException("dir");
        File out = new File(dir, ASSET);
        File part = new File(dir, ASSET + ".part");
        HttpURLConnection connection = open(assetUrl(release.tag, ASSET), true);
        try (InputStream in = connection.getInputStream(); FileOutputStream file = new FileOutputStream(part)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[65536];
            long count = 0;
            int read;
            while ((read = in.read(buffer)) >= 0) {
                count += read;
                if (count > release.size) throw new IllegalStateException("size");
                digest.update(buffer, 0, read);
                file.write(buffer, 0, read);
            }
            if (count != release.size || !hex(digest.digest()).equals(release.sha256))
                throw new IllegalStateException("hash");
        } finally {
            connection.disconnect();
        }
        if (out.exists() && !out.delete()) throw new IllegalStateException("replace");
        if (!part.renameTo(out)) throw new IllegalStateException("rename");
        return out;
    }

    /** Hand the verified APK to the system installer. The user confirms it. */
    static void offer(Activity activity, File apk) {
        if (!activity.getPackageManager().canRequestPackageInstalls()) {
            activity.startActivity(new Intent(
                android.provider.Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                Uri.parse("package:" + activity.getPackageName())));
            return;
        }
        Uri uri = FileProvider.getUriForFile(activity, activity.getPackageName() + ".updates", apk);
        Intent intent = new Intent(Intent.ACTION_VIEW)
            .setDataAndType(uri, "application/vnd.android.package-archive")
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_ACTIVITY_NEW_TASK);
        activity.startActivity(intent);
    }

    private static boolean newer(String tag, String current) {
        int[] published = parts(tag), installed = parts(current);
        if (published == null || installed == null) return false;
        for (int i = 0; i < 3; i++) if (published[i] != installed[i]) return published[i] > installed[i];
        return false;
    }

    private static int[] parts(String version) {
        String bare = version.startsWith("v") ? version.substring(1) : version;
        int cut = bare.length();
        for (int i = 0; i < bare.length(); i++) if (bare.charAt(i) == '-' || bare.charAt(i) == '+') { cut = i; break; }
        String[] split = bare.substring(0, cut).split("\\.");
        if (split.length != 3) return null;
        int[] values = new int[3];
        for (int i = 0; i < 3; i++) {
            try { values[i] = Integer.parseInt(split[i]); }
            catch (NumberFormatException e) { return null; }
        }
        return values;
    }

    private static String hashOf(String sums, String name) {
        for (String line : sums.split("\n")) {
            int gap = line.indexOf("  ");
            if (gap != 64) continue;
            if (line.substring(gap + 2).trim().equals(name)) return line.substring(0, 64).toLowerCase(Locale.ROOT);
        }
        return null;
    }

    private static long assetSize(JSONObject release, String name) throws Exception {
        JSONArray assets = release.getJSONArray("assets");
        for (int i = 0; i < assets.length(); i++) {
            JSONObject asset = assets.getJSONObject(i);
            if (name.equals(asset.getString("name"))) return asset.getLong("size");
        }
        throw new IllegalStateException("asset");
    }

    private static JSONObject getJson(String url) throws Exception {
        return new JSONObject(getText(url, 1024 * 1024, false));
    }

    private static String getText(String url, int limit, boolean redirect) throws Exception {
        HttpURLConnection connection = open(url, redirect);
        try (InputStream in = connection.getInputStream()) {
            byte[] data = read(in, limit);
            return new String(data, java.nio.charset.StandardCharsets.UTF_8);
        } finally {
            connection.disconnect();
        }
    }

    private static byte[] read(InputStream in, int limit) throws Exception {
        byte[] data = new byte[0];
        byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) >= 0) {
            if (data.length + read > limit) throw new IllegalStateException("limit");
            byte[] next = new byte[data.length + read];
            System.arraycopy(data, 0, next, 0, data.length);
            System.arraycopy(buffer, 0, next, data.length, read);
            data = next;
        }
        return data;
    }

    /** `redirect` follows exactly one hop to GitHub's signed release-asset host. */
    private static HttpURLConnection open(String address, boolean redirect) throws Exception {
        HttpURLConnection connection = connect(address, false);
        int code = connection.getResponseCode();
        if (redirect && (code == 301 || code == 302 || code == 307 || code == 308)) {
            String next = connection.getHeaderField("Location");
            connection.disconnect();
            connection = connect(next, true);
            code = connection.getResponseCode();
        }
        if (code != 200) throw new IllegalStateException("status");
        return connection;
    }

    private static HttpURLConnection connect(String address, boolean assetHost) throws Exception {
        URL url = new URL(address);
        String host = url.getHost();
        boolean allowed = "https".equals(url.getProtocol()) && (assetHost
            ? host.equals("release-assets.githubusercontent.com") || host.equals("objects.githubusercontent.com")
            : url.getQuery() == null && (host.equals("api.github.com") || host.equals(HOST)));
        if (!allowed) throw new IllegalStateException("url");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setInstanceFollowRedirects(false);
        connection.setConnectTimeout(10_000);
        connection.setReadTimeout(120_000);
        connection.setRequestProperty("User-Agent", "rtrust-update");
        connection.setRequestProperty("Accept", "application/vnd.github+json");
        return connection;
    }

    private static String assetUrl(String tag, String name) {
        if (!safe(tag) || !safe(name)) throw new IllegalArgumentException("name");
        return "https://" + HOST + "/" + REPOSITORY + "/releases/download/" + tag + "/" + name;
    }

    private static boolean safe(String value) {
        if (value.isEmpty() || value.length() > 160 || value.contains("..")) return false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (!(Character.isLetterOrDigit(c) || c == '.' || c == '-' || c == '_')) return false;
        }
        return true;
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) out.append(String.format(Locale.ROOT, "%02x", b));
        return out.toString();
    }
}
