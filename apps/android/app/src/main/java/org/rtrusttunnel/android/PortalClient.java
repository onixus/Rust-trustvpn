package org.rtrusttunnel.android;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import javax.net.ssl.HttpsURLConnection;
import org.json.*;

/** The same v2 one-time enrollment / revision contract as the server UI. */
final class PortalClient {
    final String origin, token;
    static String origin(String input) throws Exception {
        URI uri = new URI(input.trim());
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || uri.getRawUserInfo() != null
            || uri.getRawQuery() != null || uri.getRawFragment() != null
            || !(uri.getRawPath().isEmpty() || uri.getRawPath().equals("/")) || uri.getPort() == 0)
            throw new IllegalArgumentException("HTTPS origin required");
        return new URI("https", null, uri.getHost(), uri.getPort(), null, null, null).toASCIIString();
    }
    PortalClient(String origin, String token) throws Exception {
        this.origin = origin(origin); this.token = token;
        if (!token.isEmpty() && !token.matches("[A-Za-z0-9_-]{40,128}")) throw new IllegalArgumentException("Invalid token");
    }
    static String id(String id) {
        if (!id.matches("[A-Za-z0-9_-]{1,80}")) throw new IllegalArgumentException("Invalid identifier");
        return id;
    }
    JSONObject request(String path, JSONObject body) throws Exception {
        if (!path.startsWith("/portal/v2/") || path.contains("..")) throw new IllegalArgumentException();
        HttpsURLConnection connection = (HttpsURLConnection) new URL(origin + path).openConnection();
        connection.setInstanceFollowRedirects(false); connection.setConnectTimeout(15000); connection.setReadTimeout(20000);
        connection.setUseCaches(false); connection.setRequestProperty("Accept", "application/json");
        if (!token.isEmpty()) connection.setRequestProperty("Authorization", "Bearer " + token);
        try {
            if (body != null) {
                byte[] bytes = body.toString().getBytes(StandardCharsets.UTF_8);
                if (bytes.length > 2 * 1024 * 1024) throw new IOException();
                connection.setRequestMethod("POST"); connection.setDoOutput(true);
                connection.setRequestProperty("Content-Type", "application/json"); connection.setFixedLengthStreamingMode(bytes.length);
                try (OutputStream out = connection.getOutputStream()) { out.write(bytes); }
                finally { java.util.Arrays.fill(bytes, (byte) 0); }
            }
            int code = connection.getResponseCode();
            if (code != 200) throw new Failure(code);
            try (InputStream in = connection.getInputStream()) {
                byte[] bytes = ProfileVault.readBounded(in, 2 * 1024 * 1024);
                try { return new JSONObject(new String(bytes, StandardCharsets.UTF_8)); }
                finally { java.util.Arrays.fill(bytes, (byte) 0); }
            }
        } finally { connection.disconnect(); }
    }
    JSONObject enroll(String code, String name) throws Exception {
        JSONObject capabilities = request("/portal/v2/capabilities", null);
        if (capabilities.getInt("version") != 2) throw new IOException();
        JSONObject result = request("/portal/v2/enroll", new JSONObject().put("code", code).put("name", name).put("platform", "android"));
        if (!result.getString("token").matches("[A-Za-z0-9_-]{40,128}") || result.getLong("device_id") < 1 || result.getLong("expires_in") < 1) throw new IOException();
        new PortalClient(origin, result.getString("token"));
        return result.put("origin", origin);
    }
    JSONArray download() throws Exception {
        JSONArray metadata = request("/portal/v2/profiles", null).getJSONArray("profiles");
        if (metadata.length() > 64) throw new IOException();
        JSONArray result = new JSONArray();
        for (int i = 0; i < metadata.length(); i++) {
            JSONObject meta = metadata.getJSONObject(i);
            String remoteId = id(meta.getString("id")), revision = meta.getString("revision");
            JSONObject exported = request("/portal/v2/profiles/" + remoteId + "/export", new JSONObject()
                .put("format", "profile_json").put("revision", revision).put("include_secrets", true).put("accept_losses", false));
            JSONObject parsed = new JSONObject(NativeCore.INSTANCE.parse(exported.getString("content")));
            if (!parsed.getBoolean("ok")) throw new IOException();
            result.put(new JSONObject().put("id", "portal:" + remoteId).put("remote_id", remoteId).put("revision", revision)
                .put("profile", parsed.getJSONObject("profile")));
        }
        return result;
    }
    static final class Failure extends IOException {
        final int status;
        Failure(int status) { super("Portal request failed"); this.status = status; }
    }
}
