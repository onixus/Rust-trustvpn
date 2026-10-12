package org.rtrusttunnel.android;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import javax.net.ssl.HttpsURLConnection;
import org.json.*;

/** The same v2 one-time enrollment / revision contract as the server UI. */
class PortalClient {
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
    static java.util.Map<String, java.util.List<String>> metadata(JSONArray profiles) throws Exception {
        if (profiles.length() > 64) throw new IOException("Invalid profile list");
        java.util.Map<String, java.util.List<String>> result = new java.util.TreeMap<>();
        for (int i = 0; i < profiles.length(); i++) {
            JSONObject item = profiles.getJSONObject(i);
            Object rawId = item.opt("id"), rawRevision = item.opt("revision");
            if (!(rawId instanceof String) || !(rawRevision instanceof String)) throw new IOException("Invalid profile metadata");
            String remoteId = id((String) rawId), revision = (String) rawRevision;
            if (!revision.matches("[!-~]{1,256}")) throw new IOException("Invalid profile metadata");
            Object rawOrigin = item.opt("origin");
            String profileOrigin = null;
            if (rawOrigin != null && rawOrigin != JSONObject.NULL) {
                if (!(rawOrigin instanceof String)) throw new IOException("Invalid profile metadata");
                profileOrigin = (String) rawOrigin;
                if (profileOrigin.isEmpty() || profileOrigin.getBytes(StandardCharsets.UTF_8).length > 80
                    || profileOrigin.codePoints().anyMatch(Character::isISOControl)) throw new IOException("Invalid profile metadata");
            }
            if (result.put(remoteId, java.util.Arrays.asList(revision, profileOrigin)) != null)
                throw new IOException("Duplicate profile identifier");
        }
        return result;
    }
    JSONObject parseExport(String content) throws Exception {
        JSONObject parsed = new JSONObject(NativeCore.INSTANCE.parse(content));
        if (!parsed.getBoolean("ok")) throw new IOException();
        return parsed.getJSONObject("profile");
    }
    static void checkCancelled() throws java.io.InterruptedIOException {
        if (Thread.currentThread().isInterrupted()) throw new java.io.InterruptedIOException("Synchronization cancelled");
    }
    JSONArray download() throws Exception {
        checkCancelled();
        java.util.Map<String, java.util.List<String>> before = metadata(request("/portal/v2/profiles", null).getJSONArray("profiles"));
        JSONArray result = new JSONArray();
        for (java.util.Map.Entry<String, java.util.List<String>> entry : before.entrySet()) {
            checkCancelled();
            String remoteId = entry.getKey(), revision = entry.getValue().get(0);
            JSONObject exported = request("/portal/v2/profiles/" + remoteId + "/export", new JSONObject()
                .put("format", "profile_json").put("revision", revision).put("include_secrets", true).put("accept_losses", false));
            JSONObject profile = parseExport(exported.getString("content"));
            result.put(new JSONObject().put("id", "portal:" + remoteId).put("remote_id", remoteId).put("revision", revision)
                .put("profile", profile));
        }
        if (!before.equals(metadata(request("/portal/v2/profiles", null).getJSONArray("profiles"))))
            throw new IOException("Profile list changed during synchronization");
        checkCancelled();
        return result;
    }
    static final class Failure extends IOException {
        final int status;
        Failure(int status) { super("Portal request failed"); this.status = status; }
    }
}
