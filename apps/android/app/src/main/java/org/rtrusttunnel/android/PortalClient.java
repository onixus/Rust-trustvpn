package org.rtrusttunnel.android;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import javax.net.ssl.HttpsURLConnection;
import org.json.*;

/** The same v2 one-time enrollment / revision contract as the server UI. */
class PortalClient {
    final String origin, token;
    private Long expiresAt;
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
    PortalClient(JSONObject session) throws Exception {
        this(session.getString("origin"), session.getString("token"));
        if (session.has("expires_at")) { expiresAt = session.getLong("expires_at"); if (expiresAt <= 0) throw new IOException(); }
    }
    static String id(String id) {
        if (!id.matches("[A-Za-z0-9_-]{1,80}")) throw new IllegalArgumentException("Invalid identifier");
        return id;
    }
    JSONObject request(String path, JSONObject body) throws Exception {
        if (expiresAt != null && System.currentTimeMillis()/1000 >= expiresAt) throw new Failure(401);
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
                byte[] bytes = ProfileVault.readBounded(in, 8 * 1024 * 1024);
                try { return new JSONObject(new String(bytes, StandardCharsets.UTF_8)); }
                finally { java.util.Arrays.fill(bytes, (byte) 0); }
            }
        } finally { connection.disconnect(); }
    }
    JSONObject enroll(String code, String name) throws Exception {
        JSONObject capabilities = request("/portal/v2/capabilities", null);
        if (capabilities.getInt("version") != 2) throw new IOException();
        long requestedAt = System.currentTimeMillis()/1000;
        JSONObject result = request("/portal/v2/enroll", new JSONObject().put("code", code).put("name", name).put("platform", "android"));
        if (!result.getString("token").matches("[A-Za-z0-9_-]{40,128}") || result.getLong("device_id") < 1 || result.getLong("expires_in") < 1) throw new IOException();
        new PortalClient(origin, result.getString("token"));
        long deadline = Math.addExact(requestedAt,result.getLong("expires_in"));
        if (deadline <= System.currentTimeMillis()/1000) throw new Failure(401);
        return result.put("origin", origin).put("expires_at",deadline);
    }
    JSONArray download() throws Exception {
        JSONObject capabilities = request("/portal/v2/capabilities",null);
        if (capabilities.getInt("version") != 2 || capabilities.has("routing") && capabilities.getInt("routing") != 1
            || capabilities.has("snapshot") && capabilities.getInt("snapshot") != 1) throw new IOException();
        JSONArray result = new JSONArray();
        if (capabilities.optInt("snapshot") == 1) {
            JSONObject batch = request("/portal/v2/snapshot",new JSONObject().put("include_secrets",true));
            if (batch.getInt("version") != 1 || !batch.getString("revision").matches("[0-9a-f]{64}")) throw new IOException();
            requireSupportedRouting(batch.getJSONObject("routing"));
            JSONArray items = batch.getJSONArray("profiles");
            if (items.length() > 64) throw new IOException();
            java.util.HashSet<String> ids = new java.util.HashSet<>(); int total = 0;
            for (int i=0; i<items.length(); i++) {
                JSONObject item = items.getJSONObject(i), meta = item.getJSONObject("metadata");
                if (!ids.add(id(meta.getString("id")))) throw new IOException();
                String content = item.getString("content"); total += content.getBytes(StandardCharsets.UTF_8).length;
                if (total > 4*1024*1024) throw new IOException();
                result.put(downloaded(meta,content));
            }
            return result;
        }
        JSONArray metadata = request("/portal/v2/profiles", null).getJSONArray("profiles");
        if (metadata.length() > 64) throw new IOException();
        JSONObject routing = legacyRouting(); requireSupportedRouting(routing);
        java.util.HashSet<String> ids = new java.util.HashSet<>(); int total = 0;
        for (int i = 0; i < metadata.length(); i++) {
            JSONObject meta = metadata.getJSONObject(i);
            String remoteId = id(meta.getString("id")), revision = meta.getString("revision");
            if (!ids.add(remoteId)) throw new IOException();
            JSONObject exported = request("/portal/v2/profiles/" + remoteId + "/export", new JSONObject()
                .put("format", "profile_json").put("revision", revision).put("include_secrets", true).put("accept_losses", false));
            String content = exported.getString("content"); total += content.getBytes(StandardCharsets.UTF_8).length;
            if (total > 4*1024*1024) throw new IOException();
            result.put(downloaded(meta,content));
        }
        if (!metadata.toString().equals(request("/portal/v2/profiles",null).getJSONArray("profiles").toString())
            || !routing.toString().equals(legacyRouting().toString())) throw new IOException();
        return result;
    }
    private JSONObject legacyRouting() throws Exception {
        try { return request("/portal/v2/routing",null); }
        catch (Failure failure) { if (failure.status != 404) throw failure; return new JSONObject().put("unsupported",true); }
    }
    private static void requireSupportedRouting(JSONObject routing) throws Exception {
        // Device-group routes are not implemented by the mobile adapter yet.
        // Reject the complete batch instead of silently downloading profiles
        // that would bypass the server-assigned routing policy.
        if (!routing.optBoolean("unsupported") && (!routing.has("policy") || !routing.isNull("policy"))) throw new IOException();
    }
    private static JSONObject downloaded(JSONObject meta, String content) throws Exception {
        String remoteId = id(meta.getString("id")), revision = meta.getString("revision");
        if (revision.isEmpty() || revision.length() > 256 || content.getBytes(StandardCharsets.UTF_8).length > 1024*1024) throw new IOException();
        JSONObject parsed = new JSONObject(NativeCore.INSTANCE.parse(content));
        if (!parsed.getBoolean("ok")) throw new IOException();
        return new JSONObject().put("id", "portal:" + remoteId).put("remote_id", remoteId).put("revision", revision).put("profile",parsed.getJSONObject("profile"));
    }
    static final class Failure extends IOException {
        final int status;
        Failure(int status) { super("Portal request failed"); this.status = status; }
    }
}
