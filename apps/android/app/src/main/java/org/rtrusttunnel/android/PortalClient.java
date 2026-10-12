package org.rtrusttunnel.android;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import javax.net.ssl.HttpsURLConnection;
import org.json.*;

/** The same v2 one-time enrollment / revision contract as the server UI. */
class PortalClient {
    private android.content.Context context;
    private JSONObject lease;
    private long issuedWall,issuedElapsed;
    final String origin, token;
    private Long expiresAt;
    private long batchDeadline;
    private static final java.util.concurrent.ScheduledExecutorService DEADLINES=java.util.concurrent.Executors.newSingleThreadScheduledExecutor(task -> {
        Thread thread=new Thread(task,"portal-deadline"); thread.setDaemon(true); return thread;
    });
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
    PortalClient(android.content.Context context,JSONObject session) throws Exception {this(session);this.context=context.getApplicationContext();}
    static String id(String id) {
        if (!id.matches("[A-Za-z0-9_-]{1,80}")) throw new IllegalArgumentException("Invalid identifier");
        return id;
    }
    JSONObject request(String path, JSONObject body) throws Exception {
        if (expiresAt != null && System.currentTimeMillis()/1000 >= expiresAt) throw new Failure(401);
        if (!path.startsWith("/portal/v2/") || path.contains("..")) throw new IllegalArgumentException();
        long deadline=batchDeadline==0?System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(25):batchDeadline;
        long remaining=java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(deadline-System.nanoTime());
        if (remaining<=0) throw new IOException();
        android.net.Network control=context==null?null:TunnelService.portalRecoveryNetwork();
        HttpsURLConnection connection = (HttpsURLConnection)(control==null?new URL(origin+path).openConnection():control.openConnection(new URL(origin+path)));
        connection.setInstanceFollowRedirects(false); connection.setConnectTimeout((int)Math.min(15000,remaining)); connection.setReadTimeout((int)Math.min(20000,remaining));
        connection.setUseCaches(false); connection.setRequestProperty("Accept", "application/json");
        if (!token.isEmpty()) connection.setRequestProperty("Authorization", "Bearer " + token);
        java.util.concurrent.ScheduledFuture<?> cutoff=DEADLINES.schedule(connection::disconnect,remaining,java.util.concurrent.TimeUnit.MILLISECONDS);
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
                try {
                    if (System.nanoTime()>=deadline) throw new IOException();
                    return new JSONObject(new String(bytes, StandardCharsets.UTF_8));
                }
                finally { java.util.Arrays.fill(bytes, (byte) 0); }
            }
        } finally { cutoff.cancel(false); connection.disconnect(); }
    }
    JSONObject enroll(String code, String name) throws Exception {
        if (code.trim().startsWith("{")) code = invitation(code,origin).getString("code");
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
    static JSONObject invitation(String raw, String expectedOrigin) throws Exception {
        if (raw.length()>4096) throw new IOException();
        JSONObject value=new JSONObject(raw);
        long now=System.currentTimeMillis()/1000, expires=value.getLong("expires_at");
        if (value.length()!=5 || !value.getString("kind").equals("rtrust_enrollment") || value.getInt("version")!=1
            || !origin(value.getString("origin")).equals(origin(expectedOrigin)) || expires<=now || expires-now>300
            || !value.getString("code").matches("[A-Za-z0-9_-]{20,128}")) throw new IOException();
        return value;
    }
    long renewAccess() throws Exception {
        long requestedAt=System.currentTimeMillis()/1000;
        JSONObject result=request("/portal/v2/token/renew",new JSONObject().put("consent",true));
        long lifetime=result.getLong("expires_in");
        if (lifetime<=0 || lifetime>30*86400 || !result.getString("scope").equals("portal_access_only")) throw new IOException();
        long deadline=Math.addExact(requestedAt,lifetime);
        if (deadline<=System.currentTimeMillis()/1000) throw new Failure(401);
        return deadline;
    }
    JSONArray download() throws Exception {
        issuedWall=System.currentTimeMillis();issuedElapsed=android.os.SystemClock.elapsedRealtime();lease=null;
        batchDeadline=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(30);
        try { return downloadBatch(); } finally { batchDeadline=0; }
    }
    private JSONArray downloadBatch() throws Exception {
        JSONObject capabilities = request("/portal/v2/capabilities",null);
        if (capabilities.getInt("version") != 2 || capabilities.has("routing") && capabilities.getInt("routing") != 1
            || capabilities.has("snapshot") && capabilities.getInt("snapshot") != 1) throw new IOException();
        JSONArray result = new JSONArray();
        if (context!=null && capabilities.optInt("offline_freshness")!=1) throw new IOException("Panel freshness contract required");
        if (capabilities.optInt("snapshot") == 1) {
            JSONObject consent=new JSONObject().put("include_secrets",true);
            if(context!=null) consent.put("freshness_version",1);
            JSONObject batch = request("/portal/v2/snapshot",consent);
            if(context!=null) lease=OfflineLease.issue(context,batch.getJSONObject("freshness"),issuedWall,issuedElapsed);
            if (batch.getInt("version") != 1 || !batch.getString("revision").matches("[0-9a-f]{64}")) throw new IOException();
            JSONObject routing=batch.getJSONObject("routing"); requireSupportedRouting(routing);
            JSONArray items = batch.getJSONArray("profiles");
            if (items.length() > 64) throw new IOException();
            java.util.HashSet<String> ids = new java.util.HashSet<>(); int total = 0;
            for (int i=0; i<items.length(); i++) {
                JSONObject item = items.getJSONObject(i), meta = item.getJSONObject("metadata");
                if (!ids.add(id(meta.getString("id")))) throw new IOException();
                String content = item.getString("content"); total += content.getBytes(StandardCharsets.UTF_8).length;
                if (total > 4*1024*1024) throw new IOException();
                result.put(downloaded(meta,content,routing));
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
            result.put(downloaded(meta,content,routing));
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
        if (routing.optBoolean("unsupported")) return;
        if (!routing.has("policy")) throw new IOException();
        if (!routing.isNull("policy")) routing.getJSONObject("policy");
    }
    private JSONObject downloaded(JSONObject meta, String content, JSONObject routing) throws Exception {
        String remoteId = id(meta.getString("id")), revision = meta.getString("revision");
        if (revision.isEmpty() || revision.length() > 256 || content.getBytes(StandardCharsets.UTF_8).length > 1024*1024) throw new IOException();
        JSONObject parsed = new JSONObject(NativeCore.INSTANCE.parse(content));
        if (!parsed.getBoolean("ok")) throw new IOException();
        JSONObject profile=parsed.getJSONObject("profile"), group=routing.optJSONObject("policy");
        if (group!=null && !new JSONObject(NativeCore.INSTANCE.planManaged(profile.toString(),group.toString())).getBoolean("ok")) throw new IOException();
        JSONObject result=new JSONObject().put("id", "portal:" + remoteId).put("remote_id", remoteId).put("revision", revision).put("profile",profile);
        if (group!=null) result.put("managed_routing",group);
        if(lease!=null) result.put("access_lease",new JSONObject(lease.toString()));
        if (routing.optBoolean("unsupported")) result.put("routing_unsupported",true);
        return result;
    }
    static final class Failure extends IOException {
        final int status;
        Failure(int status) { super("Portal request failed"); this.status = status; }
    }
}
