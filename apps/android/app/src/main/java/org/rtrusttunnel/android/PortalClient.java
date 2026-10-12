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
            if (code == 409) throw Failure.conflict(conflictBody(connection));
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
    /** Same policy as iOS: 1..80 printable ASCII (0x20-0x7E); compared code unit by code unit. */
    static boolean originLabel(String value) {
        if (value.isEmpty() || value.length() > 80) return false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 0x20 || c > 0x7E) return false;
        }
        return true;
    }
    /**
     * Validates a profile metadata list (legacy list or snapshot metadata) into an
     * order-independent id -> (revision, origin) map. Duplicates, malformed revisions and
     * origins reject the whole batch before any export is requested or applied.
     */
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
                if (!originLabel(profileOrigin)) throw new IOException("Invalid profile metadata");
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
    /** Cooperative stop signal; WorkManager stops a Worker without interrupting its thread. */
    interface Cancellation { boolean cancelled(); }
    static final Cancellation NEVER = () -> false;
    static void checkCancelled(Cancellation cancellation) throws java.io.InterruptedIOException {
        if (Thread.currentThread().isInterrupted() || cancellation.cancelled())
            throw new java.io.InterruptedIOException("Synchronization cancelled");
    }
    JSONArray download() throws Exception { return download(NEVER); }
    JSONArray download(Cancellation cancellation) throws Exception {
        checkCancelled(cancellation);
        issuedWall=System.currentTimeMillis();issuedElapsed=android.os.SystemClock.elapsedRealtime();lease=null;
        batchDeadline=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(30);
        try {
            JSONArray result = downloadBatch(cancellation);
            checkCancelled(cancellation);
            return result;
        } finally { batchDeadline=0; }
    }
    private JSONArray downloadBatch(Cancellation cancellation) throws Exception {
        JSONObject capabilities = request("/portal/v2/capabilities",null);
        if (capabilities.getInt("version") != 2 || capabilities.has("routing") && capabilities.getInt("routing") != 1
            || capabilities.has("snapshot") && capabilities.getInt("snapshot") != 1) throw new IOException();
        JSONArray result = new JSONArray();
        if (context!=null && capabilities.optInt("offline_freshness")!=1) throw new IOException("Panel freshness contract required");
        checkCancelled(cancellation);
        if (capabilities.optInt("snapshot") == 1) {
            JSONObject consent=new JSONObject().put("include_secrets",true);
            if(context!=null) consent.put("freshness_version",1);
            JSONObject batch = request("/portal/v2/snapshot",consent);
            if(context!=null) lease=OfflineLease.issue(context,batch.getJSONObject("freshness"),issuedWall,issuedElapsed);
            if (batch.getInt("version") != 1 || !batch.getString("revision").matches("[0-9a-f]{64}")) throw new IOException();
            JSONObject routing=batch.getJSONObject("routing"); requireSupportedRouting(routing);
            JSONArray items = batch.getJSONArray("profiles");
            if (items.length() > 64) throw new IOException();
            // The snapshot is one server transaction: validate all metadata (ids, duplicates,
            // revisions, origin labels) before parsing any profile content.
            JSONArray metas = new JSONArray();
            for (int i=0; i<items.length(); i++) metas.put(items.getJSONObject(i).getJSONObject("metadata"));
            metadata(metas);
            int total = 0;
            for (int i=0; i<items.length(); i++) {
                checkCancelled(cancellation);
                JSONObject item = items.getJSONObject(i), meta = item.getJSONObject("metadata");
                String content = item.getString("content"); total += content.getBytes(StandardCharsets.UTF_8).length;
                if (total > 4*1024*1024) throw new IOException();
                result.put(downloaded(meta,content,routing));
            }
            return result;
        }
        // Legacy panel without snapshots: list, export each revision, list again; any change in
        // the id -> (revision, origin) map (order-independent) or routing rejects the batch.
        java.util.Map<String, java.util.List<String>> before = metadata(request("/portal/v2/profiles", null).getJSONArray("profiles"));
        checkCancelled(cancellation);
        JSONObject routing = legacyRouting(); requireSupportedRouting(routing);
        int total = 0;
        for (java.util.Map.Entry<String, java.util.List<String>> entry : before.entrySet()) {
            checkCancelled(cancellation);
            String remoteId = entry.getKey(), revision = entry.getValue().get(0);
            JSONObject exported = request("/portal/v2/profiles/" + remoteId + "/export", new JSONObject()
                .put("format", "profile_json").put("revision", revision).put("include_secrets", true).put("accept_losses", false));
            String content = exported.getString("content"); total += content.getBytes(StandardCharsets.UTF_8).length;
            if (total > 4*1024*1024) throw new IOException();
            result.put(downloaded(new JSONObject().put("id", remoteId).put("revision", revision),content,routing));
        }
        checkCancelled(cancellation);
        if (!before.equals(metadata(request("/portal/v2/profiles",null).getJSONArray("profiles"))))
            throw new IOException("Profile list changed during synchronization");
        checkCancelled(cancellation);
        if (!routing.toString().equals(legacyRouting().toString())) throw new IOException("Routing changed during synchronization");
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
        JSONObject profile=parseExport(content), group=routing.optJSONObject("policy");
        if (group!=null && !new JSONObject(NativeCore.INSTANCE.planManaged(profile.toString(),group.toString())).getBoolean("ok")) throw new IOException();
        JSONObject result=new JSONObject().put("id", "portal:" + remoteId).put("remote_id", remoteId).put("revision", revision).put("profile",profile);
        if (group!=null) result.put("managed_routing",group);
        if(lease!=null) result.put("access_lease",new JSONObject(lease.toString()));
        if (routing.optBoolean("unsupported")) result.put("routing_unsupported",true);
        return result;
    }
    static boolean samePortal(JSONObject a, JSONObject b) {
        return a != null && a.optString("origin").equals(b.optString("origin"))
            && !a.optString("token").isEmpty() && a.optString("token").equals(b.optString("token"));
    }
    /**
     * Pure vault commit step used by ProfileVault under its lock. Replaces every managed
     * ({@code remote_id}) profile with {@code remote}, keeps local profiles and the selection when
     * it still exists. All checks run before {@code data} is touched, so a rejected batch leaves it
     * unchanged. A changed registration throws for a foreground sync and returns false (no write)
     * for a background sync, which also requires background sync to still be enabled. Managed
     * routing/revision conflicts reject the batch for both.
     */
    static boolean applyBatch(JSONObject data, JSONObject session, JSONArray remote, boolean background, long now) throws Exception {
        JSONObject current = data.optJSONObject("portal");
        if (!samePortal(current, session)) {
            if (background) return false;
            throw new IOException("Registration changed");
        }
        if (background && !current.optBoolean("background_sync")) return false;
        JSONArray old = data.getJSONArray("profiles");
        for (int i = 0; i < remote.length(); i++) {
            JSONObject next = remote.getJSONObject(i), group = next.optJSONObject("managed_routing");
            for (int j = 0; j < old.length(); j++) {
                JSONObject previous = old.getJSONObject(j), priorGroup = previous.optJSONObject("managed_routing");
                if (priorGroup != null && next.optBoolean("routing_unsupported")) throw new IOException("Assigned routing capability disappeared");
                if (priorGroup != null && group != null && priorGroup.getString("revision").equals(group.getString("revision"))
                    && !priorGroup.toString().equals(group.toString())) throw new IOException("Managed group revision conflict");
                if (next.getString("id").equals(previous.getString("id")) && next.getString("revision").equals(previous.optString("revision"))
                    && !next.getJSONObject("profile").toString().equals(previous.getJSONObject("profile").toString())) throw new IOException("Profile revision conflict");
            }
        }
        String selected = data.getString("default");
        JSONArray profiles = new JSONArray();
        for (int i = 0; i < old.length(); i++) if (!old.getJSONObject(i).has("remote_id")) profiles.put(old.get(i));
        if (profiles.length() + remote.length() > 64) throw new IOException("Profile limit");
        java.util.HashSet<String> ids = new java.util.HashSet<>();
        for (int i = 0; i < remote.length(); i++) {
            JSONObject item = remote.getJSONObject(i);
            if (!ids.add(item.getString("id"))) throw new IOException("Duplicate remote profile");
            profiles.put(item);
        }
        String repaired = profiles.length() == 0 ? "" : profiles.getJSONObject(0).getString("id");
        for (int i = 0; i < profiles.length(); i++)
            if (profiles.getJSONObject(i).getString("id").equals(selected)) { repaired = selected; break; }
        data.put("profiles", profiles).put("default", repaired);
        current.put("last_sync", now).remove("sync_auth_expired");
        return true;
    }
    /** Reads at most 512 bytes of a 409 body for classification only; never logged or shown. */
    static byte[] conflictBody(HttpsURLConnection connection) {
        try (InputStream in = connection.getErrorStream()) {
            if (in == null) return new byte[0];
            byte[] body = new byte[512]; int size = 0;
            for (int n; size < body.length && (n = in.read(body, size, body.length - size)) != -1;) size += n;
            if (in.read() != -1) return new byte[0];
            return java.util.Arrays.copyOf(body, size);
        } catch (Exception ignored) { return new byte[0]; }
    }
    static final class Failure extends IOException {
        static final int SYNC_LIMIT = 1, DEVICE_LIMIT = 2;
        final int status, conflict;
        Failure(int status) { this(status, 0); }
        private Failure(int status, int conflict) { super("Portal request failed"); this.status = status; this.conflict = conflict; }
        /** Only the server's exact limit details are recognised; other 409s stay revision conflicts. */
        static Failure conflict(byte[] body) {
            String detail = null;
            try { detail = new JSONObject(new String(body, StandardCharsets.UTF_8)).optString("detail", null); } catch (Exception ignored) {}
            if ("Too many profiles for client sync".equals(detail)) return new Failure(409, SYNC_LIMIT);
            if ("Device profile limit reached (64)".equals(detail)) return new Failure(409, DEVICE_LIMIT);
            return new Failure(409, 0);
        }
    }
}
