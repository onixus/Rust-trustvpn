package org.rtrusttunnel.android;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.AtomicFile;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import org.json.*;

/** Device-local authenticated encryption. Never falls back to plaintext or resets corrupt data. */
final class ProfileVault {
    private static final Object LOCK = new Object();
    private static final String ALIAS = "rtrust.profiles.v1";
    private final AtomicFile file;
    ProfileVault(Context context) { file = new AtomicFile(new File(context.getNoBackupFilesDir(), "profiles.enc")); }
    private static SecretKey key(boolean create) throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore"); store.load(null);
        if (!store.containsAlias(ALIAS)) {
            if (!create) throw new IOException("Profile key unavailable");
            KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            generator.init(new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setKeySize(256).build());
            generator.generateKey();
        }
        return (SecretKey) store.getKey(ALIAS, null);
    }
    static byte[] readBounded(InputStream in, int limit) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(); byte[] block = new byte[8192];
        for (int n; (n = in.read(block)) != -1;) {
            if (out.size() + n > limit) throw new IOException("Input exceeds size limit");
            out.write(block, 0, n);
        }
        Arrays.fill(block, (byte) 0); return out.toByteArray();
    }
    JSONObject read() throws Exception { synchronized (LOCK) { return readUnlocked(); } }
    private JSONObject readUnlocked() throws Exception {
        byte[] bytes;
        try (InputStream in = file.openRead()) { bytes = readBounded(in, 8 * 1024 * 1024); }
        catch (FileNotFoundException absent) { if (file.getBaseFile().exists()) throw absent; return new JSONObject().put("profiles", new JSONArray()).put("default", ""); }
        if (bytes.length < 29 || bytes.length > 8 * 1024 * 1024 || bytes[0] != 1) throw new IOException("Invalid encrypted vault");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key(false), new GCMParameterSpec(128, bytes, 1, 12));
        cipher.updateAAD(ALIAS.getBytes(StandardCharsets.UTF_8));
        byte[] plain = cipher.doFinal(bytes, 13, bytes.length - 13);
        try { return new JSONObject(new String(plain, StandardCharsets.UTF_8)); }
        finally { Arrays.fill(plain, (byte) 0); Arrays.fill(bytes, (byte) 0); }
    }
    void write(JSONObject data) throws Exception { synchronized (LOCK) { writeUnlocked(data); } }
    interface Edit { void apply(JSONObject data) throws Exception; }
    void edit(Edit edit) throws Exception { synchronized (LOCK) {
        JSONObject data = readUnlocked(); edit.apply(data); writeUnlocked(data);
    } }
    private void writeUnlocked(JSONObject data) throws Exception {
        byte[] plain = data.toString().getBytes(StandardCharsets.UTF_8);
        if (plain.length > 8 * 1024 * 1024 - 64) throw new IOException("Profile storage limit reached");
        FileOutputStream out = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.ENCRYPT_MODE, key(true));
            cipher.updateAAD(ALIAS.getBytes(StandardCharsets.UTF_8));
            byte[] encrypted = cipher.doFinal(plain);
            out = file.startWrite(); out.write(1); out.write(cipher.getIV()); out.write(encrypted);
            file.finishWrite(out); out = null;
        } finally { if (out != null) file.failWrite(out); Arrays.fill(plain, (byte) 0); }
    }
    void saveAppRouting(AppRouting routing) throws Exception { synchronized (LOCK) {
        JSONObject data = readUnlocked(); data.put("app_routing", routing.json()); writeUnlocked(data);
    } }
    void savePortal(JSONObject session) throws Exception { synchronized (LOCK) {
        JSONObject data = readUnlocked();
        if (data.has("portal")) throw new IOException("Already enrolled");
        data.put("portal", session); writeUnlocked(data);
    } }
    void setPortalSync(boolean enabled) throws Exception { synchronized (LOCK) {
        JSONObject data = readUnlocked(), session = data.getJSONObject("portal");
        session.put("background_sync", enabled).remove("sync_auth_expired"); writeUnlocked(data);
    } }
    void renewPortalAccess(JSONObject session,long expiresAt) throws Exception { synchronized (LOCK) {
        JSONObject data=readUnlocked(), current=data.optJSONObject("portal");
        if (!PortalClient.samePortal(current,session) || current.optLong("expires_at")!=session.optLong("expires_at")) throw new IOException("Registration changed");
        current.put("expires_at",expiresAt).remove("sync_auth_expired"); writeUnlocked(data);
    } }
    void expirePortalSync(JSONObject session) throws Exception { synchronized (LOCK) {
        JSONObject data = readUnlocked(), current = data.optJSONObject("portal");
        if (!PortalClient.samePortal(current, session)) return;
        JSONArray entries=data.getJSONArray("profiles");
        for(int i=0;i<entries.length();i++){JSONObject entry=entries.getJSONObject(i);if(entry.has("remote_id"))entry.remove("access_lease");}
        current.put("background_sync", false).put("sync_auth_expired", true); writeUnlocked(data);
    } }
    void syncPortalBackground(JSONObject session, JSONArray remote) throws Exception { synchronized (LOCK) {
        JSONObject data = readUnlocked();
        // A canceled, expired or replaced registration cannot commit an in-flight response.
        if (PortalClient.applyBatch(data, session, remote, true, System.currentTimeMillis())) writeUnlocked(data);
    } }
    void forgetPortal() throws Exception { synchronized (LOCK) {
        JSONObject data = readUnlocked(); removeRemote(data); data.remove("portal"); writeUnlocked(data);
    } }
    private static void removeRemote(JSONObject data) throws Exception {
        JSONArray old = data.getJSONArray("profiles"), kept = new JSONArray();
        for (int i = 0; i < old.length(); i++) if (!old.getJSONObject(i).has("remote_id")) kept.put(old.get(i));
        data.put("profiles", kept); repairDefault(data);
    }
    private static void repairDefault(JSONObject data) throws Exception {
        JSONArray profiles = data.getJSONArray("profiles");
        for (int i = 0; i < profiles.length(); i++) if (profiles.getJSONObject(i).getString("id").equals(data.getString("default"))) return;
        data.put("default", profiles.length() == 0 ? "" : profiles.getJSONObject(0).getString("id"));
    }
    void syncPortal(JSONObject session, JSONArray remote) throws Exception { synchronized (LOCK) {
        JSONObject data = readUnlocked();
        PortalClient.applyBatch(data, session, remote, false, System.currentTimeMillis());
        writeUnlocked(data);
    } }
    void pendingExport(String content) throws Exception { synchronized (LOCK) {
        JSONObject data = readUnlocked();
        data.put("pending_export", new JSONObject().put("content", content).put("created", System.currentTimeMillis())); writeUnlocked(data);
    } }
    String takeExport() throws Exception { synchronized (LOCK) {
        JSONObject data = readUnlocked(), pending = data.optJSONObject("pending_export");
        data.remove("pending_export"); writeUnlocked(data);
        if (pending == null) return null;
        long age = System.currentTimeMillis() - pending.getLong("created");
        if (age < 0 || age > 3600000) return null;
        return pending.getString("content");
    } }
    static final class Selection {
        final String id;
        final String revision;
        final JSONObject profile;
        final boolean localPolicy;
        final JSONObject managedRouting;
        final JSONObject lease;
        Selection(JSONObject entry) throws Exception {
            id = entry.getString("id"); profile = entry.getJSONObject("profile");
            revision=entry.optString("revision","local");
            localPolicy = !entry.has("remote_id");
            managedRouting = entry.optJSONObject("managed_routing");
            lease=entry.optJSONObject("access_lease");
        }
    }
    static final class Admission {
        final Selection primary;
        final AppRouting apps;
        Admission(JSONObject data,String id)throws Exception {primary=resolveSelection(data,id);apps=AppRouting.read(data);}
    }
    Admission admission(String id)throws Exception {synchronized(LOCK){return new Admission(readUnlocked(),id);}}
    static final class ConnectionSet {
        final java.util.ArrayList<Selection> profiles=new java.util.ArrayList<>();
        final AppRouting apps;
        ConnectionSet(JSONObject data,String id) throws Exception {
            Selection primary=resolveSelection(data,id);profiles.add(primary);apps=AppRouting.read(data);
            JSONObject settings=data.optJSONObject("mobile_recovery");
            if(settings==null || !settings.getBoolean("enabled") || !primary.id.equals(settings.getString("primary"))) return;
            JSONArray ids=settings.getJSONArray("backups");
            if(ids.length()<1 || ids.length()>3) throw new IOException("Select 1 to 3 backups");
            java.util.HashSet<String> seen=new java.util.HashSet<>();seen.add(primary.id);
            for(int i=0;i<ids.length();i++) {
                String backupId=ids.getString(i);if(!seen.add(backupId)) throw new IOException("Duplicate backup");
                Selection backup=resolveSelection(data,backupId);
                if(backup.localPolicy!=primary.localPolicy || !java.util.Objects.equals(primary.managedRouting==null?null:primary.managedRouting.toString(),backup.managedRouting==null?null:backup.managedRouting.toString())) throw new IOException("Backup policy ownership differs");
                profiles.add(backup);
            }
        }
    }
    ConnectionSet connectionSet(String id) throws Exception {synchronized(LOCK){return new ConnectionSet(readUnlocked(),id);}}
    Selection selection(String requestedId) throws Exception { synchronized (LOCK) {
        return resolveSelection(readUnlocked(), requestedId);
    } }
    static Selection resolveSelection(JSONObject data, String requestedId) throws Exception {
        String id = requestedId == null ? data.getString("default") : requestedId;
        if (id.isEmpty()) throw new IOException("Select a profile first");
        JSONArray profiles = data.getJSONArray("profiles");
        for (int i = 0; i < profiles.length(); i++) {
            JSONObject item = profiles.getJSONObject(i);
            if (item.getString("id").equals(id)) return new Selection(item);
        }
        throw new IOException("Selected profile no longer exists");
    }
    JSONObject selected() throws Exception { return selection(null).profile; }
    JSONObject profile(String id) throws Exception { return resolveProfile(read(), id); }
    static JSONObject resolveProfile(JSONObject data, String id) throws Exception {
        if (id == null || id.isEmpty()) throw new IOException("Select a profile first");
        return resolveSelection(data, id).profile;
    }
}
