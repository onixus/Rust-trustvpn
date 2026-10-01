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
    JSONObject selected() throws Exception {
        JSONObject data = read(); JSONArray profiles = data.getJSONArray("profiles");
        for (int i = 0; i < profiles.length(); i++) {
            JSONObject item = profiles.getJSONObject(i);
            if (item.getString("id").equals(data.getString("default"))) return item.getJSONObject("profile");
        }
        throw new IOException("Choose a default profile");
    }
}
