package org.rtrusttunnel.android;

import android.app.*;
import android.os.Build;
import android.text.InputType;
import android.widget.*;
import org.json.*;

final class PortalDialog {
    interface Task { void run() throws Exception; }
    final Activity activity;
    final ProfileVault vault;
    final Runnable saved;
    PortalDialog(Activity activity, ProfileVault vault, Runnable saved) { this.activity = activity; this.vault = vault; this.saved = saved; }
    void error(String message) { if (!activity.isDestroyed()) new AlertDialog.Builder(activity).setMessage(message).setPositiveButton(android.R.string.ok, null).show(); }
    void background(Task task) {
        ProgressDialog progress = new ProgressDialog(activity); progress.setMessage(activity.getString(R.string.portal_working)); progress.setCancelable(false); progress.show();
        new Thread(() -> {
            try { task.run(); }
            catch (Exception e) { activity.runOnUiThread(() -> error(activity.getString(e instanceof PortalClient.Failure && ((PortalClient.Failure)e).status == 401 ? R.string.portal_expired : R.string.portal_failed))); }
            finally { activity.runOnUiThread(() -> { if (!activity.isDestroyed()) progress.dismiss(); }); }
        }, "portal").start();
    }
    void show() {
        try {
            JSONObject session = vault.read().optJSONObject("portal");
            if (session == null) { enroll(); return; }
            new AlertDialog.Builder(activity).setTitle(session.getString("origin"))
                .setItems(new String[]{activity.getString(R.string.portal_sync), activity.getString(R.string.portal_upload), activity.getString(R.string.portal_forget), activity.getString(R.string.portal_background)}, (d, choice) -> {
                    if (choice == 0) sync(session);
                    if (choice == 1) upload(session);
                    if (choice == 2) new AlertDialog.Builder(activity).setMessage(R.string.portal_forget_warning).setNegativeButton(android.R.string.cancel, null)
                        .setPositiveButton(R.string.portal_forget, (a,b) -> { try { if (TunnelService.active) throw new IllegalStateException(); vault.forgetPortal(); PortalSyncWorker.schedule(activity); saved.run(); } catch (Exception e) { error(activity.getString(R.string.portal_disconnect)); } }).show();
                    if (choice == 3) backgroundSettings(session);
                }).show();
        } catch (Exception e) { error(activity.getString(R.string.portal_failed)); }
    }
    void backgroundSettings(JSONObject session) {
        boolean enabled = session.optBoolean("background_sync");
        String details = activity.getString(R.string.portal_background_help);
        if (session.optBoolean("sync_auth_expired")) details += "\n\n" + activity.getString(R.string.portal_expired);
        if (session.optLong("last_sync") > 0) details += "\n\n" + activity.getString(R.string.portal_last_sync,
            java.text.DateFormat.getDateTimeInstance().format(new java.util.Date(session.optLong("last_sync"))));
        new AlertDialog.Builder(activity).setTitle(R.string.portal_background).setMessage(details)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(enabled ? R.string.portal_background_disable : R.string.portal_background_enable, (d,w) -> {
                try { vault.setPortalSync(!enabled); PortalSyncWorker.schedule(activity); saved.run(); }
                catch (Exception error) { error(activity.getString(R.string.portal_failed)); }
            }).show();
    }
    void enroll() {
        LinearLayout panel = new LinearLayout(activity); panel.setOrientation(LinearLayout.VERTICAL);
        EditText url = new EditText(activity); url.setHint("https://vpn.example.com"); url.setSingleLine(true); url.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI); panel.addView(url);
        EditText code = new EditText(activity); code.setHint(R.string.portal_code); code.setSingleLine(true); code.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD); code.setImportantForAutofill(android.view.View.IMPORTANT_FOR_AUTOFILL_NO); panel.addView(code);
        EditText name = new EditText(activity); name.setText(Build.MODEL); name.setSingleLine(true); name.setFilters(new android.text.InputFilter[]{new android.text.InputFilter.LengthFilter(80)}); panel.addView(name);
        new AlertDialog.Builder(activity).setTitle(R.string.portal_register).setMessage(R.string.portal_enroll_help).setView(panel).setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.portal_register, (d,w) -> {
                String origin = url.getText().toString(), secret = code.getText().toString().trim(), label = name.getText().toString().trim(); code.setText("");
                background(() -> {
                    JSONObject session = new PortalClient(origin, "").enroll(secret, label);
                    // Serialize with UI profile edits, including a recreated Activity.
                    activity.runOnUiThread(() -> {
                        try { vault.savePortal(session); error(activity.getString(R.string.portal_enrolled)); }
                        catch (Exception e) { error(activity.getString(R.string.portal_failed)); }
                    });
                });
            }).show();
    }
    PortalClient client(JSONObject session) throws Exception { return new PortalClient(session.getString("origin"), session.getString("token")); }
    void sync(JSONObject session) {
        if (TunnelService.active) { error(activity.getString(R.string.portal_disconnect)); return; }
        new AlertDialog.Builder(activity).setMessage(R.string.portal_sync_warning).setNegativeButton(android.R.string.cancel, null).setPositiveButton(R.string.portal_sync, (d,w) -> background(() -> {
            final int count;
            synchronized (PortalSyncWorker.SYNC) {
                JSONArray profiles = client(session).download();
                vault.syncPortal(session, profiles); count = profiles.length();
            }
            activity.runOnUiThread(() -> {
                if (!activity.isDestroyed()) { saved.run(); error(activity.getString(R.string.portal_synced, count)); }
            });
        })).show();
    }
    void upload(JSONObject session) {
        try {
            JSONArray profiles = vault.read().getJSONArray("profiles"); String[] names = new String[profiles.length()];
            for (int i = 0; i < names.length; i++) names[i] = profiles.getJSONObject(i).getJSONObject("profile").optString("name", "Profile");
            new AlertDialog.Builder(activity).setTitle(R.string.portal_upload).setItems(names, (d,index) -> {
                new AlertDialog.Builder(activity).setMessage(R.string.portal_upload_warning).setNegativeButton(android.R.string.cancel, null).setPositiveButton(R.string.portal_upload, (a,b) -> background(() -> {
                    PortalClient client = client(session);
                    JSONObject preview = client.request("/portal/v2/profile-imports/preview", new JSONObject().put("intent", "external_stored").put("content", profiles.getJSONObject(index).getJSONObject("profile").toString()));
                    client.request("/portal/v2/profile-imports/" + PortalClient.id(preview.getString("preview_id")) + "/commit", new JSONObject().put("action", "create").put("consent", true));
                    activity.runOnUiThread(() -> error(activity.getString(R.string.portal_uploaded)));
                })).show();
            }).show();
        } catch (Exception e) { error(activity.getString(R.string.portal_failed)); }
    }
}
