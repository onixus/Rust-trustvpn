package org.rtrusttunnel.android;

import android.content.pm.PackageManager;
import android.net.VpnService;
import java.util.*;
import org.json.*;

/** Device-local allowlist, deliberately excluded from portable server profiles. */
final class AppRouting {
    final boolean selectedOnly;
    final List<String> packages;
    AppRouting(boolean selectedOnly, Collection<String> packages) {
        TreeSet<String> unique = new TreeSet<>(packages);
        if (unique.size() > 1024) throw new IllegalArgumentException("Too many apps");
        for (String name : unique) if (!name.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)*")) throw new IllegalArgumentException("Invalid app");
        if (selectedOnly && unique.isEmpty()) throw new IllegalArgumentException("Select at least one app");
        this.selectedOnly = selectedOnly; this.packages = Collections.unmodifiableList(new ArrayList<>(unique));
    }
    static AppRouting read(JSONObject vault) throws JSONException {
        if (!vault.has("app_routing")) return new AppRouting(false, Collections.emptyList());
        JSONObject value = vault.getJSONObject("app_routing");
        String mode = value.getString("mode");
        if (!mode.equals("all") && !mode.equals("selected")) throw new IllegalArgumentException("Invalid routing mode");
        JSONArray array = value.getJSONArray("packages"); List<String> packages = new ArrayList<>();
        for (int i = 0; i < array.length(); i++) {
            Object item = array.get(i);
            if (!(item instanceof String)) throw new IllegalArgumentException("Invalid app");
            packages.add((String) item);
        }
        return new AppRouting(mode.equals("selected"), packages);
    }
    JSONObject json() throws JSONException {
        return new JSONObject().put("mode", selectedOnly ? "selected" : "all").put("packages", new JSONArray(packages));
    }
    void validateInstalled(PackageManager manager) throws PackageManager.NameNotFoundException {
        if (selectedOnly) for (String name : packages) manager.getApplicationInfo(name, 0);
    }
    void apply(VpnService.Builder builder, PackageManager manager) throws PackageManager.NameNotFoundException {
        // Do not skip missing packages: an empty Android allowlist means ALL apps.
        validateInstalled(manager);
        if (selectedOnly) for (String name : packages) builder.addAllowedApplication(name);
    }
    String summary() { return selectedOnly ? "VPN apps · " + packages.size() + " selected" : "VPN apps · All apps"; }
}
