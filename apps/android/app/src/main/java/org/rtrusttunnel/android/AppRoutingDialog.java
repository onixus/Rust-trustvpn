package org.rtrusttunnel.android;

import android.app.*;
import android.content.pm.*;
import android.text.*;
import android.view.*;
import android.widget.*;
import java.util.*;
import org.json.*;

final class AppRoutingDialog {
    private static final class App {
        final String name, label;
        App(String name, String label) { this.name = name; this.label = label; }
        @Override public String toString() { return label + "\n" + name; }
    }
    static void show(Activity activity, ProfileVault vault, Runnable saved) throws Exception {
        AppRouting current = AppRouting.read(vault.read());
        Set<String> selected = new TreeSet<>(current.packages);
        List<App> apps = new ArrayList<>(); Set<String> known = new HashSet<>();
        PackageManager pm = activity.getPackageManager();
        for (ApplicationInfo info : pm.getInstalledApplications(0)) {
            if (info.packageName.equals(activity.getPackageName())) continue;
            if (pm.checkPermission("android.permission.INTERNET", info.packageName) != PackageManager.PERMISSION_GRANTED && !selected.contains(info.packageName)) continue;
            apps.add(new App(info.packageName, info.loadLabel(pm).toString())); known.add(info.packageName);
        }
        for (String name : selected) if (!known.contains(name)) apps.add(new App(name, "Unavailable app"));
        apps.sort(Comparator.comparing((App app) -> !selected.contains(app.name)).thenComparing(app -> app.label, String.CASE_INSENSITIVE_ORDER).thenComparing(app -> app.name));
        LinearLayout panel = new LinearLayout(activity); panel.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * activity.getResources().getDisplayMetrics().density); panel.setPadding(pad, 0, pad, 0);
        RadioGroup modes = new RadioGroup(activity);
        RadioButton all = new RadioButton(activity); all.setId(View.generateViewId()); all.setText("All apps"); modes.addView(all);
        RadioButton only = new RadioButton(activity); only.setId(View.generateViewId()); only.setText("Only selected apps"); modes.addView(only);
        modes.check(current.selectedOnly ? only.getId() : all.getId()); panel.addView(modes);
        TextView hint = new TextView(activity); hint.setText("Unselected apps connect directly. Disconnect VPN before saving changes."); panel.addView(hint);
        EditText search = new EditText(activity); search.setSingleLine(true); search.setHint("Search apps"); panel.addView(search);
        search.setImeOptions(android.view.inputmethod.EditorInfo.IME_ACTION_DONE);
        Runnable hideKeyboard = () -> {
            android.view.inputmethod.InputMethodManager keyboard = activity.getSystemService(android.view.inputmethod.InputMethodManager.class);
            if (keyboard != null) keyboard.hideSoftInputFromWindow(search.getWindowToken(), 0);
            search.clearFocus();
        };
        search.setOnEditorActionListener((view, action, event) -> {
            if (action != android.view.inputmethod.EditorInfo.IME_ACTION_DONE) return false;
            hideKeyboard.run(); return true;
        });
        TextView count = new TextView(activity); panel.addView(count);
        ListView list = new ListView(activity); list.setChoiceMode(ListView.CHOICE_MODE_MULTIPLE);
        int height = Math.min((int) (320 * activity.getResources().getDisplayMetrics().density), activity.getResources().getDisplayMetrics().heightPixels / 3);
        panel.addView(list, new LinearLayout.LayoutParams(-1, height));
        List<App> visible = new ArrayList<>();
        ArrayAdapter<App> adapter = new ArrayAdapter<>(activity, android.R.layout.simple_list_item_multiple_choice, visible); list.setAdapter(adapter);
        Runnable render = () -> {
            String query = search.getText().toString().trim().toLowerCase(Locale.ROOT);
            visible.clear(); for (App app : apps) if (app.toString().toLowerCase(Locale.ROOT).contains(query)) visible.add(app);
            adapter.notifyDataSetChanged(); list.clearChoices();
            for (int i = 0; i < visible.size(); i++) list.setItemChecked(i, selected.contains(visible.get(i).name));
            boolean enabled = modes.getCheckedRadioButtonId() == only.getId();
            list.setEnabled(enabled); list.setAlpha(enabled ? 1f : .45f); search.setEnabled(enabled);
            count.setText(selected.size() + " selected");
        };
        list.setOnItemClickListener((parent, view, position, id) -> {
            String name = visible.get(position).name;
            if (list.isItemChecked(position)) selected.add(name); else selected.remove(name);
            count.setText(selected.size() + " selected");
            hint.setText("Unselected apps connect directly. Disconnect VPN before saving changes.");
            hideKeyboard.run();
        });
        modes.setOnCheckedChangeListener((group, id) -> render.run());
        search.addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            public void onTextChanged(CharSequence s, int start, int before, int count) { render.run(); }
            public void afterTextChanged(Editable value) {}
        });
        AlertDialog dialog = new AlertDialog.Builder(activity).setTitle("Apps using VPN").setView(panel).setNegativeButton("Cancel", null).setPositiveButton("Save", null).create();
        dialog.setOnShowListener(d -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            if (TunnelService.active) { hint.setText("Disconnect VPN before saving changes. Your current selection has not changed."); return; }
            try {
                AppRouting next = new AppRouting(modes.getCheckedRadioButtonId() == only.getId(), selected);
                next.validateInstalled(pm);
                vault.saveAppRouting(next); saved.run(); dialog.dismiss();
            } catch (PackageManager.NameNotFoundException error) { hint.setText("A selected app is no longer installed. Uncheck it before saving."); }
            catch (IllegalArgumentException error) { hint.setText("Select at least one installed app, or choose All apps."); }
            catch (Exception error) { hint.setText("Could not save app selection. Existing settings are preserved."); }
        }));
        render.run(); dialog.show();
    }
}
