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
        for (String name : selected) if (!known.contains(name)) apps.add(new App(name, activity.getString(R.string.unavailable_app)));
        apps.sort(Comparator.comparing((App app) -> !selected.contains(app.name)).thenComparing(app -> app.label, String.CASE_INSENSITIVE_ORDER).thenComparing(app -> app.name));
        LinearLayout panel = new LinearLayout(activity); panel.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * activity.getResources().getDisplayMetrics().density); panel.setPadding(pad, 0, pad, 0);
        RadioGroup modes = new RadioGroup(activity);
        RadioButton all = new RadioButton(activity); all.setId(View.generateViewId()); all.setText(activity.getString(R.string.all_apps)); modes.addView(all);
        RadioButton only = new RadioButton(activity); only.setId(View.generateViewId()); only.setText(activity.getString(R.string.only_selected_apps)); modes.addView(only);
        modes.check(current.selectedOnly ? only.getId() : all.getId()); panel.addView(modes);
        TextView hint = new TextView(activity); hint.setText(activity.getString(R.string.unselected_apps_connect_directly_or_have)); panel.addView(hint);
        EditText search = new EditText(activity); search.setSingleLine(true); search.setHint(activity.getString(R.string.search_apps)); panel.addView(search);
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
            count.setText(activity.getString(R.string.selected_count, selected.size()));
        };
        list.setOnItemClickListener((parent, view, position, id) -> {
            String name = visible.get(position).name;
            if (list.isItemChecked(position)) selected.add(name); else selected.remove(name);
            count.setText(activity.getString(R.string.selected_count, selected.size()));
            hint.setText(activity.getString(R.string.unselected_apps_connect_directly_or_have));
            hideKeyboard.run();
        });
        modes.setOnCheckedChangeListener((group, id) -> render.run());
        search.addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            public void onTextChanged(CharSequence s, int start, int before, int count) { render.run(); }
            public void afterTextChanged(Editable value) {}
        });
        AlertDialog dialog = new AlertDialog.Builder(activity).setTitle(activity.getString(R.string.apps_using_vpn)).setView(panel).setNegativeButton(activity.getString(R.string.cancel), null).setPositiveButton(activity.getString(R.string.save), null).create();
        dialog.setOnShowListener(d -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            if (TunnelService.active) { hint.setText(activity.getString(R.string.disconnect_vpn_before_saving_changes_your)); return; }
            try {
                AppRouting next = new AppRouting(modes.getCheckedRadioButtonId() == only.getId(), selected);
                next.validateInstalled(pm);
                vault.saveAppRouting(next); saved.run(); dialog.dismiss();
            } catch (PackageManager.NameNotFoundException error) { hint.setText(activity.getString(R.string.a_selected_app_is_no_longer)); }
            catch (IllegalArgumentException error) { hint.setText(activity.getString(R.string.select_at_least_one_installed_app)); }
            catch (Exception error) { hint.setText(activity.getString(R.string.could_not_save_app_selection_existing)); }
        }));
        render.run(); dialog.show();
    }
}
