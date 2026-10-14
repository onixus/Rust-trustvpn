package org.rtrusttunnel.android;

import android.app.Activity;
import android.app.Dialog;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.os.Build;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowInsets;
import android.view.WindowManager;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/**
 * App-styled bottom sheet for choices and actions. Replaces system list dialogs
 * and PopupMenu, which ignore the app palette. Content is never screenshot.
 */
final class Sheet {
    private final Activity activity;
    private final Dialog dialog;
    private final LinearLayout body;

    Sheet(Activity activity, CharSequence title, CharSequence subtitle) {
        this.activity = activity;
        dialog = new Dialog(activity);
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
        body = new LinearLayout(activity); body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(dp(12), dp(10), dp(12), dp(12));
        View handle = new View(activity); handle.setBackground(round(color(R.color.outline), dp(2)));
        LinearLayout.LayoutParams handleParams = new LinearLayout.LayoutParams(dp(36), dp(4)); handleParams.gravity = Gravity.CENTER_HORIZONTAL; handleParams.bottomMargin = dp(10);
        body.addView(handle, handleParams);
        if (title != null) {
            TextView head = text(title, 18, R.color.text, true); head.setPadding(dp(8), dp(4), dp(8), 0); head.setMaxLines(2); head.setEllipsize(TextUtils.TruncateAt.END); body.addView(head);
        }
        if (subtitle != null && subtitle.length() > 0) {
            TextView sub = text(subtitle, 13, R.color.text_muted, false); sub.setPadding(dp(8), dp(2), dp(8), 0); sub.setMaxLines(3); sub.setEllipsize(TextUtils.TruncateAt.END); body.addView(sub);
        }
        if (title != null || subtitle != null) body.addView(new View(activity), new LinearLayout.LayoutParams(1, dp(8)));
    }

    Sheet section(int title) {
        TextView label = text(activity.getString(title).toUpperCase(java.util.Locale.getDefault()), 11, R.color.text_muted, true);
        label.setLetterSpacing(0.08f); label.setPadding(dp(8), dp(14), dp(8), dp(6)); body.addView(label);
        return this;
    }

    /** A row without an action is informational and is not focusable; icon 0 leaves the tile empty. */
    Sheet item(int icon, CharSequence title, CharSequence detail, Runnable action) { return add(icon, title, detail, action, false); }
    Sheet danger(int icon, CharSequence title, CharSequence detail, Runnable action) { return add(icon, title, detail, action, true); }
    /** Status row: a coloured dot instead of an icon tile. */
    Sheet status(int dotColor, CharSequence title, CharSequence detail) {
        LinearLayout row = row();
        View dot = new View(activity); dot.setBackground(round(dotColor, dp(5)));
        LinearLayout.LayoutParams dotParams = new LinearLayout.LayoutParams(dp(10), dp(10)); dotParams.setMarginStart(dp(13)); dotParams.setMarginEnd(dp(13));
        row.addView(dot, dotParams); row.addView(texts(title, detail, false), new LinearLayout.LayoutParams(0, -2, 1));
        body.addView(row); return this;
    }
    Sheet footer(CharSequence note) {
        TextView text = text(note, 12, R.color.text_muted, false); text.setPadding(dp(8), dp(12), dp(8), 0); body.addView(text);
        return this;
    }

    Dialog show() {
        ScrollView scroll = new ScrollView(activity); scroll.setVerticalScrollBarEnabled(false); scroll.addView(body);
        float r = dp(24); GradientDrawable bg = new GradientDrawable(); bg.setColor(color(R.color.surface_raised)); bg.setCornerRadii(new float[]{r, r, r, r, 0, 0, 0, 0});
        scroll.setBackground(bg);
        scroll.setOnApplyWindowInsetsListener((view, insets) -> {
            int bottom = Build.VERSION.SDK_INT >= 30 ? insets.getInsets(WindowInsets.Type.systemBars()).bottom : insets.getSystemWindowInsetBottom();
            view.setPadding(0, 0, 0, bottom); return insets;
        });
        dialog.setContentView(scroll);
        Window window = dialog.getWindow();
        if (window != null) {
            window.setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
            window.setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            window.setGravity(Gravity.BOTTOM);
            window.setWindowAnimations(android.R.style.Animation_InputMethod);
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE | WindowManager.LayoutParams.FLAG_DIM_BEHIND);
            window.setDimAmount(0.55f);
        }
        dialog.setCanceledOnTouchOutside(true);
        if (!activity.isFinishing() && !activity.isDestroyed()) dialog.show();
        return dialog;
    }

    private Sheet add(int icon, CharSequence title, CharSequence detail, Runnable action, boolean danger) {
        LinearLayout row = row();
        int tint = color(danger ? R.color.danger : R.color.accent);
        ImageView image = new ImageView(activity); if (icon != 0) image.setImageDrawable(tinted(icon, tint)); image.setScaleType(ImageView.ScaleType.CENTER_INSIDE);
        image.setPadding(dp(8), dp(8), dp(8), dp(8)); image.setBackground(round(danger ? Color.argb(40, 229, 72, 77) : color(R.color.accent_soft), dp(12)));
        LinearLayout.LayoutParams iconParams = new LinearLayout.LayoutParams(dp(40), dp(40)); iconParams.setMarginEnd(dp(14)); row.addView(image, iconParams);
        row.addView(texts(title, detail, danger), new LinearLayout.LayoutParams(0, -2, 1));
        if (action != null) {
            ImageView chevron = new ImageView(activity); chevron.setImageDrawable(tinted(R.drawable.ic_chevron, color(R.color.text_muted))); chevron.setAlpha(danger ? 0f : 0.6f);
            row.addView(chevron, new LinearLayout.LayoutParams(dp(20), dp(20)));
            row.setBackground(new RippleDrawable(ColorStateList.valueOf(color(R.color.ripple)), null, round(Color.WHITE, dp(14))));
            row.setClickable(true); row.setFocusable(true);
            row.setOnClickListener(v -> { dialog.dismiss(); action.run(); });
        }
        body.addView(row); return this;
    }
    private LinearLayout row() {
        LinearLayout row = new LinearLayout(activity); row.setGravity(Gravity.CENTER_VERTICAL); row.setMinimumHeight(dp(60));
        row.setPadding(dp(8), dp(8), dp(8), dp(8)); return row;
    }
    private LinearLayout texts(CharSequence title, CharSequence detail, boolean danger) {
        LinearLayout column = new LinearLayout(activity); column.setOrientation(LinearLayout.VERTICAL);
        TextView head = text(title, 15, danger ? R.color.danger : R.color.text, true); head.setMaxLines(2); head.setEllipsize(TextUtils.TruncateAt.END); column.addView(head);
        if (detail != null && detail.length() > 0) {
            TextView sub = text(detail, 12, R.color.text_muted, false); sub.setPadding(0, dp(2), 0, 0); sub.setMaxLines(3); sub.setEllipsize(TextUtils.TruncateAt.END); column.addView(sub);
        }
        return column;
    }
    private TextView text(CharSequence value, int size, int colorId, boolean bold) {
        TextView view = new TextView(activity); view.setText(value); view.setTextSize(size); view.setTextColor(color(colorId));
        if (bold) view.setTypeface(null, Typeface.BOLD); return view;
    }
    private Drawable tinted(int id, int tint) { Drawable icon = activity.getDrawable(id).mutate(); icon.setTint(tint); return icon; }
    private GradientDrawable round(int fill, int radius) { GradientDrawable bg = new GradientDrawable(); bg.setColor(fill); bg.setCornerRadius(radius); return bg; }
    private int color(int id) { return activity.getColor(id); }
    private int dp(int n) { return Math.round(n * activity.getResources().getDisplayMetrics().density); }
}
