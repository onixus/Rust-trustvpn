package org.rtrusttunnel.android;

import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.text.TextPaint;
import android.text.TextUtils;
import android.view.MotionEvent;
import android.view.View;
import android.view.accessibility.AccessibilityNodeInfo;
import android.widget.Button;

/**
 * Slide-to-act control: the knob must be dragged to the end, so a pocket tap cannot
 * connect or disconnect. Forward slides left to right; reverse (used to disconnect)
 * starts the knob on the right and slides right to left. A tap only nudges the knob.
 * Accessibility services and performClick() act directly, so TalkBack users are not
 * asked to drag.
 */
final class SlideButton extends View {
    private final Paint fill = new Paint(Paint.ANTI_ALIAS_FLAG), stroke = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final TextPaint label = new TextPaint(Paint.ANTI_ALIAS_FLAG);
    private final RectF rect = new RectF();
    private final Drawable icon;
    private final float density;
    private Runnable action;
    private String text = "";
    private int track, trackStroke, knob, iconTint, labelColor;
    private boolean outline, dragging, reverse;
    private float progress, grab, downX;
    private ValueAnimator animator;

    SlideButton(Context context) {
        super(context);
        density = context.getResources().getDisplayMetrics().density;
        icon = context.getDrawable(R.drawable.ic_power).mutate();
        stroke.setStyle(Paint.Style.STROKE);
        label.setTextSize(15 * context.getResources().getDisplayMetrics().scaledDensity);
        label.setTypeface(Typeface.create(Typeface.SANS_SERIF, 700, false));
        setClickable(true); setFocusable(true);
    }

    void setAction(Runnable action) { this.action = action; }
    String text() { return text; }

    /** Repaints only when something changed; called from the 500 ms status poll. */
    void set(String text, int knob, int iconTint, boolean outline, boolean reverse, int track, int trackStroke, int labelColor) {
        if (text.equals(this.text) && knob == this.knob && iconTint == this.iconTint && outline == this.outline && reverse == this.reverse
            && track == this.track && trackStroke == this.trackStroke && labelColor == this.labelColor) return;
        if (reverse != this.reverse) { stop(); progress = 0; }
        this.text = text; this.knob = knob; this.iconTint = iconTint; this.outline = outline; this.reverse = reverse;
        this.track = track; this.trackStroke = trackStroke; this.labelColor = labelColor;
        setContentDescription(text);
        invalidate();
    }

    private float pad() { return 6 * density; }
    private float knobSize() { return getHeight() - 2 * pad(); }
    private float range() { return Math.max(1, getWidth() - 2 * pad() - knobSize()); }
    /** Left edge of the knob for the current progress and direction. */
    private float knobX() { return pad() + (reverse ? 1 - progress : progress) * range(); }

    @Override protected void onDraw(Canvas canvas) {
        float w = getWidth(), h = getHeight(), r = h / 2, pad = pad(), d = knobSize();
        rect.set(0, 0, w, h); fill.setColor(track); canvas.drawRoundRect(rect, r, r, fill);
        stroke.setStrokeWidth(density); stroke.setColor(trackStroke);
        rect.inset(density / 2, density / 2); canvas.drawRoundRect(rect, r, r, stroke);

        int alpha = Math.round(Math.max(0, 1 - progress * 1.6f) * 255);
        if (alpha > 0) {
            label.setColor(labelColor); label.setAlpha(alpha);
            float room = w - (pad + d + 14 * density) - 16 * density;
            CharSequence shown = TextUtils.ellipsize(reverse ? "←  " + text : text + "  →", label, room, TextUtils.TruncateAt.END);
            float baseline = h / 2 - (label.descent() + label.ascent()) / 2;
            float start = reverse ? w - pad - d - 14 * density - label.measureText(shown, 0, shown.length()) : pad + d + 14 * density;
            canvas.drawText(shown, 0, shown.length(), start, baseline, label);
        }

        float x = knobX(), cx = x + d / 2, cy = h / 2;
        if (outline) {
            stroke.setStrokeWidth(2.5f * density); stroke.setColor(knob);
            canvas.drawCircle(cx, cy, d / 2 - 1.25f * density, stroke);
        } else { fill.setColor(knob); canvas.drawCircle(cx, cy, d / 2, fill); }
        int size = Math.round(22 * density);
        icon.setTint(iconTint);
        icon.setBounds(Math.round(cx - size / 2f), Math.round(cy - size / 2f), Math.round(cx + size / 2f), Math.round(cy + size / 2f));
        icon.draw(canvas);
    }

    /** A touch never clicks: only a full drag acts. performClick() is the accessibility path. */
    @android.annotation.SuppressLint("ClickableViewAccessibility")
    @Override public boolean onTouchEvent(MotionEvent event) {
        if (!isEnabled()) return false;
        float x = knobX();
        switch (event.getActionMasked()) {
            case MotionEvent.ACTION_DOWN:
                stop(); downX = event.getX();
                dragging = event.getX() >= x - 8 * density && event.getX() <= x + knobSize() + 8 * density;
                grab = event.getX() - x;
                if (dragging && getParent() != null) getParent().requestDisallowInterceptTouchEvent(true);
                return true;
            case MotionEvent.ACTION_MOVE:
                if (dragging) {
                    float left = (event.getX() - grab - pad()) / range();
                    progress = clamp(reverse ? 1 - left : left); invalidate();
                }
                return true;
            case MotionEvent.ACTION_UP:
                if (dragging && progress > 0.8f) { animateTo(1, this::fire); }
                else if (Math.abs(event.getX() - downX) < 8 * density && progress < 0.05f) nudge();
                else animateTo(0, null);
                dragging = false; return true;
            case MotionEvent.ACTION_CANCEL:
                dragging = false; animateTo(0, null); return true;
            default: return false;
        }
    }
    @Override public boolean performClick() { super.performClick(); fire(); return true; }
    @Override public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
        super.onInitializeAccessibilityNodeInfo(info); info.setClassName(Button.class.getName());
    }
    @Override protected void onDetachedFromWindow() { stop(); super.onDetachedFromWindow(); }

    private void fire() {
        if (isEnabled() && action != null) action.run();
        postDelayed(() -> animateTo(0, null), 350);
    }
    private void nudge() {
        stop();
        animator = ValueAnimator.ofFloat(0, 0.18f, 0); animator.setDuration(420);
        animator.addUpdateListener(a -> { progress = (float) a.getAnimatedValue(); invalidate(); });
        animator.start();
    }
    private void animateTo(float target, Runnable end) {
        stop();
        animator = ValueAnimator.ofFloat(progress, target); animator.setDuration(180);
        animator.addUpdateListener(a -> { progress = (float) a.getAnimatedValue(); invalidate(); });
        if (end != null) animator.addListener(new android.animation.AnimatorListenerAdapter() {
            @Override public void onAnimationEnd(android.animation.Animator a) { end.run(); }
        });
        animator.start();
    }
    private void stop() { if (animator != null) { animator.removeAllListeners(); animator.cancel(); animator = null; } }
    private static float clamp(float v) { return Math.max(0, Math.min(1, v)); }
}
