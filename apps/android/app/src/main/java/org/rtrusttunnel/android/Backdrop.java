package org.rtrusttunnel.android;

import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.PixelFormat;
import android.graphics.RadialGradient;
import android.graphics.Rect;
import android.graphics.Shader;
import android.graphics.drawable.Drawable;

/**
 * Screen background. The light theme paints soft colour blobs that translucent
 * cards sit on, which reads as frosted glass without a backdrop blur (Android has
 * no in-window backdrop blur before API 31, and minSdk is 29). The first blob
 * follows the connection state colour.
 */
final class Backdrop extends Drawable {
    private final Palette palette;
    private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private int accent;

    Backdrop(Palette palette) { this.palette = palette; accent = palette.blue; }

    void setAccent(int color) {
        if (accent == color) return;
        accent = color; invalidateSelf();
    }

    @Override public void draw(Canvas canvas) {
        canvas.drawColor(palette.bg);
        if (!palette.light) return;
        Rect b = getBounds(); float w = b.width(), h = b.height();
        blob(canvas, accent, 0.40f, b.left + w * 0.05f, b.top + h * 0.20f, w * 0.85f);
        blob(canvas, 0xFFB9AEFF, 0.45f, b.left + w * 0.95f, b.top + h * 0.50f, w * 0.75f);
        blob(canvas, 0xFF9FDCFF, 0.45f, b.left + w * 0.40f, b.top + h * 0.98f, w * 0.80f);
    }
    private void blob(Canvas canvas, int color, float alpha, float x, float y, float radius) {
        int center = (Math.round(alpha * 255) << 24) | (color & 0xFFFFFF);
        paint.setShader(new RadialGradient(x, y, radius, center, color & 0xFFFFFF, Shader.TileMode.CLAMP));
        canvas.drawCircle(x, y, radius, paint);
    }
    @Override public void setAlpha(int alpha) { }
    @Override public void setColorFilter(ColorFilter filter) { }
    @Override public int getOpacity() { return PixelFormat.OPAQUE; }
}
