package org.rtrusttunnel.android;

import android.content.Context;
import android.content.res.Configuration;
import android.graphics.Color;

/**
 * Dark and light (frosted glass) colours. State colours: grey off, blue connecting
 * or running, green only for fresh passed checks, yellow for a failed check, red on
 * error. Each has a dot/fill tone and a darker text tone for the light theme.
 */
final class Palette {
    static final String MODE_SYSTEM = "system", MODE_DARK = "dark", MODE_LIGHT = "light";
    private static final String PREFS = "ui", KEY = "theme";

    final boolean light;
    final int bg, text, muted, card, cardStroke, chip, field, rule, empty, sheet, ripple;
    final int blue, blueText, blueSoft, onBlue, green, greenText, yellow, yellowText, red, redText, grey, greyText, danger;

    private Palette(boolean light) {
        this.light = light;
        if (light) {
            bg = 0xFFE8EDF5; text = 0xFF0E1726; muted = 0xFF4A566B; card = 0x8CFFFFFF; cardStroke = 0xD9FFFFFF;
            chip = 0x99FFFFFF; field = 0xCCFFFFFF; rule = 0x140E1726; empty = 0xFF8C97A8; sheet = 0xFFF4F7FB; ripple = 0x220E1726;
            blueText = 0xFF1F6FE0; blueSoft = 0xFFDCE9FF; onBlue = Color.WHITE; greenText = 0xFF138A4E; yellowText = 0xFF8F6200;
            redText = 0xFFC2272D; greyText = 0xFF5B6678; danger = 0xFFC2272D;
        } else {
            bg = 0xFF08090B; text = 0xFFF4F5F7; muted = 0xFF8A93A0; card = 0xFF121418; cardStroke = 0xFF1B1E24;
            chip = 0xFF15181D; field = 0xFF1A1D23; rule = 0xFF1E2128; empty = 0xFF4A515C; sheet = 0xFF15181D; ripple = 0x33FFFFFF;
            blueText = 0xFF4DA3FF; blueSoft = 0xFF14243A; onBlue = 0xFF06213D; greenText = 0xFF3DD68C; yellowText = 0xFFE0A526;
            redText = 0xFFFF6B70; greyText = 0xFF9AA6B4; danger = 0xFFFF6B70;
        }
        blue = MainActivity.BUSY; green = MainActivity.VERIFIED; yellow = MainActivity.WARNING; red = MainActivity.ERROR;
        grey = light ? 0xFF8C97A8 : MainActivity.IDLE;
    }

    static String mode(Context context) {
        String mode = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY, MODE_SYSTEM);
        return MODE_DARK.equals(mode) || MODE_LIGHT.equals(mode) ? mode : MODE_SYSTEM;
    }
    static void setMode(Context context, String mode) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(KEY, mode).apply();
    }
    static boolean light(Context context) {
        String mode = mode(context);
        if (!MODE_SYSTEM.equals(mode)) return MODE_LIGHT.equals(mode);
        return (context.getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_NO;
    }
    static Palette of(Context context) { return new Palette(light(context)); }

    /** Text tone for a state fill colour. */
    int textFor(int fill) {
        if (fill == blue) return blueText;
        if (fill == green) return greenText;
        if (fill == yellow) return yellowText;
        if (fill == red) return redText;
        return greyText;
    }
}
