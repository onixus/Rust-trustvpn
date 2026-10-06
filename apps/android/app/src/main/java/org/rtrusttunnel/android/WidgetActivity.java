package org.rtrusttunnel.android;

import android.content.Intent;
import android.os.Bundle;

/** Only our immutable widget PendingIntent can enter this non-exported activity. */
public final class WidgetActivity extends MainActivity {
    private boolean pending;
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        pending = state == null; // Rotation/process restoration must not toggle again.
    }
    @Override protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent); pending = true;
    }
    @Override public void onResume() {
        // MainActivity resumes a lost Always-on session. Do not race that recovery
        // with a second toggle which could immediately stop the starting tunnel.
        boolean recoveryRequested = TunnelService.alwaysOnSessionLost(this);
        super.onResume();
        if (pending) {
            pending = false;
            if (!recoveryRequested) { TunnelService.refreshPolicy(); toggle(); }
        }
    }
}
