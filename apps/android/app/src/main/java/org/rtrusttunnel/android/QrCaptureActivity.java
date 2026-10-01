package org.rtrusttunnel.android;

/** Keep camera frames and scanned credentials out of screenshots and recent-app previews. */
public final class QrCaptureActivity extends com.journeyapps.barcodescanner.CaptureActivity {
    @Override public void onCreate(android.os.Bundle state) {
        getWindow().addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE);
        super.onCreate(state);
    }
}
