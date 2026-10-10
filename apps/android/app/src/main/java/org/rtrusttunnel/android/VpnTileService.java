package org.rtrusttunnel.android;

import android.content.Intent;
import android.graphics.drawable.Icon;
import android.os.Build;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;

/** Quick Settings control reuses the widget's VPN permission and recovery flow. */
public final class VpnTileService extends TileService {
    /** Set while the shade shows the tile, so status changes repaint it live. */
    private static volatile VpnTileService listening;

    static void refresh() {
        VpnTileService service = listening;
        if (service != null) service.update();
    }

    private void update() {
        Tile tile = getQsTile();
        if (tile == null) return;
        tile.setLabel(getString(R.string.app_name));
        tile.setSubtitle(getString(VpnWidget.status()));
        tile.setIcon(Icon.createWithResource(this, R.drawable.ic_power));
        tile.setState(TunnelService.active ? Tile.STATE_ACTIVE : Tile.STATE_INACTIVE);
        tile.setContentDescription(getString(R.string.widget_toggle));
        tile.updateTile();
    }

    @Override public void onStartListening() {
        super.onStartListening();
        listening = this;
        update();
    }

    @Override public void onStopListening() {
        if (listening == this) listening = null;
        super.onStopListening();
    }

    @Override public void onClick() {
        super.onClick();
        Runnable launch = () -> {
            if (Build.VERSION.SDK_INT >= 34) {
                startActivityAndCollapse(VpnWidget.action(this));
            } else {
                Intent intent = new Intent(this, WidgetActivity.class)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
                startActivityAndCollapse(intent);
            }
        };
        if (isLocked()) unlockAndRun(launch); else launch.run();
    }
}
