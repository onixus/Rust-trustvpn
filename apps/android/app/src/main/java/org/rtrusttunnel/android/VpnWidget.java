package org.rtrusttunnel.android;

import android.app.PendingIntent;
import android.appwidget.*;
import android.content.*;
import android.widget.RemoteViews;
import org.json.JSONObject;

/** No profiles or credentials are stored in the launcher. */
public final class VpnWidget extends AppWidgetProvider {
    private static int lastStatus = -1;
    static int status() {
        if (!TunnelService.problem.isEmpty()) return R.string.connection_failed;
        if (!TunnelService.active) return R.string.disconnected;
        try {
            switch (new JSONObject(NativeCore.INSTANCE.status()).optInt("state")) {
                case 2: return R.string.connected;
                case 3: return R.string.reconnecting;
                case 4: return R.string.connection_failed;
                default: return R.string.connecting;
            }
        } catch (Exception ignored) { return R.string.vpn_status_unavailable; }
    }
    static PendingIntent action(Context context) {
        return PendingIntent.getActivity(context, 42,
            new Intent(context, WidgetActivity.class).setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
    }
    static void refresh(Context context, boolean force) {
        AppWidgetManager manager = AppWidgetManager.getInstance(context);
        int[] ids = manager.getAppWidgetIds(new ComponentName(context, VpnWidget.class));
        if (ids.length == 0) return;
        int status = status();
        if (!force && lastStatus == status) return;
        lastStatus = status;
        RemoteViews views = new RemoteViews(context.getPackageName(), R.layout.vpn_widget);
        views.setTextViewText(R.id.widget_status, context.getString(status));
        views.setOnClickPendingIntent(R.id.widget_power, action(context));
        views.setContentDescription(R.id.widget_power, context.getString(R.string.widget_toggle));
        manager.updateAppWidget(ids, views);
    }
    @Override public void onUpdate(Context context, AppWidgetManager manager, int[] ids) { refresh(context, true); }
}
