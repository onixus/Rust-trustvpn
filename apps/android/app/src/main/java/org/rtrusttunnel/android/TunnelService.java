package org.rtrusttunnel.android;

import android.app.*;
import android.content.*;
import android.content.pm.ServiceInfo;
import android.net.*;
import android.os.*;
import java.net.*;
import java.util.concurrent.*;
import org.json.*;

public final class TunnelService extends VpnService {
    static final String STOP = "org.rtrusttunnel.android.STOP";
    static volatile String problem = "";
    static volatile boolean active;
    static volatile boolean alwaysOn, lockdown;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private volatile Network underlying;
    private ParcelFileDescriptor tun;
    private ConnectivityManager connectivity;
    private ConnectivityManager.NetworkCallback callback;
    private volatile boolean stopping;
    private boolean cleaned;
    private static volatile TunnelService running;
    static void refreshPolicy() {
        TunnelService service = running;
        if (service == null) return;
        boolean previous = alwaysOn;
        alwaysOn = service.isAlwaysOn(); lockdown = service.isLockdownEnabled();
        if (previous != alwaysOn && active) service.getSystemService(NotificationManager.class).notify(1, service.notification());
    }

    @Override public void onCreate() {
        super.onCreate(); running = this; connectivity = getSystemService(ConnectivityManager.class);
        getSystemService(NotificationManager.class).createNotificationChannel(new NotificationChannel("vpn", getString(R.string.vpn_connection), NotificationManager.IMPORTANCE_LOW));
    }
    private Notification notification() {
        PendingIntent open = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        PendingIntent stop = PendingIntent.getService(this, 1, new Intent(this, TunnelService.class).setAction(STOP), PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        Notification.Builder notification = new Notification.Builder(this, "vpn").setSmallIcon(R.drawable.ic_flow_notification)
            .setContentTitle("R-TrustTunnel").setContentText(getString(R.string.vpn_active_open_app_for_connection))
            .setContentIntent(open).setOngoing(true);
        if (!isAlwaysOn()) notification.addAction(new Notification.Action.Builder(null, getString(R.string.disconnect), stop).build());
        return notification.build();
    }
    @Override public int onStartCommand(Intent intent, int flags, int id) {
        alwaysOn = isAlwaysOn(); lockdown = isLockdownEnabled();
        if (intent != null && STOP.equals(intent.getAction()) && !alwaysOn) { disconnect(); return START_NOT_STICKY; }
        if (active || stopping) return START_STICKY;
        if (VpnService.prepare(this) != null) { problem = getString(R.string.vpn_permission_is_required); stopSelf(); return START_NOT_STICKY; }
        if (Build.VERSION.SDK_INT >= 34) startForeground(1, notification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED);
        else startForeground(1, notification());
        active = true; problem = "";
        worker.execute(() -> {
            try { connect(); }
            catch (Exception error) {
                // Never include config, addresses or exception payloads in UI/logs.
                problem = getString(R.string.cannot_start_vpn_check_the_profile);
                cleanup(); stopForeground(STOP_FOREGROUND_REMOVE); stopSelf();
            }
        });
        return START_STICKY;
    }
    private Network availableNetwork() {
        for (Network network : connectivity.getAllNetworks()) {
            NetworkCapabilities caps = connectivity.getNetworkCapabilities(network);
            // Only a foreground network accepts sockets from an ordinary app: a background
            // one (e.g. mobile data kept up next to Wi-Fi) rejects bindSocket with EPERM.
            if (caps != null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_FOREGROUND)) return network;
        }
        return null;
    }
    private void connect() throws Exception {
        JSONObject profile = new ProfileVault(this).selected();
        JSONObject prepared = new JSONObject(NativeCore.INSTANCE.plan(profile.toString()));
        if (!prepared.getBoolean("ok")) throw new IllegalArgumentException("Unsupported mobile policy");
        profile = prepared.getJSONObject("profile");
        JSONObject plan = prepared.getJSONObject("plan");
        underlying = availableNetwork();
        JSONObject endpoint = profile.getJSONObject("endpoint");
        boolean ipv6 = endpoint.optBoolean("has_ipv6", true);
        Builder builder = new Builder().setSession("R-TrustTunnel").setMtu(plan.getInt("mtu"))
            .addAddress("169.254.254.2", 32)
            .setBlocking(false)
            .setUnderlyingNetworks(underlying == null ? new Network[]{} : new Network[]{underlying});
        // Leaving IPv6 unconfigured blocks that family in Android; never allowBypass/allowFamily.
        // Advertising a local IPv6 route for an IPv4-only endpoint makes browser
        // connection attempts reach an unusable tunnel instead of falling back to IPv4.
        if (ipv6) builder.addAddress("fd00:5254::2", 128);
        JSONArray routes = plan.getJSONArray("routes");
        for (int i = 0; i < routes.length(); i++) {
            String[] route = routes.getString(i).split("/"); builder.addRoute(route[0], Integer.parseInt(route[1]));
        }
        AppRouting.read(new ProfileVault(this).read()).apply(builder, getPackageManager());
        // The engine rejects unsupported policy/DNS options; do not silently bypass them.
        JSONArray dns = plan.getJSONArray("dns");
        if (dns == null || dns.length() == 0) builder.addDnsServer("1.1.1.1");
        else for (int i = 0; i < dns.length(); i++) {
            String server = dns.getString(i);
            if (!server.matches("[0-9a-fA-F:.]+")) throw new IllegalArgumentException("Numeric DNS required");
            if (!ipv6 && server.contains(":")) throw new IllegalArgumentException("IPv6 DNS requires an IPv6 endpoint");
            builder.addDnsServer(server);
        }
        if (stopping) return;
        tun = builder.establish();
        if (tun == null) throw new IllegalStateException("VPN permission revoked");
        // isAlwaysOn()/isLockdownEnabled() report false until this VPN is established, even
        // for a system Always-on start. The TUN carries no traffic yet, so checking here opens
        // no bypass; a refusal closes it through cleanup() and reports "cannot start".
        refreshPolicy();
        if (plan.getBoolean("require_lockdown") && (!isAlwaysOn() || !isLockdownEnabled())) throw new IllegalArgumentException("System lockdown required");
        callback = new ConnectivityManager.NetworkCallback() {
            @Override public void onAvailable(Network network) { updateUnderlying(); }
            @Override public void onLost(Network network) { updateUnderlying(); }
            private void updateUnderlying() {
                Network next = availableNetwork(); underlying = next;
                if (!stopping) setUnderlyingNetworks(next == null ? new Network[]{} : new Network[]{next});
            }
        };
        connectivity.registerNetworkCallback(new NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).addCapability(NetworkCapabilities.NET_CAPABILITY_FOREGROUND).build(), callback);
        // Establish the blocking TUN before waiting for connectivity or endpoint DNS.
        // The system's lockdown policy also protects the interval before service startup.
        JSONArray addresses = endpoint.getJSONArray("addresses");
        while (!stopping) {
            Network network = underlying;
            if (network != null) try {
                JSONArray resolved = new JSONArray();
                for (int i = 0; i < addresses.length(); i++) {
                    String address = addresses.getString(i);
                    int colon = address.lastIndexOf(':');
                    if (colon < 1) throw new IllegalArgumentException("Invalid endpoint");
                    String host = address.substring(0, colon).replace("[", "").replace("]", "");
                    int port = Integer.parseInt(address.substring(colon + 1));
                    for (InetAddress ip : network.getAllByName(host)) {
                        resolved.put((ip instanceof Inet6Address ? "[" + ip.getHostAddress() + "]" : ip.getHostAddress()) + ":" + port);
                        if (resolved.length() > 64) throw new IllegalArgumentException("Too many endpoints");
                    }
                }
                if (resolved.length() == 0) throw new UnknownHostException();
                endpoint.put("addresses", resolved);
                if (stopping) return;
                if (!NativeCore.INSTANCE.start(profile.toString(), tun.getFd(), this)) throw new IllegalStateException("Core rejected profile");
                problem = "";
                return;
            } catch (UnknownHostException unavailable) { /* Network/DNS can be unavailable at boot. */ }
            Thread.sleep(500);
            underlying = availableNetwork();
        }

    }
    /** Called from Rust before every endpoint socket connects. Failure always blocks that attempt. */
    public boolean protectSocket(int fd) {
        Network network = underlying;
        if (network == null || stopping || !protect(fd)) return false;
        try (ParcelFileDescriptor duplicate = ParcelFileDescriptor.fromFd(fd)) {
            network.bindSocket(duplicate.getFileDescriptor()); return true;
        } catch (Exception error) { return false; }
    }
    private void cleanup() {
        if (cleaned) return;
        cleaned = true;
        NativeCore.INSTANCE.stop();
        if (callback != null) { connectivity.unregisterNetworkCallback(callback); callback = null; }
        if (tun != null) { try { tun.close(); } catch (Exception ignored) {} tun = null; }
        underlying = null; active = false;
    }
    private void disconnect() {
        if (stopping) return;
        stopping = true;
        worker.execute(() -> { cleanup(); stopForeground(STOP_FOREGROUND_REMOVE); stopSelf(); });
    }
    @Override public void onRevoke() { disconnect(); }
    @Override public void onDestroy() { running = null; stopping = true; worker.execute(this::cleanup); worker.shutdown(); super.onDestroy(); }
}
