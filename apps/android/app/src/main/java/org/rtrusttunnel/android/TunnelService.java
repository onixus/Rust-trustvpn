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
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private volatile Network underlying;
    private ParcelFileDescriptor tun;
    private ConnectivityManager connectivity;
    private ConnectivityManager.NetworkCallback callback;
    private volatile boolean stopping;
    private boolean cleaned;

    @Override public void onCreate() {
        super.onCreate(); connectivity = getSystemService(ConnectivityManager.class);
        getSystemService(NotificationManager.class).createNotificationChannel(new NotificationChannel("vpn", "VPN connection", NotificationManager.IMPORTANCE_LOW));
    }
    private Notification notification() {
        PendingIntent open = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        PendingIntent stop = PendingIntent.getService(this, 1, new Intent(this, TunnelService.class).setAction(STOP), PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        return new Notification.Builder(this, "vpn").setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("R-TrustTunnel").setContentText("VPN active · open app for connection status")
            .setContentIntent(open).setOngoing(true).addAction(new Notification.Action.Builder(null, "Disconnect", stop).build()).build();
    }
    @Override public int onStartCommand(Intent intent, int flags, int id) {
        if (intent != null && STOP.equals(intent.getAction())) { disconnect(); return START_NOT_STICKY; }
        if (active || stopping) return START_NOT_STICKY;
        if (VpnService.prepare(this) != null) { problem = "VPN permission is required"; stopSelf(); return START_NOT_STICKY; }
        if (Build.VERSION.SDK_INT >= 34) startForeground(1, notification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED);
        else startForeground(1, notification());
        active = true; problem = "";
        worker.execute(() -> {
            try { connect(); }
            catch (Exception error) {
                // Never include config, addresses or exception payloads in UI/logs.
                problem = "Cannot start VPN. Check the profile and network, then retry.";
                cleanup(); stopForeground(STOP_FOREGROUND_REMOVE); stopSelf();
            }
        });
        return START_NOT_STICKY;
    }
    private Network availableNetwork() {
        for (Network network : connectivity.getAllNetworks()) {
            NetworkCapabilities caps = connectivity.getNetworkCapabilities(network);
            if (caps != null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) return network;
        }
        return null;
    }
    private void connect() throws Exception {
        JSONObject profile = new ProfileVault(this).selected();
        if (profile.has("original_cli") && !profile.isNull("original_cli")) throw new IllegalArgumentException("Desktop CLI policy unsupported");
        if (!profile.isNull("policy") && !profile.opt("policy").toString().equals("{}")) throw new IllegalArgumentException("Desktop policy unsupported");
        underlying = availableNetwork();
        if (underlying == null) throw new IllegalStateException("No underlying network");
        JSONObject endpoint = profile.getJSONObject("endpoint");
        JSONArray addresses = endpoint.getJSONArray("addresses"), resolved = new JSONArray();
        for (int i = 0; i < addresses.length(); i++) {
            String address = addresses.getString(i);
            int colon = address.lastIndexOf(':');
            if (colon < 1) throw new IllegalArgumentException("Invalid endpoint");
            String host = address.substring(0, colon).replace("[", "").replace("]", "");
            int port = Integer.parseInt(address.substring(colon + 1));
            for (InetAddress ip : underlying.getAllByName(host)) {
                resolved.put((ip instanceof Inet6Address ? "[" + ip.getHostAddress() + "]" : ip.getHostAddress()) + ":" + port);
                if (resolved.length() > 64) throw new IllegalArgumentException("Too many endpoints");
            }
        }
        endpoint.put("addresses", resolved);
        boolean ipv6 = endpoint.optBoolean("has_ipv6", true);
        Builder builder = new Builder().setSession("R-TrustTunnel").setMtu(1500)
            .addAddress("169.254.254.2", 32)
            .addRoute("0.0.0.0", 0).setBlocking(false)
            .setUnderlyingNetworks(new Network[]{underlying});
        // Leaving IPv6 unconfigured blocks that family in Android; never allowBypass/allowFamily.
        // Advertising a local IPv6 route for an IPv4-only endpoint makes browser
        // connection attempts reach an unusable tunnel instead of falling back to IPv4.
        if (ipv6) builder.addAddress("fd00:5254::2", 128).addRoute("::", 0);
        AppRouting.read(new ProfileVault(this).read()).apply(builder, getPackageManager());
        // The engine rejects unsupported policy/DNS options; do not silently bypass them.
        JSONArray dns = endpoint.optJSONArray("dns_upstreams");
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
        if (!NativeCore.INSTANCE.start(profile.toString(), tun.getFd(), this)) throw new IllegalStateException("Core rejected profile");
        callback = new ConnectivityManager.NetworkCallback() {
            @Override public void onAvailable(Network network) { updateUnderlying(); }
            @Override public void onLost(Network network) { updateUnderlying(); }
            private void updateUnderlying() {
                Network next = availableNetwork(); underlying = next;
                if (!stopping) setUnderlyingNetworks(next == null ? new Network[]{} : new Network[]{next});
            }
        };
        connectivity.registerNetworkCallback(new NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), callback);
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
    @Override public void onDestroy() { stopping = true; worker.execute(this::cleanup); worker.shutdown(); super.onDestroy(); }
}
