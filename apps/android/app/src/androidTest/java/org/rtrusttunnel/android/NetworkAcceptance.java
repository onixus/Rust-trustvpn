package org.rtrusttunnel.android;

import android.app.*;
import android.content.*;
import android.os.SystemClock;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import org.json.*;

final class NetworkAcceptance {
    private static void check(boolean ok, String message) { if (!ok) throw new AssertionError(message); }
    private static int state() throws Exception { return new JSONObject(NativeCore.INSTANCE.status()).getInt("state"); }
    private static void await(int expected, long timeout) throws Exception {
        long end = SystemClock.elapsedRealtime() + timeout;
        while (SystemClock.elapsedRealtime() < end) { if (state() == expected) return; Thread.sleep(100); }
        throw new AssertionError("VPN state timeout, expected " + expected + ", got " + NativeCore.INSTANCE.status());
    }
    private static byte[] request(String address, int port, String request) throws Exception {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(address, port), 5000); socket.setSoTimeout(5000);
            socket.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII));
            return ProfileVault.readBounded(socket.getInputStream(), 1024 * 1024);
        }
    }
    private static void tcp(String address) throws Exception {
        byte[] response = request(address, 8080, "GET / HTTP/1.0\r\nHost: fixture\r\n\r\n");
        int body = -1;
        for (int i = 0; i + 3 < response.length; i++) if (response[i] == 13 && response[i + 1] == 10 && response[i + 2] == 13 && response[i + 3] == 10) { body = i + 4; break; }
        check(body > 0 && response.length - body == 512 * 1024, "TCP payload length");
        for (int i = body; i < response.length; i++) check(response[i] == (byte) (i - body), "TCP payload integrity");
    }
    private static void udp(String address) throws Exception {
        for (int size : new int[]{1, 1472, 5000, 60000}) {
            byte[] payload = new byte[size]; for (int i = 0; i < size; i++) payload[i] = (byte) i;
            try (DatagramSocket socket = new DatagramSocket()) {
                socket.setSoTimeout(5000); socket.connect(InetAddress.getByName(address), 8081);
                socket.send(new DatagramPacket(payload, payload.length));
                byte[] bytes = new byte[65535]; DatagramPacket packet = new DatagramPacket(bytes, bytes.length); socket.receive(packet);
                check(packet.getLength() == size && Arrays.equals(payload, Arrays.copyOf(bytes, size)), "UDP payload integrity");
            }
        }
    }
    static void verifyTraffic(JSONObject fixture) throws Exception {
        tcp(fixture.getString("target")); tcp(fixture.getString("target6"));
        udp(fixture.getString("target")); udp(fixture.getString("target6"));
    }
    static void run(Instrumentation test) throws Exception {
        Context context = test.getTargetContext();
        File source = new File(context.getCacheDir(), "vpn-fixture.json");
        JSONObject fixture = new JSONObject(new String(Files.readAllBytes(source.toPath()), StandardCharsets.UTF_8)); source.delete();
        ProfileVault vault = new ProfileVault(context); JSONObject previous = vault.read();
        JSONObject profile = new JSONObject(NativeCore.INSTANCE.parse(fixture.getJSONObject("base").toString())).getJSONObject("profile");
        Activity activity = null;
        try {
            vault.write(new JSONObject().put("default", "acceptance").put("profiles", new JSONArray().put(new JSONObject().put("id", "acceptance").put("profile", profile))));
            check(android.net.VpnService.prepare(context) == null, "Emulator VPN consent prerequisite");
            activity = test.startActivitySync(new Intent(context, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
            context.startForegroundService(new Intent(context, TunnelService.class));
            await(2, 45000);
            check(vault.selected().getJSONObject("endpoint").getString("upstream_protocol").equals("http3"), "Stored HTTP/3 retained");
            String v4 = fixture.getString("target"), v6 = fixture.getString("target6");
            tcp(v4); tcp(v6); udp(v4); udp(v6);
            check(Arrays.stream(InetAddress.getAllByName("rtrust-" + System.nanoTime() + ".example")).anyMatch(ip -> ip.getHostAddress().equals(v4)), "System DNS through tunnel");
            byte[] control = request(v4, 8082, "POST /cycle HTTP/1.0\r\nHost: fixture\r\nAuthorization: Bearer " + fixture.getString("control_token") + "\r\nContent-Length: 0\r\n\r\n");
            check(new String(control, StandardCharsets.US_ASCII).contains("204"), "Endpoint outage scheduled");
            await(3, 10000);
            check(TunnelService.active, "TUN retained during reconnect");
            boolean blocked = false;
            try (Socket socket = new Socket()) { socket.connect(new InetSocketAddress(v4, 8080), 2000); }
            catch (IOException expected) { blocked = true; }
            check(blocked, "No direct fallback during outage");
            await(2, 45000); tcp(v4); tcp(v6);
            Activity finished = activity; test.runOnMainSync(finished::finish); activity = null;
            Thread.sleep(1500); check(TunnelService.active && state() == 2, "Activity close retains VPN"); tcp(v4);
            context.startService(new Intent(context, TunnelService.class).setAction(TunnelService.STOP));
            await(0, 10000);
            long end = SystemClock.elapsedRealtime() + 5000;
            while (TunnelService.active && SystemClock.elapsedRealtime() < end) Thread.sleep(50);
            check(!TunnelService.active, "Service and TUN stopped");
            Thread.sleep(300);
            AppRoutingAcceptance.uidRouting(test, fixture);
            // A server without IPv6 must not be advertised as an IPv6 VPN. Otherwise
            // browsers can complete a local handshake into an unusable address family.
            JSONObject ipv4Only = vault.read();
            ipv4Only.getJSONArray("profiles").getJSONObject(0).getJSONObject("profile").getJSONObject("endpoint").put("has_ipv6", false);
            vault.write(ipv4Only);
            context.startForegroundService(new Intent(context, TunnelService.class));
            await(2, 45000);
            android.net.ConnectivityManager cm = context.getSystemService(android.net.ConnectivityManager.class);
            android.net.LinkProperties links = cm.getLinkProperties(cm.getActiveNetwork());
            check(links != null && links.getLinkAddresses().stream().noneMatch(a -> a.getAddress() instanceof Inet6Address), "IPv4-only endpoint must not advertise IPv6 on Android");
            check(links.getRoutes().stream().noneMatch(r -> r.getType() == android.net.RouteInfo.RTN_UNICAST && r.getDestination().getAddress() instanceof Inet6Address), "No IPv6 route for IPv4-only endpoint");
            tcp(v4); udp(v4);
            boolean v6Blocked = false;
            try (Socket socket = new Socket()) { socket.connect(new InetSocketAddress(v6, 8080), 2000); }
            catch (IOException expected) { v6Blocked = true; }
            check(v6Blocked, "IPv6 cannot bypass an IPv4-only VPN");
            context.startService(new Intent(context, TunnelService.class).setAction(TunnelService.STOP));
            await(0, 10000);

        } finally {
            if (TunnelService.active) { context.startService(new Intent(context, TunnelService.class).setAction(TunnelService.STOP)); await(0, 10000); }
            if (activity != null) { Activity finished = activity; test.runOnMainSync(finished::finish); }
            vault.write(previous);
        }
    }
}
