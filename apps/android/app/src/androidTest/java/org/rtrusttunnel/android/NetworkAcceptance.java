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
    private static boolean largeUdpDigest;
    private static void check(boolean ok, String message) { if (!ok) throw new AssertionError(message); }
    private static int state() throws Exception { return new JSONObject(NativeCore.INSTANCE.status()).getInt("state"); }
    private static void await(int expected, long timeout) throws Exception {
        long end = SystemClock.elapsedRealtime() + timeout;
        while (SystemClock.elapsedRealtime() < end) { if (state() == expected) return; Thread.sleep(100); }
        throw new AssertionError("VPN state timeout, expected " + expected + ", got " + NativeCore.INSTANCE.status());
    }
    private static android.net.Network lastVpn;
    /** The service reports "connected" before Android makes the new VPN the active
     *  network of this UID. A socket opened in between leaves through the underlying
     *  network, and link properties read in between describe that network. */
    static void awaitVpn(Context context) throws Exception {
        android.net.ConnectivityManager cm = context.getSystemService(android.net.ConnectivityManager.class);
        long end = SystemClock.elapsedRealtime() + 10000;
        while (SystemClock.elapsedRealtime() < end) {
            android.net.Network network = cm.getActiveNetwork();
            android.net.NetworkCapabilities caps = cm.getNetworkCapabilities(network);
            // A new network: the previous VPN can stay active for a moment after Stop.
            if (network != null && !network.equals(lastVpn) && caps != null && caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)) { lastVpn = network; return; }
            Thread.sleep(50);
        }
        throw new AssertionError("VPN did not become the active network");
    }
    private static void connect(Context context) throws Exception {
        context.startForegroundService(new Intent(context, TunnelService.class));
        await(2, 45000); awaitVpn(context);
    }
    private static byte[] request(String address, int port, String request) throws Exception { return request(address, port, request, 5000); }
    private static byte[] request(String address, int port, String request, int connectTimeout) throws Exception {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(address, port), connectTimeout); socket.setSoTimeout(5000);
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
                byte[] expected=payload;
                if(largeUdpDigest && size>4000){
                    StringBuilder hex=new StringBuilder();for(byte value:java.security.MessageDigest.getInstance("SHA-256").digest(payload))hex.append(String.format(java.util.Locale.ROOT,"%02x",value&255));
                    expected=("SHA256:"+size+":"+hex).getBytes(StandardCharsets.US_ASCII);
                }
                check(packet.getLength()==expected.length && Arrays.equals(expected,Arrays.copyOf(bytes,packet.getLength())), "UDP payload integrity (large Hysteria requests use length+hash reply)");
            }
        }
    }
    static void verifyTraffic(JSONObject fixture) throws Exception {
        tcp(fixture.getString("target")); tcp(fixture.getString("target6"));
        udp(fixture.getString("target")); udp(fixture.getString("target6"));
    }
    private static String sourceTcp(String address) throws Exception {
        String response = new String(request(address, 8083, "GET / HTTP/1.0\r\nHost: fixture\r\n\r\n"), StandardCharsets.US_ASCII);
        return response.substring(response.indexOf("\r\n\r\n") + 4).trim();
    }
    private static String sourceUdp(String address) throws Exception {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(5000); socket.connect(InetAddress.getByName(address),8084);
            socket.send(new DatagramPacket(new byte[]{1},1)); byte[] bytes = new byte[128];
            DatagramPacket reply = new DatagramPacket(bytes,bytes.length);socket.receive(reply);
            return new String(bytes,0,reply.getLength(),StandardCharsets.US_ASCII).trim();
        }
    }
    private static void flowRouting(Context context, ProfileVault vault, JSONObject fixture, JSONObject base) throws Exception {
        String target=fixture.getString("target");
        String directTcp=sourceTcp(target), directUdp=sourceUdp(target);
        for (String kind : new String[]{"baseline","ip","port","domain","selective"}) {
            JSONObject candidate=new JSONObject(base.toString());
            JSONArray exclusions=new JSONArray();
            if (kind.equals("ip")) exclusions.put(target+"/32");
            if (kind.equals("port")) { exclusions.put("*:8083"); exclusions.put("*:8084"); }
            if (kind.equals("domain")) exclusions.put("*.split.example");
            if (kind.equals("selective")) exclusions.put(target+"/32");
            candidate.put("policy",new JSONObject().put("mode",kind.equals("selective")?"selective":"general").put("exclusions",exclusions));
            vault.edit(data -> { data.put("app_routing",new AppRouting(false,java.util.Collections.emptyList()).json());
                data.put("default","flow").put("profiles",new JSONArray().put(new JSONObject().put("id","flow").put("profile",candidate))); });
            connect(context);
            try {
                if(kind.equals("domain")) check(InetAddress.getByName("rtrust-"+System.nanoTime()+".split.example").getHostAddress().equals(target),"Domain rule learned through VPN DNS");
                boolean bypass=kind.equals("ip")||kind.equals("port")||kind.equals("domain");
                check(sourceTcp(target).equals(directTcp)==bypass,"TCP source confirms "+kind+" route");
                check(sourceUdp(target).equals(directUdp)==bypass,"UDP source confirms "+kind+" route");
            } finally {
                context.startService(new Intent(context,TunnelService.class).setAction(TunnelService.STOP));
                await(0,10000);for(int i=0;i<100&&TunnelService.active;i++)Thread.sleep(50);Thread.sleep(300);
            }
        }
        vault.write(new JSONObject().put("default","acceptance").put("profiles",new JSONArray().put(new JSONObject().put("id","acceptance").put("profile",base))));
    }
    static void run(Instrumentation test) throws Exception {
        Context context = test.getTargetContext();
        File source = new File(context.getCacheDir(), "vpn-fixture.json");
        JSONObject fixture = new JSONObject(new String(Files.readAllBytes(source.toPath()), StandardCharsets.UTF_8)); source.delete();
        largeUdpDigest=fixture.optBoolean("large_udp_digest");
        ProfileVault vault = new ProfileVault(context); JSONObject previous = vault.read();
        JSONObject profile = new JSONObject(NativeCore.INSTANCE.parse(fixture.getJSONObject("base").toString())).getJSONObject("profile");
        Activity activity = null;
        try {
            // Without the VPN the echo service sees this device's own address.
            String direct = sourceTcp(fixture.getString("target"));
            vault.write(new JSONObject().put("default", "acceptance").put("profiles", new JSONArray().put(new JSONObject().put("id", "acceptance").put("profile", profile))));
            check(android.net.VpnService.prepare(context) == null, "Emulator VPN consent prerequisite");
            activity = test.startActivitySync(new Intent(context, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
            connect(context);
            check(vault.selected().getJSONObject("endpoint").getString("upstream_protocol").equals("http3"), "Stored HTTP/3 retained");
            String v4 = fixture.getString("target"), v6 = fixture.getString("target6");
            tcp(v4); tcp(v6); udp(v4); udp(v6);
            check(Arrays.stream(InetAddress.getAllByName("rtrust-" + System.nanoTime() + ".example")).anyMatch(ip -> ip.getHostAddress().equals(v4)), "System DNS through tunnel");
            byte[] control = request(v4, 8082, "POST /cycle HTTP/1.0\r\nHost: fixture\r\nAuthorization: Bearer " + fixture.getString("control_token") + "\r\nContent-Length: 0\r\n\r\n");
            check(new String(control, StandardCharsets.US_ASCII).contains("204"), "Endpoint outage scheduled");
            // Hysteria notices a silent server only by QUIC idle timeout: about 37 s after
            // the last reply (keep-alive restart + 30 s) plus the 5 s health poll, measured
            // against the official server. The fixture restores it 60 s after scheduling,
            // so detection has a margin on both sides.
            await(3, largeUdpDigest ? 55000 : 10000);
            check(TunnelService.active, "TUN retained during reconnect");
            // The endpoint may return between the state check and this connection. A
            // connection that succeeds must then arrive through the tunnel, never
            // from this device's own address.
            String during = null;
            try {
                String response = new String(request(v4, 8083, "GET / HTTP/1.0\r\nHost: fixture\r\n\r\n", 2000), StandardCharsets.US_ASCII);
                int body = response.indexOf("\r\n\r\n");
                if (body >= 0) during = response.substring(body + 4).trim();
            } catch (IOException expected) { }
            check(during == null || during.isEmpty() || !during.equals(direct), "No direct fallback during outage");
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
            flowRouting(context, vault, fixture, profile);
            // A server without IPv6 must not be advertised as an IPv6 VPN. Otherwise
            // browsers can complete a local handshake into an unusable address family.
            JSONObject ipv4Only = vault.read();
            ipv4Only.getJSONArray("profiles").getJSONObject(0).getJSONObject("profile").getJSONObject("endpoint").put("has_ipv6", false);
            vault.write(ipv4Only);
            connect(context);
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
            Thread.sleep(300);
            JSONObject unavailable = vault.read();
            unavailable.getJSONArray("profiles").getJSONObject(0).getJSONObject("profile").getJSONObject("endpoint")
                .put("addresses", new JSONArray().put("startup-unavailable.invalid:443"));
            vault.write(unavailable);
            context.startForegroundService(new Intent(context, TunnelService.class));
            boolean guarded = false;
            for (int i = 0; i < 100; i++) {
                android.net.NetworkCapabilities caps = cm.getNetworkCapabilities(cm.getActiveNetwork());
                if (TunnelService.active && caps != null && caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)) { guarded = true; break; }
                Thread.sleep(100);
            }
            check(guarded, "Unavailable startup DNS retains blocking TUN");
            Thread.sleep(1000);
            check(TunnelService.active && TunnelService.problem.isEmpty(), "Unavailable DNS waits instead of terminating service");
            context.startService(new Intent(context, TunnelService.class).setAction(TunnelService.STOP));
            for (int i = 0; i < 100 && TunnelService.active; i++) Thread.sleep(100);
            check(!TunnelService.active, "Offline startup can be cancelled");

        } finally {
            if (TunnelService.active) { context.startService(new Intent(context, TunnelService.class).setAction(TunnelService.STOP)); await(0, 10000); }
            if (activity != null) { Activity finished = activity; test.runOnMainSync(finished::finish); }
            vault.write(previous);largeUdpDigest=false;
        }
    }
}
