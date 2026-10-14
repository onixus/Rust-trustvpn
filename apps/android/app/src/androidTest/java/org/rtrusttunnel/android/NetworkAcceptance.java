package org.rtrusttunnel.android;

import android.app.*;
import android.content.*;
import android.os.ParcelFileDescriptor;
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
        await(2, 45000); awaitVpn(context); settle(context);
    }
    /** The emulator's Wi-Fi can pass validation only after the tunnel is up. Android then
     *  makes it the default network and the service follows it with a reconnect, so traffic
     *  checks wait for a validated physical network and a connected tunnel. */
    static void settle(Context context) throws Exception {
        android.net.ConnectivityManager cm = context.getSystemService(android.net.ConnectivityManager.class);
        long end = SystemClock.elapsedRealtime() + 30000;
        while (SystemClock.elapsedRealtime() < end) {
            android.net.Network network = physical(cm);
            android.net.NetworkCapabilities caps = network == null ? null : cm.getNetworkCapabilities(network);
            if (caps != null && caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED)) break;
            Thread.sleep(200);
        }
        Thread.sleep(1000); // the default switch and the service's network callback follow validation
        await(2, 75000);
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
        largeUdpDigest = fixture.optBoolean("large_udp_digest");
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
    private static void shell(Instrumentation test, String command) throws Exception {
        try (ParcelFileDescriptor out = test.getUiAutomation().executeShellCommand(command);
             InputStream in = new ParcelFileDescriptor.AutoCloseInputStream(out)) { while (in.read() >= 0) { } }
    }
    /** The physical network the service should use: the same ranking as TunnelService. */
    private static android.net.Network physical(android.net.ConnectivityManager cm) {
        android.net.Network best = null; int bestRank = -1;
        for (android.net.Network n : cm.getAllNetworks()) {
            android.net.NetworkCapabilities caps = cm.getNetworkCapabilities(n);
            if (caps != null && caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET)
                && caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                && caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_FOREGROUND)
                && TunnelService.preference(caps) > bestRank) { best = n; bestRank = TunnelService.preference(caps); }
        }
        return best;
    }
    private static final int[] PHYSICAL_TRANSPORTS = {android.net.NetworkCapabilities.TRANSPORT_WIFI, android.net.NetworkCapabilities.TRANSPORT_CELLULAR, android.net.NetworkCapabilities.TRANSPORT_ETHERNET};
    /** Waits until a validated physical network other than {@code previous} is in use
     *  and the VPN declares its transports. Metering is not compared: the Builder leaves
     *  the VPN metered by default. */
    private static android.net.Network awaitDeclared(android.net.ConnectivityManager cm, android.net.Network previous, String stage, long timeout) throws Exception {
        return awaitDeclared(cm, previous, -1, stage, timeout);
    }
    /** {@code required} (a transport, or -1 for any) is required of the network the VPN must ride. */
    private static android.net.Network awaitDeclared(android.net.ConnectivityManager cm, android.net.Network previous, int required, String stage, long timeout) throws Exception {
        long end = SystemClock.elapsedRealtime() + timeout;
        String last = "no VPN";
        while (SystemClock.elapsedRealtime() < end) {
            android.net.Network current = physical(cm), vpn = cm.getActiveNetwork();
            android.net.NetworkCapabilities physicalCaps = current == null ? null : cm.getNetworkCapabilities(current), vpnCaps = vpn == null ? null : cm.getNetworkCapabilities(vpn);
            if (physicalCaps != null && vpnCaps != null && vpnCaps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)) {
                last = "VPN " + vpnCaps + " over " + physicalCaps;
                // Wait for validation too: later checks open direct sockets on this network.
                boolean declared = !current.equals(previous) && (required < 0 || physicalCaps.hasTransport(required)) && physicalCaps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED);
                for (int transport : PHYSICAL_TRANSPORTS) declared &= vpnCaps.hasTransport(transport) == physicalCaps.hasTransport(transport);
                if (declared) return current;
            }
            Thread.sleep(200);
        }
        throw new AssertionError("VPN does not declare the underlying network " + stage + ": " + last);
    }
    /** Android derives the VPN's transports, bandwidth and roaming state from its declared
     *  underlying network. A TUN retained across a handoff must not keep declaring the
     *  lost one: the VPN then reports no physical transport.
     *  Turning the current network off and on again hands off twice: on the emulator from
     *  Wi-Fi to background mobile data and back to a new Wi-Fi network. */
    private static void underlyingFollowsHandoff(Instrumentation test) throws Exception {
        android.net.ConnectivityManager cm = test.getTargetContext().getSystemService(android.net.ConnectivityManager.class);
        // With Wi-Fi and mobile data both up, the VPN must ride the preferred network.
        android.net.Network before = awaitDeclared(cm, null, "before handoff", 30000);
        android.net.NetworkCapabilities caps = cm.getNetworkCapabilities(before);
        check(caps != null && (caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI) || caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR)), "Handoff prerequisite: Wi-Fi or mobile data in use, got " + caps);
        String radio = caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI) ? "wifi" : "data";
        android.net.Network previous = before;
        try {
            shell(test, "svc " + radio + " disable");
            long end = SystemClock.elapsedRealtime() + 15000;
            while (before.equals(physical(cm)) && SystemClock.elapsedRealtime() < end) Thread.sleep(100);
            check(!before.equals(physical(cm)), "Handoff prerequisite: " + radio + " disabled");
            if (physical(cm) != null) previous = awaitDeclared(cm, before, "after losing " + radio, 30000);
        } finally { shell(test, "svc " + radio + " enable"); }
        // Restored Wi-Fi is preferred again; restored mobile data stays behind any Wi-Fi.
        // The emulator can take over a minute to rejoin its Wi-Fi network.
        if (radio.equals("wifi")) awaitDeclared(cm, previous, android.net.NetworkCapabilities.TRANSPORT_WIFI, "after restoring wifi", 120000);
        else awaitDeclared(cm, before, "after restoring data", 120000);
        await(2, 75000); // the TUN and its VPN network are retained
    }
    /** The user setting switches the VPN between Android's always-metered default and the
     *  metering of its underlying network. Android fixes metering when it registers the VPN
     *  network, so each value is checked on a new connection. */
    private static void meteringFollowsSetting(Instrumentation test) throws Exception {
        Context context = test.getTargetContext();
        android.net.ConnectivityManager cm = context.getSystemService(android.net.ConnectivityManager.class);
        try {
            for (boolean inherit : new boolean[]{true, false}) {
                TunnelService.setInheritMetering(context, inherit);
                context.startService(new Intent(context, TunnelService.class).setAction(TunnelService.STOP));
                await(0, 10000);
                for (int i = 0; i < 100 && TunnelService.active; i++) Thread.sleep(100);
                Thread.sleep(300);
                connect(context);
                android.net.Network network = physical(cm), vpn = cm.getActiveNetwork();
                android.net.NetworkCapabilities physicalCaps = network == null ? null : cm.getNetworkCapabilities(network), vpnCaps = vpn == null ? null : cm.getNetworkCapabilities(vpn);
                check(physicalCaps != null && vpnCaps != null && vpnCaps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN), "Metering prerequisite: VPN over a physical network");
                boolean expected = inherit && physicalCaps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_NOT_METERED);
                check(vpnCaps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_NOT_METERED) == expected, "VPN metering follows the setting (inherit=" + inherit + "): VPN " + vpnCaps + " over " + physicalCaps);
            }
        } finally { TunnelService.setInheritMetering(context, false); }
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
            long connectedAt = SystemClock.elapsedRealtime();
            check(vault.selected().getJSONObject("endpoint").getString("upstream_protocol").equals(profile.getJSONObject("endpoint").getString("upstream_protocol")), "Stored transport retained");
            String v4 = fixture.getString("target"), v6 = fixture.getString("target6");
            tcp(v4); tcp(v6); udp(v4); udp(v6);
            check(Arrays.stream(InetAddress.getAllByName("rtrust-" + System.nanoTime() + ".example")).anyMatch(ip -> ip.getHostAddress().equals(v4)), "System DNS through tunnel");
            byte[] control = request(v4, 8082, "POST /cycle HTTP/1.0\r\nHost: fixture\r\nAuthorization: Bearer " + fixture.getString("control_token") + "\r\nContent-Length: 0\r\n\r\n");
            check(new String(control, StandardCharsets.US_ASCII).contains("204"), "Endpoint outage scheduled");
            // Hysteria notices a silent server only by QUIC idle timeout: about 37 s after
            // the last reply (keep-alive restart + 30 s) plus the 5 s health poll, measured
            // against the official server. The fixture restores it 60 s after scheduling,
            // so detection has a margin on both sides.
            // WireGuard has no connection to lose: a silent AmneziaWG peer is noticed
            // only when traffic goes unanswered, so keep some flowing while waiting.
            long detected = SystemClock.elapsedRealtime() + fixture.optInt("outage_detection_ms", largeUdpDigest ? 55000 : 10000);
            while (state() != 3) {
                if (SystemClock.elapsedRealtime() > detected) throw new AssertionError("VPN state timeout, expected 3, got " + NativeCore.INSTANCE.status());
                try (Socket probe = new Socket()) { probe.connect(new InetSocketAddress(v4, 8080), 1000); }
                catch (IOException expected) { }
                Thread.sleep(500);
            }
            long connectedFor = SystemClock.elapsedRealtime() - connectedAt;
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
            // Recovery holds a connection that dropped within 60 s off for the rest of
            // that minute plus 0-3 s jitter (docs/recovery.md), even when the endpoint
            // is already back. connectedFor starts after awaitVpn, so it never
            // overstates the product's own measure by more than the detection poll.
            long cooldown = Math.max(0, 60000 - connectedFor) + 3000 + 15000;
            await(2, Math.max(fixture.optInt("recovery_ms", 45000), cooldown)); tcp(v4); tcp(v6);
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
            // The core reports 0 before the old service finishes cleanup. A start sent to
            // that stopping instance is ignored, and its stopSelf() then drops the start.
            for (int i = 0; i < 100 && TunnelService.active; i++) Thread.sleep(100);
            check(!TunnelService.active, "IPv4-only VPN stopped");
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
            // Last: the handoff replaces the emulator's network for later checks.
            vault.write(new JSONObject().put("default", "acceptance").put("profiles", new JSONArray().put(new JSONObject().put("id", "acceptance").put("profile", profile)))); connect(context);
            meteringFollowsSetting(test); underlyingFollowsHandoff(test); verifyTraffic(fixture);
            context.startService(new Intent(context, TunnelService.class).setAction(TunnelService.STOP));
            await(0, 10000);

        } finally {
            if (TunnelService.active) { context.startService(new Intent(context, TunnelService.class).setAction(TunnelService.STOP)); await(0, 10000); }
            if (activity != null) { Activity finished = activity; test.runOnMainSync(finished::finish); }
            vault.write(previous);largeUdpDigest=false;
        }
    }
}
