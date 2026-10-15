package org.rtrusttunnel.android;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** LinkProperties updates on the same underlying network that must or must not rebuild the session. */
public final class LinkChangeTest {
    // Linux uapi values, equal to android.system.OsConstants / RouteInfo on Android.
    private static final int TEMPORARY = 0x01, DADFAILED = 0x08, DEPRECATED = 0x20, TENTATIVE = 0x40, PERMANENT = 0x80;
    private static final int UNICAST = 1, UNREACHABLE = 7, UNKNOWN = -1;
    private static final List<String> NONE = Collections.<String>emptyList();

    private static void check(boolean value, String label) {
        if (!value) throw new AssertionError(label);
    }
    private static List<String> list(String... values) {
        return Arrays.asList(values);
    }
    /** Mutable description of one snapshot, turned into State through the production Builder. */
    private static final class Link {
        String iface = "wlan0", nat64;
        int mtu = 1500;
        final java.util.LinkedHashMap<String, Integer> addresses = new java.util.LinkedHashMap<>(), routes = new java.util.LinkedHashMap<>();
        Link address(String address, int flags) { addresses.put(address, flags); return this; }
        Link drop(String address) { addresses.remove(address); return this; }
        Link route(String route, int type) { routes.put(route, type); return this; }
        Link dropRoute(String route) { routes.remove(route); return this; }
        Link mtu(int value) { mtu = value; return this; }
        Link nat64(String value) { nat64 = value; return this; }
        Link iface(String value) { iface = value; return this; }
        Link copy() {
            Link result = new Link();
            result.iface = iface; result.nat64 = nat64; result.mtu = mtu;
            result.addresses.putAll(addresses); result.routes.putAll(routes);
            return result;
        }
        LinkChange.State state() {
            LinkChange.Builder builder = new LinkChange.Builder(iface, mtu, nat64, TEMPORARY, DEPRECATED, DADFAILED, UNICAST);
            for (java.util.Map.Entry<String, Integer> entry : addresses.entrySet()) builder.address(entry.getKey(), entry.getValue());
            for (java.util.Map.Entry<String, Integer> entry : routes.entrySet()) builder.route(entry.getKey(), entry.getValue());
            return builder.build();
        }
    }
    private static boolean rebuild(Link before, Link after) {
        return LinkChange.requiresRebuild(before.state(), after.state());
    }
    private static Link dualStack() {
        return new Link().address("192.0.2.10/24", PERMANENT).address("fe80::1/64", PERMANENT).address("2001:db8::10/64", 0)
            .route("192.0.2.0/24 null wlan0", UNICAST).route("0.0.0.0/0 192.0.2.1 wlan0", UNICAST)
            .route("fe80::/64 null wlan0", UNICAST).route("2001:db8::/64 null wlan0", UNICAST).route("::/0 fe80::1 wlan0", UNICAST);
    }
    private static Link ipv6Only() {
        return new Link().address("fe80::1/64", PERMANENT).address("2001:db8::10/64", 0).nat64("64:ff9b::/96")
            .route("fe80::/64 null wlan0", UNICAST).route("2001:db8::/64 null wlan0", UNICAST).route("::/0 fe80::1 wlan0", UNICAST);
    }

    private static void mapping() {
        LinkChange.State state = new LinkChange.Builder("wlan0", 1500, null, TEMPORARY, DEPRECATED, DADFAILED, UNICAST)
            .address("2001:db8::10/64", TEMPORARY | DEPRECATED).address("2001:db8::11/64", DADFAILED | TENTATIVE)
            .address("192.0.2.10/24", PERMANENT)
            .route("::/0 fe80::1 wlan0", UNICAST).route("2001:db8:f::/48 null wlan0", UNREACHABLE).route("10.0.0.0/8 null wlan0", UNKNOWN)
            .build();
        check(state.addresses.equals(list("2001:db8::10/64", "2001:db8::11/64", "192.0.2.10/24")), "mapping keeps all addresses");
        check(state.deprecated.equals(list("2001:db8::10/64")), "mapping deprecated flag");
        check(state.temporary.equals(list("2001:db8::10/64")), "mapping temporary flag");
        check(state.failed.equals(list("2001:db8::11/64")), "mapping DAD-failed flag");
        check(state.routes.equals(list("::/0 fe80::1 wlan0 1", "2001:db8:f::/48 null wlan0 7", "10.0.0.0/8 null wlan0 -1")),
            "mapping route key carries type, unknown as -1");
        check(state.restrictive.equals(list("2001:db8:f::/48 null wlan0 7")), "mapping restrictive = known non-unicast only");
        check(new LinkChange.Builder("wlan0", 0, null, TEMPORARY, DEPRECATED, DADFAILED, UNICAST).route("x", -7).build()
            .routes.equals(list("x -1")), "mapping any negative type is unknown");
    }

    public static void main(String[] args) {
        mapping();
        Link base = dualStack();
        check(!rebuild(base, base.copy()), "identical properties keep session");

        // #75 behaviour that must stay: SLAAC additions alone keep the session.
        Link v4Only = new Link().address("192.0.2.10/24", PERMANENT).address("fe80::1/64", PERMANENT)
            .route("192.0.2.0/24 null wlan0", UNICAST).route("0.0.0.0/0 192.0.2.1 wlan0", UNICAST).route("fe80::/64 null wlan0", UNICAST);
        check(!rebuild(v4Only, v4Only.copy().address("2001:db8::10/64", TENTATIVE)), "IPv6 SLAAC address added keeps session");
        check(!rebuild(v4Only, v4Only.copy().route("2001:db8::/64 null wlan0", UNICAST).route("::/0 fe80::1 wlan0", UNICAST)),
            "IPv6 prefix and default route added keep session");
        check(!rebuild(new Link().mtu(0), new Link().mtu(0).address("2001:db8::10/64", 0)), "IPv6-only addition from empty keeps session");
        check(!rebuild(base, base.copy().address("2001:db8::abcd/64", TEMPORARY)), "RFC 4941 temporary IPv6 address added keeps session");
        Link tentative = base.copy().address("2001:db8::abcd/64", TEMPORARY | TENTATIVE);
        check(!rebuild(tentative, base.copy().address("2001:db8::abcd/64", TEMPORARY)), "DAD completion keeps session");

        // Address changes.
        check(rebuild(base, base.copy().drop("192.0.2.10/24").address("192.0.2.11/24", PERMANENT)), "IPv4 address changed rebuilds");
        check(rebuild(base, base.copy().address("198.51.100.5/24", PERMANENT)), "IPv4 address added rebuilds");
        check(rebuild(base, base.copy().drop("2001:db8::10/64")), "IPv6 address removed rebuilds");
        check(rebuild(base, base.copy().address("2001:db8:1::10/64", 0).drop("192.0.2.10/24")), "IPv6 added while IPv4 removed rebuilds");
        Link withTemporary = base.copy().address("2001:db8::abcd/64", TEMPORARY);
        check(rebuild(withTemporary, base), "unused temporary IPv6 address removed still rebuilds (defensive)");

        // Deprecated / DAD-failed addresses.
        check(rebuild(base, base.copy().address("2001:db8::10/64", DEPRECATED)), "non-temporary address turning deprecated rebuilds");
        check(!rebuild(withTemporary, withTemporary.copy().address("2001:db8::abcd/64", TEMPORARY | DEPRECATED)),
            "temporary address deprecated while a preferred global IPv6 remains keeps session");
        Link onlyTemporary = new Link().address("192.0.2.10/24", PERMANENT).address("fe80::1/64", PERMANENT).address("2001:db8::abcd/64", TEMPORARY);
        check(rebuild(onlyTemporary, onlyTemporary.copy().address("2001:db8::abcd/64", TEMPORARY | DEPRECATED)),
            "last preferred global IPv6 (temporary) deprecated rebuilds: link-local and IPv4 do not count");
        Link twoTemporary = base.copy().address("2001:db8::10/64", DEPRECATED).address("2001:db8::abcd/64", TEMPORARY);
        check(rebuild(twoTemporary, twoTemporary.copy().address("2001:db8::abcd/64", TEMPORARY | DEPRECATED)),
            "temporary deprecated while the other global IPv6 is already deprecated rebuilds");
        Link failedOther = base.copy().address("2001:db8::10/64", DADFAILED).address("2001:db8::abcd/64", TEMPORARY);
        check(rebuild(failedOther, failedOther.copy().address("2001:db8::abcd/64", TEMPORARY | DEPRECATED)),
            "temporary deprecated while the other global IPv6 failed DAD rebuilds");
        check(rebuild(withTemporary, withTemporary.copy().address("2001:db8::abcd/64", TEMPORARY | DADFAILED)),
            "temporary address failing DAD rebuilds");
        check(rebuild(base, base.copy().address("2001:db8:2::10/64", DEPRECATED)), "address added already deprecated rebuilds");
        check(rebuild(base, base.copy().address("2001:db8:2::10/64", DADFAILED)), "address added DAD-failed rebuilds");
        Link deprecated = base.copy().address("2001:db8::10/64", DEPRECATED);
        check(!rebuild(deprecated, deprecated.copy()), "already deprecated address unchanged keeps session");
        check(!rebuild(deprecated, base), "address preferred again keeps session");
        check(rebuild(deprecated, deprecated.copy().drop("2001:db8::10/64")), "deprecated address removed rebuilds");

        // Routes.
        check(rebuild(base, base.copy().dropRoute("0.0.0.0/0 192.0.2.1 wlan0")), "default route removed rebuilds");
        check(rebuild(base, base.copy().dropRoute("::/0 fe80::1 wlan0").route("::/0 fe80::2 wlan0", UNICAST)),
            "IPv6 default gateway changed rebuilds");
        check(rebuild(base, base.copy().route("2001:db8::/64 null wlan0", UNREACHABLE)), "route type changed rebuilds");
        check(rebuild(base, base.copy().route("2001:db8:ffff::/48 null wlan0", UNREACHABLE)), "unreachable route added rebuilds");
        Link restrictive = base.copy().route("2001:db8:ffff::/48 null wlan0", UNREACHABLE);
        check(!rebuild(restrictive, restrictive.copy().address("2001:db8::77/64", 0)), "existing unreachable route with SLAAC addition keeps session");
        Link oldApi = v4Only.copy().route("192.0.2.0/24 null wlan0", UNKNOWN);
        check(!rebuild(oldApi, oldApi.copy().route("2001:db8::/64 null wlan0", UNKNOWN)), "route addition with unknown type (API < 33) keeps session");

        // MTU.
        check(rebuild(base, base.copy().mtu(1280)), "MTU changed rebuilds");
        check(rebuild(base.copy().mtu(0), base), "MTU 0 -> value rebuilds");
        check(rebuild(base, base.copy().mtu(0)), "MTU becoming unknown rebuilds");

        // NAT64/CLAT: only on an IPv6-only link.
        check(!rebuild(base, base.copy().nat64("64:ff9b::/96").address("2001:db8::99/64", 0)),
            "dual-stack: PREF64 arriving with a SLAAC address keeps session");
        check(!rebuild(base.copy().nat64("64:ff9b::/96"), base), "dual-stack: NAT64 prefix removed keeps session");
        Link v6 = ipv6Only();
        check(rebuild(v6, v6.copy().nat64("2001:db8:64::/96")), "IPv6-only: NAT64 prefix changed rebuilds");
        check(rebuild(v6, v6.copy().nat64(null)), "IPv6-only: NAT64 prefix removed rebuilds");
        check(rebuild(v6.copy().nat64(null), v6), "IPv6-only: NAT64 prefix added rebuilds");
        check(!rebuild(v6, v6.copy().address("2001:db8::99/64", 0)), "IPv6-only: SLAAC addition with stable NAT64 keeps session");
        check(rebuild(v6, v6.copy().address("192.0.2.10/24", PERMANENT).nat64(null)), "IPv6-only gaining IPv4 rebuilds");

        // Interface and unknown state.
        check(rebuild(base, base.copy().iface("wlan1")), "interface renamed rebuilds");
        check(rebuild(base, base.copy().iface(null)), "unknown interface rebuilds");
        LinkChange.State known = base.state();
        check(LinkChange.requiresRebuild(null, known), "null baseline (no properties at connect) rebuilds");
        check(LinkChange.requiresRebuild(known, null), "null update rebuilds");
        check(LinkChange.requiresRebuild(known, new LinkChange.State("wlan0", null, NONE, NONE, NONE, NONE, NONE, 1500, null)), "unknown addresses rebuild");
        check(LinkChange.requiresRebuild(known, new LinkChange.State("wlan0", NONE, null, NONE, NONE, NONE, NONE, 1500, null)), "unknown deprecated rebuilds");
        check(LinkChange.requiresRebuild(known, new LinkChange.State("wlan0", NONE, NONE, null, NONE, NONE, NONE, 1500, null)), "unknown failed rebuilds");
        check(LinkChange.requiresRebuild(known, new LinkChange.State("wlan0", NONE, NONE, NONE, null, NONE, NONE, 1500, null)), "unknown temporary rebuilds");
        check(LinkChange.requiresRebuild(known, new LinkChange.State("wlan0", NONE, NONE, NONE, NONE, null, NONE, 1500, null)), "unknown routes rebuild");
        check(LinkChange.requiresRebuild(known, new LinkChange.State("wlan0", NONE, NONE, NONE, NONE, NONE, null, 1500, null)), "unknown restrictive rebuilds");
        check(LinkChange.requiresRebuild(known, new LinkChange.State("wlan0", list("192.0.2.10/24", "fe80::1/64", "2001:db8::10/64", null),
            NONE, NONE, NONE, known.routes, NONE, 1500, null)), "null address rebuilds");
        check(LinkChange.requiresRebuild(known, new LinkChange.State("wlan0", known.addresses, list((String) null), NONE, NONE, known.routes, NONE, 1500, null)),
            "null deprecated address rebuilds");
        System.out.println("PASS Android link-property rebuild regressions");
    }
}
