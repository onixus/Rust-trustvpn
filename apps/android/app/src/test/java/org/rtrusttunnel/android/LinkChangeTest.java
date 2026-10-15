package org.rtrusttunnel.android;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** LinkProperties updates on the same underlying network that must or must not rebuild the session. */
public final class LinkChangeTest {
    private static final List<String> NONE = Collections.<String>emptyList();
    private static final List<String> ADDRESSES = list("192.0.2.10/24", "fe80::1/64", "2001:db8::10/64");
    private static final List<String> ROUTES = list("192.0.2.0/24 null wlan0 1", "0.0.0.0/0 192.0.2.1 wlan0 1",
        "fe80::/64 null wlan0 1", "2001:db8::/64 null wlan0 1", "::/0 fe80::1 wlan0 1");

    private static void check(boolean value, String label) {
        if (!value) throw new AssertionError(label);
    }
    private static List<String> list(String... values) {
        return Arrays.asList(values);
    }
    private static List<String> with(java.util.Collection<String> base, String... extra) {
        List<String> result = new java.util.ArrayList<>(base);
        result.addAll(Arrays.asList(extra));
        return result;
    }
    private static List<String> without(java.util.Collection<String> base, String... removed) {
        List<String> result = new java.util.ArrayList<>(base);
        result.removeAll(Arrays.asList(removed));
        return result;
    }
    private static LinkChange.State state(java.util.Collection<String> addresses, java.util.Collection<String> routes) {
        return new LinkChange.State("wlan0", addresses, NONE, routes, NONE, 1500, null);
    }
    private static boolean rebuild(LinkChange.State before, LinkChange.State after) {
        return LinkChange.requiresRebuild(before, after);
    }
    public static void main(String[] args) {
        LinkChange.State base = state(ADDRESSES, ROUTES);
        check(!rebuild(base, state(ADDRESSES, ROUTES)), "identical properties keep session");

        // #75 behaviour that must stay: SLAAC additions alone keep the session.
        LinkChange.State v4Only = state(list("192.0.2.10/24", "fe80::1/64"),
            list("192.0.2.0/24 null wlan0 1", "0.0.0.0/0 192.0.2.1 wlan0 1", "fe80::/64 null wlan0 1"));
        check(!rebuild(v4Only, state(list("192.0.2.10/24", "fe80::1/64", "2001:db8::10/64"), v4Only.routes)),
            "IPv6 SLAAC address added keeps session");
        check(!rebuild(v4Only, state(v4Only.addresses, with(v4Only.routes,
            "2001:db8::/64 null wlan0 1", "::/0 fe80::1 wlan0 1"))), "IPv6 prefix and default route added keep session");
        check(!rebuild(new LinkChange.State("wlan0", NONE, NONE, NONE, NONE, 0, null),
            new LinkChange.State("wlan0", list("2001:db8::10/64"), NONE, NONE, NONE, 0, null)),
            "IPv6-only addition from empty keeps session");
        check(!rebuild(base, state(with(ADDRESSES, "2001:db8::abcd/64"), ROUTES)),
            "RFC 4941 temporary IPv6 address added keeps session");

        // Address changes.
        check(rebuild(base, state(list("192.0.2.11/24", "fe80::1/64", "2001:db8::10/64"), ROUTES)),
            "IPv4 address changed rebuilds");
        check(rebuild(base, state(with(ADDRESSES, "198.51.100.5/24"), ROUTES)), "IPv4 address added rebuilds");
        check(rebuild(base, state(without(ADDRESSES, "2001:db8::10/64"), ROUTES)), "IPv6 address removed rebuilds");
        check(rebuild(base, state(without(with(ADDRESSES, "2001:db8:1::10/64"), "192.0.2.10/24"), ROUTES)),
            "IPv6 added while IPv4 removed rebuilds");
        check(rebuild(state(with(ADDRESSES, "2001:db8::abcd/64"), ROUTES), base),
            "unused temporary IPv6 address removed still rebuilds (defensive)");

        // Deprecated / unusable addresses (prefix rotation, preferred_lifetime=0, DAD failure).
        check(rebuild(base, new LinkChange.State("wlan0", ADDRESSES, list("2001:db8::10/64"), ROUTES, NONE, 1500, null)),
            "address turning deprecated rebuilds");
        check(rebuild(base, new LinkChange.State("wlan0", with(ADDRESSES, "2001:db8:2::10/64"),
            list("2001:db8:2::10/64"), ROUTES, NONE, 1500, null)), "address added already unusable rebuilds");
        LinkChange.State deprecated = new LinkChange.State("wlan0", ADDRESSES, list("2001:db8::10/64"), ROUTES, NONE, 1500, null);
        check(!rebuild(deprecated, deprecated), "already deprecated address unchanged keeps session");
        check(rebuild(deprecated, state(without(ADDRESSES, "2001:db8::10/64"), ROUTES)), "deprecated address removed rebuilds");
        check(rebuild(base, new LinkChange.State("wlan0", ADDRESSES, list((String) null), ROUTES, NONE, 1500, null)),
            "null unusable address rebuilds");

        // Routes.
        check(rebuild(base, state(ADDRESSES, without(ROUTES, "0.0.0.0/0 192.0.2.1 wlan0 1"))), "default route removed rebuilds");
        check(rebuild(base, state(ADDRESSES, with(without(ROUTES, "::/0 fe80::1 wlan0 1"), "::/0 fe80::2 wlan0 1"))),
            "IPv6 default gateway changed rebuilds");
        check(rebuild(base, state(ADDRESSES, with(without(ROUTES, "2001:db8::/64 null wlan0 1"), "2001:db8::/64 null wlan0 7"))),
            "route type changed rebuilds");
        List<String> unreachable = list("2001:db8:ffff::/48 null wlan0 7");
        check(rebuild(base, new LinkChange.State("wlan0", ADDRESSES, NONE, with(ROUTES, unreachable.get(0)), unreachable, 1500, null)),
            "unreachable route added rebuilds");
        LinkChange.State restrictive = new LinkChange.State("wlan0", ADDRESSES, NONE, with(ROUTES, unreachable.get(0)), unreachable, 1500, null);
        check(!rebuild(restrictive, new LinkChange.State("wlan0", with(ADDRESSES, "2001:db8::77/64"), NONE,
            with(ROUTES, unreachable.get(0)), unreachable, 1500, null)), "existing unreachable route with SLAAC addition keeps session");
        check(!rebuild(state(ADDRESSES, list("::/0 fe80::1 wlan0 -1")), state(ADDRESSES, list("::/0 fe80::1 wlan0 -1", "2001:db8::/64 null wlan0 -1"))),
            "route addition with unknown type (API < 33) keeps session");

        // MTU and NAT64/CLAT.
        check(rebuild(base, new LinkChange.State("wlan0", ADDRESSES, NONE, ROUTES, NONE, 1280, null)), "MTU changed rebuilds");
        check(rebuild(base, new LinkChange.State("wlan0", ADDRESSES, NONE, ROUTES, NONE, 0, null)), "MTU becoming unknown rebuilds");
        check(rebuild(base, new LinkChange.State("wlan0", ADDRESSES, NONE, ROUTES, NONE, 1500, "64:ff9b::/96")), "NAT64 prefix added rebuilds");
        LinkChange.State nat64 = new LinkChange.State("wlan0", ADDRESSES, NONE, ROUTES, NONE, 1500, "64:ff9b::/96");
        check(rebuild(nat64, base), "NAT64 prefix removed rebuilds");
        check(rebuild(nat64, new LinkChange.State("wlan0", ADDRESSES, NONE, ROUTES, NONE, 1500, "2001:db8:64::/96")),
            "NAT64 prefix changed rebuilds");
        check(!rebuild(nat64, new LinkChange.State("wlan0", with(ADDRESSES, "2001:db8::99/64"), NONE, ROUTES, NONE, 1500, "64:ff9b::/96")),
            "SLAAC addition with stable NAT64 keeps session");

        // Interface and unknown state.
        check(rebuild(base, new LinkChange.State("wlan1", ADDRESSES, NONE, ROUTES, NONE, 1500, null)), "interface renamed rebuilds");
        check(rebuild(null, base), "null baseline (no properties at connect) rebuilds");
        check(rebuild(base, null), "null update rebuilds");
        check(rebuild(new LinkChange.State(null, ADDRESSES, NONE, ROUTES, NONE, 1500, null), base), "unknown interface rebuilds");
        check(rebuild(base, new LinkChange.State("wlan0", null, NONE, ROUTES, NONE, 1500, null)), "unknown addresses rebuild");
        check(rebuild(base, new LinkChange.State("wlan0", ADDRESSES, NONE, null, NONE, 1500, null)), "unknown routes rebuild");
        check(rebuild(base, new LinkChange.State("wlan0", ADDRESSES, null, ROUTES, NONE, 1500, null)), "unknown unusable rebuilds");
        check(rebuild(base, new LinkChange.State("wlan0", ADDRESSES, NONE, ROUTES, null, 1500, null)), "unknown restrictive rebuilds");
        check(rebuild(base, state(with(ADDRESSES, (String) null), ROUTES)), "null address rebuilds");
        System.out.println("PASS Android link-property rebuild regressions");
    }
}
