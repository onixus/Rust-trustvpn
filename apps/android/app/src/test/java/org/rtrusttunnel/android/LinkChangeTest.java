package org.rtrusttunnel.android;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** LinkProperties updates on the same underlying network that must or must not rebuild the session. */
public final class LinkChangeTest {
    private static void check(boolean value, String label) {
        if (!value) throw new AssertionError(label);
    }
    private static List<String> list(String... values) {
        return Arrays.asList(values);
    }
    public static void main(String[] args) {
        List<String> addresses = list("192.0.2.10/24", "fe80::1/64");
        List<String> routes = list("192.0.2.0/24 null wlan0", "0.0.0.0/0 192.0.2.1 wlan0", "fe80::/64 null wlan0");
        check(!LinkChange.requiresRebuild("wlan0", addresses, routes, "wlan0", addresses, routes),
            "identical properties keep session");
        check(!LinkChange.requiresRebuild("wlan0", addresses, routes, "wlan0",
            list("192.0.2.10/24", "fe80::1/64", "2001:db8::10/64"), routes),
            "IPv6 SLAAC address added keeps session");
        check(!LinkChange.requiresRebuild("wlan0", addresses, routes, "wlan0", addresses,
            list("192.0.2.0/24 null wlan0", "0.0.0.0/0 192.0.2.1 wlan0", "fe80::/64 null wlan0",
                "2001:db8::/64 null wlan0", "::/0 fe80::1 wlan0")),
            "IPv6 prefix and default route added keep session");
        check(LinkChange.requiresRebuild("wlan0", addresses, routes, "wlan0",
            list("192.0.2.11/24", "fe80::1/64"), routes), "IPv4 address changed rebuilds");
        check(LinkChange.requiresRebuild("wlan0", addresses, routes, "wlan0",
            list("192.0.2.10/24", "fe80::1/64", "198.51.100.5/24"), routes), "IPv4 address added rebuilds");
        check(LinkChange.requiresRebuild("wlan0", list("192.0.2.10/24", "fe80::1/64", "2001:db8::10/64"), routes,
            "wlan0", addresses, routes), "IPv6 address removed rebuilds");
        check(LinkChange.requiresRebuild("wlan0", addresses, routes, "wlan0", addresses,
            list("192.0.2.0/24 null wlan0", "fe80::/64 null wlan0")), "default route removed rebuilds");
        check(LinkChange.requiresRebuild("wlan0", addresses, routes, "wlan1", addresses, routes),
            "interface renamed rebuilds");
        check(LinkChange.requiresRebuild(null, addresses, routes, "wlan0", addresses, routes), "unknown before rebuilds");
        check(LinkChange.requiresRebuild("wlan0", addresses, routes, "wlan0", null, routes), "unknown after rebuilds");
        check(LinkChange.requiresRebuild("wlan0", addresses, null, "wlan0", addresses, routes), "unknown routes rebuild");
        check(LinkChange.requiresRebuild("wlan0", addresses, routes, "wlan0",
            list("192.0.2.10/24", "fe80::1/64", null), routes), "null address rebuilds");
        check(!LinkChange.requiresRebuild("wlan0", Collections.<String>emptyList(), Collections.<String>emptyList(),
            "wlan0", list("2001:db8::10/64"), Collections.<String>emptyList()), "IPv6-only addition from empty keeps session");
        System.out.println("PASS Android link-property rebuild regressions");
    }
}
