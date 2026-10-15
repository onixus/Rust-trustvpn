package org.rtrusttunnel.android;

import java.util.Collection;
import java.util.Objects;

/**
 * Decides whether a LinkProperties update on the current underlying network must rebuild the session.
 * Pure Java so the JVM regression test can exercise it. Fails toward rebuild on doubt.
 */
final class LinkChange {
    private LinkChange(){}

    /**
     * Session-relevant view of one LinkProperties snapshot. Addresses are "address/prefix"; IPv4 = address
     * part without ':'. Routes are opaque stable strings that include the route type when Android exposes it.
     * {@code unusable} lists addresses Android marked deprecated or DAD-failed; {@code restrictive} lists
     * routes that are not unicast (unreachable/throw). MTU 0 means unknown; nat64 is null when absent or unknown.
     */
    static final class State {
        final String iface;
        final Collection<String> addresses, unusable, routes, restrictive;
        final int mtu;
        final String nat64;
        State(String iface,Collection<String> addresses,Collection<String> unusable,Collection<String> routes,Collection<String> restrictive,int mtu,String nat64){
            this.iface=iface;this.addresses=addresses;this.unusable=unusable;this.routes=routes;this.restrictive=restrictive;this.mtu=mtu;this.nat64=nat64;
        }
        private boolean incomplete(){return iface==null || addresses==null || unusable==null || routes==null || restrictive==null;}
    }

    static boolean requiresRebuild(State before,State after){
        if(before==null || after==null || before.incomplete() || after.incomplete())return true;
        if(!Objects.equals(before.iface,after.iface))return true;
        // Packet size and NAT64/CLAT translation apply to the established session's own traffic.
        if(before.mtu!=after.mtu || !Objects.equals(before.nat64,after.nat64))return true;
        // A removed or changed address or route (gateway, type) may be what the established session uses.
        if(!after.addresses.containsAll(before.addresses) || !after.routes.containsAll(before.routes))return true;
        // IPv4 link addresses feed managed-routing local prefixes; IPv6 additions (SLAAC) do not.
        for(String address:after.addresses){if(address==null)return true;if(!before.addresses.contains(address) && address.split("/",2)[0].indexOf(':')<0)return true;}
        // An address that stops being preferred (prefix rotation, preferred_lifetime=0) may be the session's source.
        for(String address:after.unusable)if(address==null || !before.unusable.contains(address))return true;
        // A new unreachable/throw route can blackhole the endpoint even though nothing was removed.
        for(String route:after.restrictive)if(route==null || !before.restrictive.contains(route))return true;
        return false;
    }
}
