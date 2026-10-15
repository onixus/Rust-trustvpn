package org.rtrusttunnel.android;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
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
     * {@code deprecated}, {@code failed} and {@code temporary} list addresses with those kernel flags;
     * {@code restrictive} lists routes that are not unicast (unreachable/throw). MTU 0 means unknown;
     * nat64 is null when absent or unknown.
     */
    static final class State {
        final String iface;
        final Collection<String> addresses, deprecated, failed, temporary, routes, restrictive;
        final int mtu;
        final String nat64;
        State(String iface,Collection<String> addresses,Collection<String> deprecated,Collection<String> failed,Collection<String> temporary,Collection<String> routes,Collection<String> restrictive,int mtu,String nat64){
            this.iface=iface;this.addresses=addresses;this.deprecated=deprecated;this.failed=failed;this.temporary=temporary;this.routes=routes;this.restrictive=restrictive;this.mtu=mtu;this.nat64=nat64;
        }
        private boolean incomplete(){return iface==null || addresses==null || deprecated==null || failed==null || temporary==null || routes==null || restrictive==null;}
    }

    /**
     * Maps raw LinkAddress flags and RouteInfo types to a State. Flag masks and the unicast type are passed in
     * (OsConstants/RouteInfo on Android) so the mapping stays testable on a plain JVM. Route type below 0 = unknown.
     */
    static final class Builder {
        private final String iface, nat64;
        private final int mtu, temporaryFlag, deprecatedFlag, failedFlag, unicastType;
        private final List<String> addresses=new ArrayList<>(), deprecated=new ArrayList<>(), failed=new ArrayList<>(), temporary=new ArrayList<>(), routes=new ArrayList<>(), restrictive=new ArrayList<>();
        Builder(String iface,int mtu,String nat64,int temporaryFlag,int deprecatedFlag,int failedFlag,int unicastType){
            this.iface=iface;this.mtu=mtu;this.nat64=nat64;this.temporaryFlag=temporaryFlag;this.deprecatedFlag=deprecatedFlag;this.failedFlag=failedFlag;this.unicastType=unicastType;
        }
        Builder address(String address,int flags){
            addresses.add(address);
            if((flags & deprecatedFlag)!=0)deprecated.add(address);
            if((flags & failedFlag)!=0)failed.add(address);
            if((flags & temporaryFlag)!=0)temporary.add(address);
            return this;
        }
        Builder route(String route,int type){
            String key=route+" "+(type<0?-1:type);routes.add(key);
            if(type>=0 && type!=unicastType)restrictive.add(key);
            return this;
        }
        State build(){return new State(iface,addresses,deprecated,failed,temporary,routes,restrictive,mtu,nat64);}
    }

    static boolean requiresRebuild(State before,State after){
        if(before==null || after==null || before.incomplete() || after.incomplete())return true;
        if(!Objects.equals(before.iface,after.iface))return true;
        // Packet size applies to the established session's own traffic.
        if(before.mtu!=after.mtu)return true;
        // NAT64/CLAT matters only on an IPv6-only link; on dual-stack a late PREF64 must not tear the session (#75).
        if(!hasIpv4(before) && !hasIpv4(after) && !Objects.equals(before.nat64,after.nat64))return true;
        // A removed or changed address or route (gateway, type) may be what the established session uses.
        if(!after.addresses.containsAll(before.addresses) || !after.routes.containsAll(before.routes))return true;
        // IPv4 link addresses feed managed-routing local prefixes; IPv6 additions (SLAAC) do not.
        for(String address:after.addresses){if(address==null)return true;if(!before.addresses.contains(address) && !isIpv6(address))return true;}
        for(String address:after.failed)if(address==null || !before.failed.contains(address))return true;
        // An address that stops being preferred may be the session's source. A deprecated RFC 4941 temporary
        // address is routine rotation and is tolerated while another preferred global address of its family remains.
        for(String address:after.deprecated){
            if(address==null)return true;
            if(before.deprecated.contains(address))continue;
            if(!after.temporary.contains(address) || !hasPreferredGlobal(after,isIpv6(address)))return true;
        }
        // A new unreachable/throw route can blackhole the endpoint even though nothing was removed.
        for(String route:after.restrictive)if(route==null || !before.restrictive.contains(route))return true;
        return false;
    }
    private static boolean isIpv6(String address){return address.split("/",2)[0].indexOf(':')>=0;}
    private static boolean hasIpv4(State state){for(String address:state.addresses)if(address!=null && !isIpv6(address))return true;return false;}
    private static boolean hasPreferredGlobal(State state,boolean ipv6){
        for(String address:state.addresses)
            if(address!=null && isIpv6(address)==ipv6 && !state.deprecated.contains(address) && !state.failed.contains(address) && isGlobal(address))return true;
        return false;
    }
    /** Literal parsing only (no DNS): the host part is a numeric address taken from LinkAddress. */
    private static boolean isGlobal(String address){
        String host=address.split("/",2)[0];
        if(host.indexOf(':')<0 && !host.matches("[0-9]+(\\.[0-9]+){3}"))return false;
        try{InetAddress ip=InetAddress.getByName(host);return !(ip.isLinkLocalAddress() || ip.isLoopbackAddress() || ip.isAnyLocalAddress() || ip.isMulticastAddress());}
        catch(Exception error){return false;}
    }
}
