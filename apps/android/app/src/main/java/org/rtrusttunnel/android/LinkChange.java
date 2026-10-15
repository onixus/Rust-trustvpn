package org.rtrusttunnel.android;

import java.util.Collection;
import java.util.Objects;

/**
 * Decides whether a LinkProperties update on the current underlying network must rebuild the session.
 * Pure Java so the JVM regression test can exercise it. Fails toward rebuild on doubt.
 */
final class LinkChange {
    private LinkChange(){}
    /** Addresses are "address/prefix"; routes are opaque stable strings. IPv4 = address part without ':'. */
    static boolean requiresRebuild(String ifaceBefore,Collection<String> addressesBefore,Collection<String> routesBefore,String ifaceAfter,Collection<String> addressesAfter,Collection<String> routesAfter){
        if(ifaceBefore==null || ifaceAfter==null || addressesBefore==null || addressesAfter==null || routesBefore==null || routesAfter==null)return true;
        if(!Objects.equals(ifaceBefore,ifaceAfter))return true;
        // A removed address or route may be what the established session uses.
        if(!addressesAfter.containsAll(addressesBefore) || !routesAfter.containsAll(routesBefore))return true;
        // IPv4 link addresses feed managed-routing local prefixes; IPv6 additions (SLAAC) do not.
        for(String address:addressesAfter){if(address==null)return true;if(!addressesBefore.contains(address) && address.split("/",2)[0].indexOf(':')<0)return true;}
        return false;
    }
}
