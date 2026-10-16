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
    /** Reconnect only while this app is still the system Always-on VPN; see alwaysOnSessionLost. */
    static final String RECOVER = "org.rtrusttunnel.android.RECOVER";
    private static final String STATE = "tunnel", ALWAYS_ON_SESSION = "always_on_session", INHERIT_METERING = "inherit_metering";
    static volatile String problem = "";
    static volatile boolean active;
    static volatile boolean alwaysOn, lockdown;
    // One process-wide native adapter: old onDestroy cleanup must finish before a
    // new service instance can start it. Tasks are bounded by lifecycle/refresh gates.
    private static final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final TunnelLifecycle lifecycle = new TunnelLifecycle();
    private volatile Network underlying;
    /** LinkProperties of {@link #underlying} the session was last checked against; guarded by networkEvents. */
    private LinkProperties linkProperties;
    private ParcelFileDescriptor tun;
    private ConnectivityManager connectivity;
    private final Object networkEvents = new Object();
    private final DeepSleepObserver sleepObserver = new DeepSleepObserver();
    private volatile ConnectivityManager.NetworkCallback callback;
    private volatile boolean stopping, recovering;
    private boolean cleaned;
    private volatile long lifecycleEpoch;
    private final Handler widgetHandler = new Handler(Looper.getMainLooper());
    private final Runnable widgetPoll = new Runnable() {
        // Always-on is switched in system Settings while the app UI is usually closed: record it
        // here too, or a session that loses its process is not recovered when the app next runs.
        public void run() { refreshPolicy(); pollAccess(); observeDeepSleep(); VpnWidget.refresh(TunnelService.this, false); widgetHandler.postDelayed(this, 1000); }
    };
    private void observeDeepSleep() {
        synchronized (networkEvents) {
            if (callback == null || stopping) return;
            long before = SystemClock.uptimeMillis();
            long elapsed = SystemClock.elapsedRealtime();
            long after = SystemClock.uptimeMillis();
            if (sleepObserver.sample(callback, elapsed, before, after)) NativeCore.INSTANCE.resumed();
        }
    }
    private static volatile TunnelService running;
    static void refreshPolicy() {
        TunnelService service = running;
        if (service == null) return;
        boolean previous = alwaysOn;
        alwaysOn = service.isAlwaysOn(); lockdown = service.isLockdownEnabled();
        if (previous == alwaysOn || !active) return;
        rememberAlwaysOn(service, alwaysOn);
        service.getSystemService(NotificationManager.class).notify(1, service.notification());
    }

    /**
     * Android does not restart this service after its process dies: the dead TUN makes the
     * system Vpn unbind first, which detaches the service record before process cleanup could
     * schedule a sticky restart, and crashes are additionally cleaned up without restart.
     * Always-on is only re-applied on boot/unlock, setting changes and package updates.
     * Lockdown keeps blocking meanwhile; this marker lets the app reconnect when it next runs.
     * It cannot tell whether Always-on was turned off since: RECOVER re-checks after establish.
     */
    static boolean alwaysOnSessionLost(Context context) {
        return !active && context.getSharedPreferences(STATE, MODE_PRIVATE).getBoolean(ALWAYS_ON_SESSION, false);
    }
    /** Android treats a VPN as metered unless it opts out. The opt-out makes the VPN
     *  follow its underlying network: unmetered over Wi-Fi, metered over mobile data. */
    static boolean inheritMetering(Context context) {
        return context.getSharedPreferences(STATE, MODE_PRIVATE).getBoolean(INHERIT_METERING, false);
    }
    /** Android fixes metering when it registers the VPN network and updates a re-established
     *  TUN in place, so this applies from the next connection. Reconnecting here would open
     *  a window without the tunnel. */
    static void setInheritMetering(Context context, boolean value) {
        context.getSharedPreferences(STATE, MODE_PRIVATE).edit().putBoolean(INHERIT_METERING, value).apply();
    }
    private static void rememberAlwaysOn(Context context, boolean value) {
        context.getSharedPreferences(STATE, MODE_PRIVATE).edit().putBoolean(ALWAYS_ON_SESSION, value).apply();
    }

    @Override public void onCreate() {
        super.onCreate(); widgetHandler.post(widgetPoll); running = this; connectivity = getSystemService(ConnectivityManager.class);
        getSystemService(NotificationManager.class).createNotificationChannel(new NotificationChannel("vpn", getString(R.string.vpn_connection), NotificationManager.IMPORTANCE_LOW));
    }
    private Notification notification() {
        PendingIntent open = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        PendingIntent stop = PendingIntent.getService(this, 1, new Intent(this, TunnelService.class).setAction(STOP), PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        Notification.Builder notification = new Notification.Builder(this, "vpn").setSmallIcon(R.drawable.ic_flow_notification)
            .setContentTitle("R-TrustTunnel").setContentText(getString(R.string.vpn_active_open_app_for_connection))
            .setContentIntent(open).setOngoing(true);
        if (!isAlwaysOn()) notification.addAction(new Notification.Action.Builder(null, getString(R.string.disconnect), stop).build());
        return notification.build();
    }
    static final String PROFILE_ID = "org.rtrusttunnel.android.PROFILE_ID";
    @Override public int onStartCommand(Intent intent, int flags, int id) {
        alwaysOn = isAlwaysOn(); lockdown = isLockdownEnabled();
        boolean stopIntent = intent != null && STOP.equals(intent.getAction());
        if (stopIntent && !alwaysOn) {
            rememberAlwaysOn(this, false);
            if (lifecycle.stop(id)) scheduleDisconnect();
            return START_NOT_STICKY;
        }
        // Always-on refuses STOP; it must not replace a queued START's profile.
        if (stopIntent && lifecycle.acknowledgeIfBusy(id)) return START_STICKY;
        TunnelLifecycle.Start request = new TunnelLifecycle.Start(id,
            intent == null ? null : intent.getStringExtra(PROFILE_ID),
            intent != null && RECOVER.equals(intent.getAction()));
        if (lifecycle.start(request)) return beginConnection(request) ? START_STICKY : START_NOT_STICKY;
        return START_STICKY;
    }
    /** Runs on the main looper, including restart after the previous worker joins. */
    private boolean beginConnection(TunnelLifecycle.Start request) {
        stopping = false; cleaned = false; recovering = request.recover;
        final long session = ++lifecycleEpoch;
        transitioning = true; accessHeld = false; localPolicy = false; localSource = false;
        requestedId = request.profileId; receiptKey = ""; policyKey = ""; adapterKey = "";
        logicalSession = System.nanoTime() & Long.MAX_VALUE;
        networkEpoch++; lastWall = 0; clockInvalid = false;
        if (VpnService.prepare(this) != null) {
            rememberAlwaysOn(this, false); problem = getString(R.string.vpn_permission_is_required);
            disconnect(); return false;
        }
        if (Build.VERSION.SDK_INT >= 34) startForeground(1, notification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED);
        else startForeground(1, notification());
        active = true; problem = "";
        worker.execute(() -> {
            try { if (!stopping && session == lifecycleEpoch) connect(request.profileId); }
            catch (Exception error) {
                if (stopping || session != lifecycleEpoch) return;
                // Never include config, addresses or exception payloads in UI/logs.
                problem = getString(R.string.cannot_start_vpn_check_the_profile);
                if (tun != null) { transitioning = true; return; }
                finishFailure();
            }
        });
        return true;
    }
    private Network availableNetwork() { return availableNetwork(null); }
    /** {@code lost} is skipped: getAllNetworks can still list a network while its onLost runs. */
    private Network availableNetwork(Network lost) {
        Network best = null; int bestRank = -1;
        for (Network network : connectivity.getAllNetworks()) {
            if (network.equals(lost)) continue;
            NetworkCapabilities caps = connectivity.getNetworkCapabilities(network);
            // Only a foreground network accepts sockets from an ordinary app: a background
            // one (e.g. mobile data kept up next to Wi-Fi) rejects bindSocket with EPERM.
            if (caps != null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_FOREGROUND)) {
                int rank = preference(caps);
                if (rank > bestRank) { best = network; bestRank = rank; }
            }
        }
        return best;
    }
    /** Mobile data can stay foreground next to Wi-Fi (e.g. for an MMS or carrier request),
     *  and getAllNetworks has no order. Prefer what Android makes the default network:
     *  validated, then unmetered, then not cellular. */
    static int preference(NetworkCapabilities caps) {
        return (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) ? 4 : 0)
            + (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) ? 2 : 0)
            + (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ? 0 : 1);
    }
    private volatile boolean localPolicy;
    private volatile boolean localSource;
    public boolean allowPolicyMutation() { return localPolicy && !stopping; }
    public boolean hasLocalSource() { return localSource; }
    private volatile boolean transitioning, accessHeld;
    private volatile java.util.List<ProfileVault.Selection> candidates=java.util.Collections.emptyList();
    private final java.util.concurrent.atomic.AtomicBoolean refreshQueued=new java.util.concurrent.atomic.AtomicBoolean();
    private volatile long logicalSession=System.nanoTime() & Long.MAX_VALUE;
    private volatile long networkEpoch, lastWall;
    private volatile boolean clockInvalid;
    private volatile String requestedId, receiptKey="", policyKey="";
    private String adapterKey="";
    private boolean meteringInherited;
    private int boot;
    /** Primary profile requested by the running service, for display only; null when stopped.
     *  It is set before the tunnel connects, so callers must also check the connection state. */
    static String connectedProfileId(){TunnelService s=running;return s!=null && active?s.requestedId:null;}
    static boolean accessBlocked(){TunnelService s=running;return s!=null && s.accessHeld;}
    static Network portalRecoveryNetwork(){TunnelService s=running;return s!=null && s.accessHeld && !s.stopping?s.underlying:null;}
    static void recoverySettingsChanged(){TunnelService s=running;if(s!=null)synchronized(s.networkEvents){s.logicalSession=System.nanoTime() & Long.MAX_VALUE;s.networkEpoch++;s.transitioning=true;s.requestRefresh();}}
    public synchronized boolean accessValid() {
        if(stopping || transitioning || accessHeld) return false;
        long wall=System.currentTimeMillis(),elapsed=SystemClock.elapsedRealtime();
        boolean managed=false;for(ProfileVault.Selection entry:candidates)if(!entry.localPolicy)managed=true;
        if(!managed)return true;
        if(lastWall>0 && wall<lastWall)clockInvalid=true;
        if(clockInvalid)return false;
        lastWall=wall;
        for(ProfileVault.Selection entry:candidates)if(!entry.localPolicy && !OfflineLease.valid(entry.lease,wall,elapsed,boot))return false;
        return true;
    }
    private static String receipts(ProfileVault.ConnectionSet set)throws Exception {
        JSONArray values=new JSONArray();for(ProfileVault.Selection entry:set.profiles)values.put(new JSONObject().put("id",entry.id).put("revision",entry.revision).put("lease",entry.lease).put("group",entry.managedRouting));
        return values.toString();
    }
    private static String policies(ProfileVault.ConnectionSet set)throws Exception {
        JSONArray values=new JSONArray();for(ProfileVault.Selection entry:set.profiles)values.put(new JSONObject().put("id",entry.id).put("revision",entry.revision).put("group",entry.managedRouting));
        return new JSONObject().put("profiles",values).put("apps",set.apps.json()).toString();
    }
    private void pollAccess(){
        if(stopping || !active || candidates.isEmpty())return;
        if(!transitioning && !accessValid()){transitioning=true;accessHeld=true;problem=getString(R.string.access_refresh_required);requestRefresh();}
        try{
            ProfileVault.ConnectionSet next=new ProfileVault(this).connectionSet(requestedId);String key=receipts(next);
            if(!key.equals(receiptKey)){
                boolean fresh=true;for(ProfileVault.Selection entry:next.profiles)if(!entry.localPolicy && !OfflineLease.valid(entry.lease,System.currentTimeMillis(),SystemClock.elapsedRealtime(),boot))fresh=false;
                if(!accessHeld && !transitioning && fresh && policies(next).equals(policyKey)){synchronized(this){candidates=java.util.Collections.unmodifiableList(next.profiles);receiptKey=key;lastWall=System.currentTimeMillis();clockInvalid=false;}}
                else requestRefresh();
            }
        }catch(Exception invalid){transitioning=true;requestRefresh();}
    }
    private void requestRefresh(){
        if(stopping || lifecycle.destroyed() || !refreshQueued.compareAndSet(false,true))return;
        final long session = lifecycleEpoch;
        worker.execute(()->{
            long epoch=networkEpoch;
            try{if(!stopping && session==lifecycleEpoch)rebuild(epoch);}catch(Exception error){if(!stopping && session==lifecycleEpoch){problem=getString(R.string.cannot_start_vpn_check_the_profile);transitioning=true;}}
            finally{refreshQueued.set(false);if(!stopping && session==lifecycleEpoch && epoch!=networkEpoch)requestRefresh();}
        });
    }
    private void connect(String profileId)throws Exception {
        requestedId=profileId;boot=OfflineLease.boot(this);meteringInherited=inheritMetering(this);
        callback=new ConnectivityManager.NetworkCallback(){
            private void changed(){changed(null);}
            private void changed(Network lost){synchronized(networkEvents){if(callback!=this || stopping)return;trackUnderlying(availableNetwork(lost));
                // A retained TUN keeps the network declared at establish. Redeclare at once:
                // the rebuild may wait for the old session to stop. Before establish this is a no-op.
                setUnderlyingNetworks(underlyingNetworks());networkEpoch++;transitioning=true;NativeCore.INSTANCE.networkChanged();requestRefresh();}}
            @Override public void onAvailable(Network n){if(!java.util.Objects.equals(underlying,availableNetwork()))changed();}
            @Override public void onLost(Network n){if(n.equals(underlying))changed(n);}
            @Override public void onCapabilitiesChanged(Network n,NetworkCapabilities caps){if(!java.util.Objects.equals(underlying,availableNetwork()))changed();}
            // IPv6 SLAAC additions after a handoff must not tear down the just-connected session.
            // Compared with the latest state: changed() stores it, so a queued older callback must not read as a removal.
            @Override public void onLinkPropertiesChanged(Network n,LinkProperties next){synchronized(networkEvents){if(callback!=this || stopping || !n.equals(underlying))return;
                LinkProperties latest=connectivity.getLinkProperties(n);if(latest==null)latest=next;if(java.util.Objects.equals(linkProperties,latest))return;
                if(LinkChange.requiresRebuild(linkState(linkProperties),linkState(latest)))changed();else linkProperties=latest;}}
        };
        connectivity.registerNetworkCallback(new NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).addCapability(NetworkCapabilities.NET_CAPABILITY_FOREGROUND).build(),callback);
        // Baseline for onLinkPropertiesChanged: without it the first update after connect reads as unknown and rebuilds.
        synchronized(networkEvents){trackUnderlying(availableNetwork());}
        rebuild(networkEpoch);
        synchronized(networkEvents){if(callback!=null && !stopping)sleepObserver.start(callback);}
    }
    /** Caller holds networkEvents: underlying and its baseline LinkProperties change together. */
    private void trackUnderlying(Network network){underlying=network;linkProperties=network==null?null:connectivity.getLinkProperties(network);}
    /** Linux RTN_UNICAST, the value of RouteInfo.RTN_UNICAST (public only from API 33; types are read only there). */
    private static final int RTN_UNICAST=1;
    /** Public API only: stacked (CLAT) links are hidden, so NAT64 prefix (API 30+) stands in for them. */
    private static LinkChange.State linkState(LinkProperties p){
        if(p==null)return null;
        IpPrefix nat64=Build.VERSION.SDK_INT>=30?p.getNat64Prefix():null;
        LinkChange.Builder state=new LinkChange.Builder(p.getInterfaceName(),p.getMtu(),nat64==null?null:nat64.toString(),
            android.system.OsConstants.IFA_F_TEMPORARY,android.system.OsConstants.IFA_F_DEPRECATED,android.system.OsConstants.IFA_F_DADFAILED,RTN_UNICAST);
        for(LinkAddress link:p.getLinkAddresses())state.address(link.getAddress().getHostAddress()+"/"+link.getPrefixLength(),link.getFlags());
        for(RouteInfo route:p.getRoutes())state.route(route.getDestination()+" "+route.getGateway()+" "+route.getInterface(),Build.VERSION.SDK_INT>=33?route.getType():-1);
        return state.build();
    }
    private JSONArray localPrefixes(Network network)throws Exception {
        LinkProperties properties=network==null?null:connectivity.getLinkProperties(network);if(properties==null)return null;
        JSONArray result=new JSONArray();for(LinkAddress link:properties.getLinkAddresses())if(link.getAddress() instanceof Inet4Address){if(link.getPrefixLength()==0)return null;result.put(link.getAddress().getHostAddress()+"/"+link.getPrefixLength());if(result.length()>64)throw new IllegalArgumentException("Local prefix limit");}return result;
    }
    /** Android derives the VPN's transports, bandwidth and roaming state from this declaration. */
    private Network[] underlyingNetworks(){Network network=underlying;return network==null?new Network[]{}:new Network[]{network};}
    private ParcelFileDescriptor establish(JSONObject plan,AppRouting apps,boolean guard)throws Exception {
        Builder builder=new Builder().setSession("R-TrustTunnel").setMtu(plan.getInt("mtu")).addAddress("169.254.254.2",32).setBlocking(false)
            .setUnderlyingNetworks(underlyingNetworks()).setMetered(!meteringInherited);
        if(guard || plan.getBoolean("ipv6"))builder.addAddress("fd00:5254::2",128);
        if(guard){builder.addRoute("0.0.0.0",0).addRoute("::",0);}else{JSONArray routes=plan.getJSONArray("routes");for(int i=0;i<routes.length();i++){String[] route=routes.getString(i).split("/");builder.addRoute(route[0],Integer.parseInt(route[1]));}}
        apps.apply(builder,getPackageManager());JSONArray dns=plan.getJSONArray("dns");for(int i=0;i<dns.length();i++)builder.addDnsServer(dns.getString(i));
        ParcelFileDescriptor next=builder.establish();if(next==null)throw new IllegalStateException("VPN permission revoked");return next;
    }
    private void rebuild(long epoch)throws Exception {
        if(stopping)return;transitioning=true;
        NativeCore.INSTANCE.suspend(); // joins old owners; retains local session policy and retry budget
        ProfileVault vault=new ProfileVault(this);
        ProfileVault.Admission admission=vault.admission(requestedId);requestedId=admission.primary.id;
        boolean guard=!admission.primary.localPolicy;
        if(tun==null && guard){
            JSONObject blocking=new JSONObject().put("mtu",1500).put("ipv6",true).put("dns",new JSONArray().put("198.18.0.53"));
            tun=establish(blocking,admission.apps,true);adapterKey="";
        }
        ProfileVault.ConnectionSet set=vault.connectionSet(requestedId);
        if(guard==set.profiles.get(0).localPolicy)throw new IllegalStateException("Ownership changed");
        String nextReceipts=receipts(set);synchronized(this){if(!nextReceipts.equals(receiptKey)){lastWall=System.currentTimeMillis();clockInvalid=false;}receiptKey=nextReceipts;policyKey=policies(set);candidates=java.util.Collections.unmodifiableList(set.profiles);}
        long wall=System.currentTimeMillis(),elapsed=SystemClock.elapsedRealtime();
        if(guard && clockInvalid){accessHeld=true;problem=getString(R.string.access_refresh_required);return;}
        for(ProfileVault.Selection entry:candidates)if(!entry.localPolicy && !OfflineLease.valid(entry.lease,wall,elapsed,boot)){accessHeld=true;problem=getString(R.string.access_refresh_required);return;}
        accessHeld=false;Network network=underlying;if(network==null){problem="";return;}
        JSONArray local=localPrefixes(network), profiles=new JSONArray(), unavailable=new JSONArray();JSONObject firstPlan=null;
        for(ProfileVault.Selection entry:candidates){
            JSONObject planned=new JSONObject(entry.managedRouting==null?NativeCore.INSTANCE.plan(entry.profile.toString()):NativeCore.INSTANCE.planManagedOnNetwork(entry.profile.toString(),entry.managedRouting.toString(),local==null?"null":local.toString()));
            if(!planned.getBoolean("ok"))throw new IllegalArgumentException("Unsupported policy");JSONObject plan=planned.getJSONObject("plan");
            if(firstPlan==null)firstPlan=plan;else if(!firstPlan.toString().equals(plan.toString()))throw new IllegalArgumentException("Backup cannot change route/DNS/guard policy");
            JSONObject profile=planned.getJSONObject("profile"), endpoint=profile.getJSONObject("endpoint");JSONArray addresses=endpoint.getJSONArray("addresses"), resolved=new JSONArray();
            try{for(int i=0;i<addresses.length();i++){String address=addresses.getString(i);int colon=address.lastIndexOf(':');String host=address.substring(0,colon).replace("[","").replace("]","");int port=Integer.parseInt(address.substring(colon+1));for(InetAddress ip:network.getAllByName(host)){resolved.put((ip instanceof Inet6Address?"["+ip.getHostAddress()+"]":ip.getHostAddress())+":"+port);if(resolved.length()>64)throw new IllegalArgumentException("Endpoint limit");}}}catch(UnknownHostException unresolved){ /* Keep an empty candidate: its unavailable DNS cannot block other permitted reserves. */ }
            if(resolved.length()>0)endpoint.put("addresses",resolved);else unavailable.put(profiles.length());profiles.put(profile);
        }
        if(stopping || epoch!=networkEpoch)return;
        String adapter=new JSONObject().put("mtu",firstPlan.getInt("mtu")).put("dns",firstPlan.getJSONArray("dns")).put("apps",set.apps.json()).put("guard",guard).put("routes",guard?new JSONArray():firstPlan.getJSONArray("routes")).put("ipv6",guard || firstPlan.getBoolean("ipv6")).toString();
        if(tun==null || !adapter.equals(adapterKey)){ParcelFileDescriptor next=establish(firstPlan,set.apps,guard);ParcelFileDescriptor old=tun;tun=next;if(old!=null)old.close();adapterKey=adapter;}
        alwaysOn=isAlwaysOn();lockdown=isLockdownEnabled();rememberAlwaysOn(this,alwaysOn);
        if(recovering && !alwaysOn){disconnect();return;}
        if(firstPlan.getBoolean("require_lockdown") && (!alwaysOn || !lockdown)) {
            // Android reports these flags after establish. This is a final refusal,
            // not a transient network error that should retain the blocking TUN.
            problem = getString(R.string.cannot_start_vpn_check_the_profile);
            finishFailure();
            return;
        }
        ProfileVault.Selection primary=set.profiles.get(0);localSource=primary.localPolicy;localPolicy=primary.localPolicy && set.profiles.size()==1;
        JSONObject request=new JSONObject().put("profiles",profiles).put("unavailable",unavailable).put("logical_session",logicalSession);
        if(guard){JSONObject context=new JSONObject().put("source",primary.managedRouting==null?"managed_unknown":primary.managedRouting.getString("revision").startsWith("admin:")?"admin":"user").put("revision",primary.managedRouting==null?primary.revision:primary.managedRouting.getString("revision"));request.put("selection",new JSONObject().put("routes",firstPlan.getJSONArray("routes")).put("ipv6",firstPlan.getBoolean("ipv6")).put("context",context));}
        synchronized(networkEvents){if(stopping || epoch!=networkEpoch)return;transitioning=false;problem="";if(!NativeCore.INSTANCE.startProfiles(request.toString(),tun.getFd(),this)){transitioning=true;throw new IllegalStateException("Core rejected candidates");}}
    }
    /** Called from Rust before every endpoint socket connects. Failure always blocks that attempt. */
    public boolean protectSocket(int fd) {
        Network network = underlying;
        if (network == null || stopping || !accessValid() || !protect(fd)) return false;
        try (ParcelFileDescriptor duplicate = ParcelFileDescriptor.fromFd(fd)) {
            network.bindSocket(duplicate.getFileDescriptor()); return true;
        } catch (Exception error) { return false; }
    }
    private void cleanup() {
        if (cleaned) return;
        cleaned = true;
        ConnectivityManager.NetworkCallback previousCallback;
        synchronized (networkEvents) {
            // Revoke the callback token before Stop: an already queued callback
            // must not touch a later worker using the process-wide Rust adapter.
            previousCallback = callback;
            callback = null;
            sleepObserver.stop();
        }
        if (previousCallback != null) try {
            connectivity.unregisterNetworkCallback(previousCallback);
        } catch (IllegalArgumentException ignored) { /* Registration failed or was already removed; token is revoked. */ }
        NativeCore.INSTANCE.stop();
        if (tun != null) { try { tun.close(); } catch (Exception ignored) {} tun = null; }
        candidates=java.util.Collections.emptyList(); synchronized (networkEvents) { underlying = null; linkProperties = null; }
        if (running == this) { active = false; VpnWidget.refresh(this, true); }
    }
    private void finishFailure() {
        if (!lifecycle.beginStop()) return;
        stopping = true; lifecycleEpoch++;
        cleanup();
        widgetHandler.post(this::completeDisconnect);
    }
    private void scheduleDisconnect() {
        stopping = true; lifecycleEpoch++;
        worker.execute(() -> { cleanup(); widgetHandler.post(this::completeDisconnect); });
    }
    private void disconnect() {
        if (lifecycle.beginStop()) scheduleDisconnect();
    }
    private void completeDisconnect() {
        if (lifecycle.destroyed()) return;
        TunnelLifecycle.Start next = lifecycle.completeStop();
        if (next != null) { beginConnection(next); return; }
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelfResult(lifecycle.latestId());
    }
    @Override public void onRevoke() {
        // Permission revocation is final: queued START cannot restart a revoked session.
        if (lifecycle.stop(lifecycle.latestId())) scheduleDisconnect();
    }
    @Override public void onDestroy() {
        lifecycle.destroy(); widgetHandler.removeCallbacksAndMessages(null);
        if (running == this) { running = null; active = false; VpnWidget.refresh(this, true); }
        stopping = true; lifecycleEpoch++; worker.execute(this::cleanup); super.onDestroy();
    }
}
