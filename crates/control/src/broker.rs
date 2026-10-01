//! Flatpak talks only to our system-bus name. Profile secrets travel over the
//! returned private socket, not through D-Bus messages or a host shell.
use std::os::fd::OwnedFd;
use tokio::net::UnixStream;
const NAME: &str = "org.rtrusttunnel.Service";
pub(super) async fn connect() -> Result<UnixStream, String> {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let bus = zbus::Connection::system()
            .await
            .map_err(|_| "System bus unavailable")?;
        let dbus = zbus::fdo::DBusProxy::new(&bus)
            .await
            .map_err(|_| "System bus proxy unavailable")?;
        let owner = dbus
            .get_name_owner(NAME.try_into().unwrap())
            .await
            .map_err(|_| "Установите системную службу R-TrustTunnel на хосте")?;
        if dbus
            .get_connection_unix_user(owner.clone().into())
            .await
            .map_err(|_| "Cannot verify service owner")?
            != 0
        {
            return Err("VPN broker must be owned by root".into());
        }
        // Pin the unique bus owner after checking its UID. Never call the
        // mutable well-known name after the identity check.
        let proxy = zbus::Proxy::new(&bus, owner.as_str(), "/org/rtrusttunnel/Service", NAME)
            .await
            .map_err(|_| "VPN broker unavailable")?;
        let fd: zbus::zvariant::OwnedFd = proxy
            .call("OpenChannel", &())
            .await
            .map_err(|_| "VPN broker rejected this desktop user")?;
        let fd: OwnedFd = fd.into();
        let socket = std::os::unix::net::UnixStream::from(fd);
        socket
            .set_nonblocking(true)
            .map_err(|_| "Cannot configure VPN channel")?;
        UnixStream::from_std(socket).map_err(|_| "Cannot open VPN channel".into())
    })
    .await
    .map_err(|_| "VPN broker timed out")?
}
