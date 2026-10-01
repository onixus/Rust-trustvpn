//! A single authenticated method returning an IPC socket, never host execution.
use std::{os::fd::OwnedFd, sync::Arc};
use tokio::sync::{Mutex, Semaphore};
use zbus::{Connection, fdo, message::Header, zvariant};
struct Broker {
    uid: u32,
    lease: Arc<Mutex<()>>,
    supervisor: Arc<crate::always_on::Supervisor>,
    channels: Arc<Semaphore>,
}
#[zbus::interface(name = "org.rtrusttunnel.Service")]
impl Broker {
    async fn open_channel(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> fdo::Result<zvariant::OwnedFd> {
        let sender = header
            .sender()
            .ok_or_else(|| fdo::Error::AccessDenied("Missing bus identity".into()))?;
        let dbus = fdo::DBusProxy::new(connection).await?;
        let uid = dbus.get_connection_unix_user(sender.clone().into()).await?;
        if uid != self.uid {
            return Err(fdo::Error::AccessDenied("Wrong desktop owner".into()));
        }
        let permit = self
            .channels
            .clone()
            .try_acquire_owned()
            .map_err(|_| fdo::Error::LimitsExceeded("Too many VPN channels".into()))?;
        let (client, server) = std::os::unix::net::UnixStream::pair()
            .map_err(|_| fdo::Error::Failed("Cannot create IPC channel".into()))?;
        server
            .set_nonblocking(true)
            .map_err(|_| fdo::Error::Failed("Cannot configure IPC channel".into()))?;
        let server = tokio::net::UnixStream::from_std(server)
            .map_err(|_| fdo::Error::Failed("Cannot open IPC channel".into()))?;
        let lease = self.lease.clone();
        let supervisor = self.supervisor.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = super::serve(server, uid, lease, Some(supervisor)).await;
        });
        let fd: OwnedFd = client.into();
        Ok(fd.into())
    }
}
pub(super) async fn start(
    uid: u32,
    lease: Arc<Mutex<()>>,
    supervisor: Arc<crate::always_on::Supervisor>,
) -> Result<Connection, String> {
    let broker = Broker {
        uid,
        lease,
        supervisor,
        channels: Arc::new(Semaphore::new(16)),
    };
    zbus::connection::Builder::system()
        .map_err(|_| "System bus unavailable")?
        .name("org.rtrusttunnel.Service")
        .map_err(|_| "Invalid broker name")?
        .serve_at("/org/rtrusttunnel/Service", broker)
        .map_err(|_| "Cannot register VPN broker")?
        .build()
        .await
        .map_err(|_| "Cannot own VPN broker; install its system-bus policy".into())
}
