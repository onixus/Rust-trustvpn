use crate::failover::Failure;
use rtrust_engine::Session;
use std::{net::Ipv4Addr, sync::Arc};
pub const DEVICE: &str = "utun5254";
pub const ADDRESS: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
pub type RunResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
pub struct Prepared {
    session: Session,
    udp: rtrust_engine::Tunnel,
    device: Arc<tun_rs::AsyncDevice>,
}
pub fn unused() -> Result<(), Failure> {
    let name = std::ffi::CString::new(DEVICE).unwrap();
    if unsafe { libc::if_nametoindex(name.as_ptr()) } != 0 {
        Err(Failure::engine(
            rtrust_engine::Error::LocalBind,
            "VPN utun interface already exists; refusing to reuse it",
        ))
    } else {
        Ok(())
    }
}
impl Prepared {
    pub async fn connect(profile: &rtrust_profile::Profile) -> Result<Self, Failure> {
        unused()?;
        let session = Session::connect(profile)
            .await
            .map_err(|e| Failure::engine(e, "Cannot authenticate VPN endpoint"))?;
        session
            .health()
            .await
            .map_err(|e| Failure::engine(e, "VPN endpoint health check failed"))?;
        let udp = session
            .open_udp()
            .await
            .map_err(|e| Failure::engine(e, "VPN UDP transport unavailable"))?;
        let device = tun_rs::DeviceBuilder::new()
            .name(DEVICE)
            .associate_route(false)
            .mtu(crate::packet::MTU as u16)
            .ipv4(ADDRESS, 32, Some(ADDRESS))
            .ipv6(crate::ipv6::ADDRESS, 128)
            .build_async()
            .map_err(|_| "Cannot create utun; install the privileged macOS service")?;
        if device.name().map_err(|_| "utun name unavailable")? != DEVICE {
            return Err("Unexpected utun device identity".into());
        }
        Ok(Self {
            session,
            udp,
            device: Arc::new(device),
        })
    }
    pub fn transport(&self) -> &'static str {
        self.session.transport_name()
    }
    pub fn device(&self) -> Arc<tun_rs::AsyncDevice> {
        self.device.clone()
    }
    pub async fn reconnect(
        profile: &rtrust_profile::Profile,
        device: Arc<tun_rs::AsyncDevice>,
    ) -> Result<Self, Failure> {
        use crate::reason::{Stage, reconnect};
        let session = Session::connect(profile).await.map_err(|e| {
            let message = reconnect(Stage::Connect, &e);
            Failure::engine(e, message)
        })?;
        session.health().await.map_err(|e| {
            let message = reconnect(Stage::Health, &e);
            Failure::engine(e, message)
        })?;
        let udp = session.open_udp().await.map_err(|e| {
            let message = reconnect(Stage::Udp, &e);
            Failure::engine(e, message)
        })?;
        Ok(Self {
            session,
            udp,
            device,
        })
    }
    pub async fn run(self) -> RunResult {
        crate::dataplane::run(self.session, self.udp, self.device, ADDRESS).await
    }
}
