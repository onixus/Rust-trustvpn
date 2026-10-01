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
pub fn unused() -> Result<(), String> {
    let name = std::ffi::CString::new(DEVICE).unwrap();
    if unsafe { libc::if_nametoindex(name.as_ptr()) } != 0 {
        Err("VPN utun interface already exists; refusing to reuse it".into())
    } else {
        Ok(())
    }
}
impl Prepared {
    pub async fn connect(profile: &rtrust_profile::Profile) -> Result<Self, String> {
        unused()?;
        if profile.endpoint.upstream_protocol != "http2" {
            return Err("System VPN requires HTTP/2".into());
        }
        let session = Session::connect(profile)
            .await
            .map_err(|_| "Cannot authenticate VPN endpoint")?;
        session
            .health()
            .await
            .map_err(|_| "VPN endpoint health check failed")?;
        let udp = session
            .open_udp()
            .await
            .map_err(|_| "VPN UDP transport unavailable")?;
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
    pub fn device(&self) -> Arc<tun_rs::AsyncDevice> {
        self.device.clone()
    }
    pub async fn reconnect(
        profile: &rtrust_profile::Profile,
        device: Arc<tun_rs::AsyncDevice>,
    ) -> Result<Self, String> {
        let session = Session::connect(profile)
            .await
            .map_err(|_| "Cannot reconnect endpoint")?;
        session
            .health()
            .await
            .map_err(|_| "Endpoint health check failed")?;
        let udp = session
            .open_udp()
            .await
            .map_err(|_| "UDP transport unavailable")?;
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
