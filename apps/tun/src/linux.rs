use crate::packet;
use rtrust_engine::Session;
use std::net::Ipv4Addr;

pub struct Prepared {
    session: Session,
    tunnel: rtrust_engine::Tunnel,
    device: tun_rs::AsyncDevice,
    address: Ipv4Addr,
}
impl Prepared {
    pub async fn connect(
        profile: &rtrust_profile::Profile,
        name: &str,
        address: Ipv4Addr,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::connect_mode(profile, name, address, false).await
    }
    pub async fn connect_mode(
        profile: &rtrust_profile::Profile,
        name: &str,
        address: Ipv4Addr,
        full: bool,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        if profile.protocol == rtrust_profile::Protocol::TrustTunnel
            && profile.endpoint.upstream_protocol != "http2"
        {
            return Err("Experimental TUN requires HTTP/2: HTTP/3 half-close interoperability with endpoint 1.1.0 is unresolved".into());
        }
        let session = if full {
            Session::connect_marked(profile, 0x5254).await?
        } else {
            Session::connect(profile).await?
        };
        session.health().await?;
        let tunnel = session.open_udp().await?;
        // Reject existing interfaces before configuring a new, nonpersistent TUN.
        if std::path::Path::new("/sys/class/net").join(name).exists() {
            return Err("Interface already exists".into());
        }
        let device = tun_rs::DeviceBuilder::new()
            .name(name)
            .mtu(packet::MTU as u16)
            .ipv4(address, 32, None)
            .ipv6(crate::ipv6::ADDRESS, 128)
            .build_async()?;
        Ok(Self {
            session,
            tunnel,
            device,
            address,
        })
    }
    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        crate::dataplane::run(
            self.session,
            self.tunnel,
            std::sync::Arc::new(self.device),
            self.address,
        )
        .await
    }
}
