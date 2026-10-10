#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Socks,
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    Tun,
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    Full,
}
impl Mode {
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    pub const ALL: &[Self] = &[Self::Socks, Self::Tun, Self::Full];
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    pub const ALL: &[Self] = &[Self::Socks];
}
impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Socks => "SOCKS5/HTTP-прокси для приложений",
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            Self::Tun => "TUN · IPv4-сети и исключения",
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            Self::Full => "Весь компьютер · IPv4/IPv6 + DNS",
        })
    }
}
#[derive(Clone)]
pub enum Session {
    Socks(rtrust_engine::proxy::Proxy),
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    Tun(rtrust_control::Client),
}
impl Session {
    pub async fn start(
        profile: rtrust_profile::Profile,
        mode: Mode,
        port: u16,
        selection: rtrust_control::Selection,
        dns: String,
    ) -> Result<Self, String> {
        let _ = &dns;
        match mode {
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            Mode::Full => rtrust_control::Client::start_full(
                profile,
                dns.parse().map_err(|_| "Некорректный IPv4 DNS")?,
            )
            .await
            .map(Self::Tun),
            Mode::Socks => {
                let _ = selection;
                rtrust_engine::proxy::Proxy::start(&profile, port)
                    .await
                    .map(Self::Socks)
                    .map_err(|e| e.to_string())
            }
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            Mode::Tun => rtrust_control::Client::start(profile, selection, dns.parse().ok())
                .await
                .map(Self::Tun),
        }
    }
    pub fn proxy(&self) -> Option<&rtrust_engine::proxy::Proxy> {
        match self {
            Self::Socks(p) => Some(p),
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            Self::Tun(_) => None,
        }
    }
    pub fn is_tun(&self) -> bool {
        self.proxy().is_none()
    }
    pub fn address(&self) -> String {
        match self {
            Self::Socks(p) => p.address().to_string(),
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            Self::Tun(c) => crate::observation_summary(&c.status().observations, true),
        }
    }

    pub fn observations(&self) -> rtrust_control::observations::Snapshot {
        match self {
            Self::Socks(_) => rtrust_control::observations::Monitor::new(
                rtrust_control::observations::Mode::Proxy,
                rtrust_control::observations::Source::ProxyLifecycle,
                rtrust_control::observations::now_ms(),
            )
            .sample(rtrust_control::observations::now_ms()),
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            Self::Tun(c) => c.status().observations,
        }
    }
    pub fn status_summary(&self, russian: bool) -> String {
        crate::observation_summary(&self.observations(), russian)
    }
    pub fn cancel(&self) {
        if let Some(proxy) = self.proxy() {
            proxy.stop();
        }
    }
    pub async fn stop(self) -> Result<(), String> {
        match self {
            Self::Socks(p) => {
                p.stop();
                Ok(())
            }
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            Self::Tun(c) => c.close().await,
        }
    }
    /// Worker/IPC liveness only; use observations for verified network availability.
    pub async fn lifecycle_health(&self) -> Result<(), String> {
        match self {
            Self::Socks(p) => p.health().await.map_err(|e| e.to_string()),
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            Self::Tun(c) => {
                let r = c.status();
                if r.state == rtrust_control::State::Connected {
                    Ok(())
                } else {
                    Err(r.message)
                }
            }
        }
    }
}
