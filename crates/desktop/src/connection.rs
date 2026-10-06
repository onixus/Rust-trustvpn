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
            Mode::Tun => rtrust_control::Client::start(profile, selection)
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
            Self::Tun(c) => {
                if c.status().state == rtrust_control::State::Connected {
                    c.status().message
                } else {
                    "TUN · проверьте блокировку сетей".into()
                }
            }
        }
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
    pub async fn health(&self) -> Result<(), String> {
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
