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
    pub async fn start_authorized(
        profile: rtrust_profile::Profile,
        fallbacks: Vec<rtrust_profile::Profile>,
        mode: Mode,
        port: u16,
        selection: rtrust_control::Selection,
        dns: String,
        lease: Option<rtrust_control::freshness::Lease>,
    ) -> Result<Self, String> {
        let Some(lease) = lease else {
            return Self::start(profile, fallbacks, mode, port, selection, dns).await;
        };
        #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
        if mode != Mode::Socks {
            let client = rtrust_control::Client::start_managed(
                profile,
                fallbacks,
                if mode == Mode::Full {
                    None
                } else {
                    Some(selection)
                },
                dns.parse().map_err(|_| "Invalid IPv4 DNS")?,
                lease,
            )
            .await?;
            return Ok(Self::tun(client).await);
        }
        Err(
            "Managed freshness requires a compatible system TUN service; SOCKS is unsupported"
                .into(),
        )
    }
    pub async fn start(
        profile: rtrust_profile::Profile,
        fallbacks: Vec<rtrust_profile::Profile>,
        mode: Mode,
        port: u16,
        selection: rtrust_control::Selection,
        dns: String,
    ) -> Result<Self, String> {
        let _ = &dns;
        match mode {
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            Mode::Full => {
                let client = rtrust_control::Client::start_full(
                    profile,
                    fallbacks,
                    dns.parse().map_err(|_| "Некорректный IPv4 DNS")?,
                )
                .await?;
                Ok(Self::tun(client).await)
            }
            Mode::Socks => {
                // The proxy has no service supervisor; backups apply to TUN modes.
                let _ = (selection, fallbacks);
                rtrust_engine::proxy::Proxy::start(&profile, port)
                    .await
                    .map(Self::Socks)
                    .map_err(|e| e.to_string())
            }
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            Mode::Tun => {
                let client =
                    rtrust_control::Client::start(profile, fallbacks, selection, dns.parse().ok())
                        .await?;
                Ok(Self::tun(client).await)
            }
        }
    }
    // The owner survives a GUI crash so this user can still stop the
    // service-owned session; only the OS credential store keeps it.
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    async fn tun(client: rtrust_control::Client) -> Self {
        if let Some(owner) = client.owner() {
            // Best effort: the live connection can still Stop without it.
            let _ =
                tokio::task::spawn_blocking(move || rtrust_store::save_session_owner(&owner)).await;
        }
        Self::Tun(client)
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
    /// 0 is the requested profile, 1.. the allowed backups in the order sent.
    pub fn active_profile(&self) -> Option<u8> {
        match self {
            Self::Socks(_) => None,
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            Self::Tun(c) => c.status().active_profile,
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
            Self::Tun(c) => {
                let owned = c.owner().is_some();
                c.close().await?;
                if owned {
                    forget_owner().await;
                }
                Ok(())
            }
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

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
async fn forget_owner() {
    let _ = tokio::task::spawn_blocking(rtrust_store::clear_session_owner).await;
}
/// Explicit Recover: stops this user's live session with the stored owner, or
/// releases a guard retained after the session ended. A live session started
/// by another client stays protected and the service reports it.
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
pub async fn recover_service() -> Result<(), String> {
    let owner = if cfg!(target_os = "macos") {
        tokio::task::spawn_blocking(rtrust_store::load_session_owner)
            .await
            .ok()
            .flatten()
    } else {
        None
    };
    let had_owner = owner.is_some();
    rtrust_control::Client::recover(owner).await?;
    if had_owner {
        forget_owner().await;
    }
    Ok(())
}
