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
    Tun(rtrust_control::Client, OwnerKey),
}
/// Whether the service session owner reached the OS credential store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerKey {
    /// The service issued none (Linux/Windows or an older reply).
    None,
    Saved,
    /// Recover after a GUI crash would need a service restart.
    Unsaved,
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
        let key = match client.owner() {
            None => OwnerKey::None,
            Some(owner) => {
                match tokio::task::spawn_blocking(move || rtrust_store::save_session_owner(&owner))
                    .await
                {
                    Ok(Ok(())) => OwnerKey::Saved,
                    // The live connection can still Stop; the user is warned.
                    _ => OwnerKey::Unsaved,
                }
            }
        };
        Self::Tun(client, key)
    }
    /// Session owner kept in memory; Recover prefers it over the Keychain.
    pub fn owner(&self) -> Option<rtrust_control::owner::Owner> {
        match self {
            Self::Socks(_) => None,
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            Self::Tun(c, _) => c.owner(),
        }
    }
    /// Warning when the owner could not be saved; never contains its value.
    pub fn owner_warning(&self, russian: bool) -> Option<&'static str> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            Self::Tun(_, OwnerKey::Unsaved) => Some(owner_unsaved_text(russian)),
            _ => None,
        }
    }
    pub fn proxy(&self) -> Option<&rtrust_engine::proxy::Proxy> {
        match self {
            Self::Socks(p) => Some(p),
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            Self::Tun(..) => None,
        }
    }
    /// A visible user interface is showing this session now. The service
    /// runs its DNS/guard probes only while such views keep arriving; a
    /// hidden window, tray or diagnostics read must not call this.
    pub fn mark_viewed(&self) {
        match self {
            Self::Socks(_) => {}
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            Self::Tun(c, _) => c.mark_viewed(),
        }
    }
    pub fn is_tun(&self) -> bool {
        self.proxy().is_none()
    }
    pub fn address(&self) -> String {
        match self {
            Self::Socks(p) => p.address().to_string(),
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            Self::Tun(c, _) => crate::observation_summary(&c.status().observations, true),
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
            Self::Tun(c, _) => c.status().observations,
        }
    }
    /// 0 is the requested profile, 1.. the allowed backups in the order sent.
    pub fn active_profile(&self) -> Option<u8> {
        match self {
            Self::Socks(_) => None,
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            Self::Tun(c, _) => c.status().active_profile,
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
            Self::Tun(c, _) => {
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
        self.health().await.map_err(|e| e.message)
    }
    /// `lifecycle_health` that keeps a SOCKS degraded verdict structured, so
    /// the caller can tell a tunnel carrying no traffic from a dead one.
    pub async fn health(&self) -> Result<(), HealthError> {
        match self {
            Self::Socks(p) => p.health().await.map_err(HealthError::from),
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            Self::Tun(c, _) => {
                let r = c.status();
                if r.state == rtrust_control::State::Connected {
                    Ok(())
                } else {
                    Err(HealthError {
                        message: r.message,
                        degraded: None,
                    })
                }
            }
        }
    }
}
/// A failed lifecycle check. `degraded` is `Some(proven)` when the transport
/// still answers but carries no traffic (`rtrust_engine::Error::Degraded`);
/// `proven`: it delivered data earlier in its life. The message never holds
/// profile secrets: it is the engine's fixed error text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthError {
    pub message: String,
    pub degraded: Option<bool>,
}
impl From<rtrust_engine::Error> for HealthError {
    fn from(error: rtrust_engine::Error) -> Self {
        Self {
            degraded: match error {
                rtrust_engine::Error::Degraded { proven, .. } => Some(proven),
                _ => None,
            },
            message: error.to_string(),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
async fn forget_owner() {
    let _ = tokio::task::spawn_blocking(rtrust_store::clear_session_owner).await;
}
pub fn owner_unsaved_text(russian: bool) -> &'static str {
    if russian {
        "Ключ управления сессией VPN не сохранён в Связке ключей и хранится только в этом приложении. При закрытии или сбое приложения он будет потерян: снять блокировку тогда можно только после перезагрузки Mac или перезапуска службы R-TrustTunnel администратором."
    } else {
        "The VPN session control key was not saved to the Keychain and exists only in this app. It is lost when the app quits or crashes; the block can then be removed only after restarting the Mac or an administrator restarting the R-TrustTunnel service."
    }
}
/// The in-memory owner of this GUI's session wins; the Keychain covers a
/// restarted GUI. The loader runs only when memory has none.
fn pick_owner(
    memory: Option<rtrust_control::owner::Owner>,
    stored: impl FnOnce() -> Option<rtrust_control::owner::Owner>,
) -> Option<rtrust_control::owner::Owner> {
    memory.or_else(stored)
}
/// Turns the service owner refusal into a concrete next step. Other errors
/// pass through unchanged.
fn recover_error(error: String, sent_owner: bool, russian: bool) -> String {
    if error != rtrust_control::owner::NOT_OWNER {
        return error;
    }
    match (sent_owner, russian) {
        (false, true) => "Подключение VPN запущено, но ключ управления им недоступен: его запустило другое приложение или ключ утерян. Сессия и защита сохранены. Отключите VPN в приложении, которое его запустило; если это было это приложение, перезагрузите Mac или перезапустите службу R-TrustTunnel от администратора, после чего снимите блокировку.",
        (false, false) => "The VPN session is running but its control key is unavailable: another app started it or the key was lost. The session and protection are kept. Disconnect in the app that started it; if it was this app, restart the Mac or have an administrator restart the R-TrustTunnel service, then remove the block.",
        (true, true) => "Ключ управления не подходит к текущей сессии VPN: её запустило другое приложение или более новое подключение. Сессия и защита сохранены. Отключите VPN в приложении, которое его запустило; если это было это приложение, перезагрузите Mac или перезапустите службу R-TrustTunnel от администратора, после чего снимите блокировку.",
        (true, false) => "The control key does not match the current VPN session: another app or a newer connection started it. The session and protection are kept. Disconnect in the app that started it; if it was this app, restart the Mac or have an administrator restart the R-TrustTunnel service, then remove the block.",
    }
    .into()
}
/// Explicit Recover: stops this user's live session with its owner (from
/// `current` or the Keychain), or releases a guard retained after the session
/// ended. A live session started by another client stays protected.
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
pub async fn recover_service(
    current: Option<rtrust_control::owner::Owner>,
    russian: bool,
) -> Result<(), String> {
    let stored = if cfg!(target_os = "macos") && current.is_none() {
        tokio::task::spawn_blocking(rtrust_store::load_session_owner)
            .await
            .ok()
            .flatten()
    } else {
        None
    };
    let owner = pick_owner(current, || stored);
    let sent_owner = owner.is_some();
    rtrust_control::Client::recover(owner)
        .await
        .map_err(|error| recover_error(error, sent_owner, russian))?;
    if sent_owner {
        forget_owner().await;
    }
    Ok(())
}

#[cfg(test)]
mod health_tests {
    use super::*;
    #[test]
    fn only_a_degraded_engine_error_is_marked_with_its_proof() {
        use rtrust_engine::{Error, Stall};
        for proven in [false, true] {
            for kind in [Stall::Silent, Stall::Quiet] {
                let error = HealthError::from(Error::Degraded { proven, kind });
                assert_eq!(error.degraded, Some(proven));
                assert_eq!(error.message, "Tunnel carries no traffic");
            }
        }
        assert_eq!(HealthError::from(Error::Io).degraded, None);
    }
}

#[cfg(test)]
mod owner_tests {
    use super::*;
    use rtrust_control::owner::{LEN, NOT_OWNER, Owner};
    #[test]
    fn memory_owner_wins_and_keychain_is_read_only_without_it() {
        let memory = Owner::from_bytes([1; LEN]);
        let picked = pick_owner(Some(memory.clone()), || panic!("Keychain must not be read"));
        assert!(picked.unwrap().matches(&memory));
        let stored = Owner::from_bytes([2; LEN]);
        let picked = pick_owner(None, || Some(stored.clone()));
        assert!(picked.unwrap().matches(&stored));
        assert!(pick_owner(None, || None).is_none());
    }
    #[test]
    fn owner_refusal_gives_a_concrete_exit_and_other_errors_pass_through() {
        for sent in [false, true] {
            for russian in [false, true] {
                let text = recover_error(NOT_OWNER.into(), sent, russian);
                assert_ne!(text, NOT_OWNER);
                assert!(text.contains(if russian {
                    "перезапустите службу"
                } else {
                    "restart the R-TrustTunnel service"
                }));
            }
        }
        assert_ne!(
            recover_error(NOT_OWNER.into(), false, true),
            recover_error(NOT_OWNER.into(), true, true)
        );
        assert_eq!(
            recover_error("IPC version mismatch".into(), true, true),
            "IPC version mismatch"
        );
        assert!(owner_unsaved_text(true).contains("Связке ключей"));
        assert!(owner_unsaved_text(false).contains("Keychain"));
    }
}
