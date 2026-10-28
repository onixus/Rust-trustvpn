//! Reason classes for transport-stop and reconnect-failure events: fixed
//! `key=value` tokens and numeric codes only. Nothing here may carry an
//! address, host name, credential, URL or endpoint-supplied text.
use rtrust_engine::{Error, io_kind};

/// The reconnect step that failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// Opening and authenticating a new session.
    Connect,
    /// The first `_check` on the new session.
    Health,
    /// Opening the UDP relay stream.
    Udp,
}
impl Stage {
    fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Health => "health",
            Self::Udp => "udp",
        }
    }
}

/// `stage=<step> reason=<class>[ key=value]...` for a failed reconnect step.
pub fn reconnect(stage: Stage, error: &Error) -> String {
    let reason = match (stage, error) {
        (Stage::Connect, Error::Timeout) => "reason=connect_timeout".into(),
        _ => engine(error, "timeout"),
    };
    format!("stage={} {reason}", stage.as_str())
}

/// `reason=<class>[ key=value]...` for a data plane that ended.
pub fn stopped(result: &Result<(), Box<dyn std::error::Error + Send + Sync>>) -> String {
    let Err(error) = result else {
        return "reason=ended".into();
    };
    if let Some(error) = error.downcast_ref::<Error>() {
        // The data plane's health worker gives each `_check` 10 s.
        return engine(error, "keepalive_timeout");
    }
    if let Some(error) = error.downcast_ref::<std::io::Error>() {
        return format!("reason=device_io kind={}", io_kind(error.kind()));
    }
    if error.is::<tokio::time::error::Elapsed>() {
        return "reason=device_timeout".into();
    }
    "reason=worker_stopped".into()
}

/// The event line for an ended data plane: `head` is the existing fixed text
/// (`VPN transport stopped` or `VPN transport worker failed`), `transport`
/// is `Session::transport_name`, `uptime_ms` the connection's lifetime.
pub fn stopped_event(head: &str, reason: &str, transport: &str, uptime_ms: u64) -> String {
    format!("{head} {reason} transport={transport} uptime_ms={uptime_ms}")
}

fn engine(error: &Error, timeout: &str) -> String {
    match error {
        Error::Closed(close) => close.fields(),
        Error::Timeout => format!("reason={timeout}"),
        Error::Degraded { proven, kind } => {
            format!("reason=degraded kind={} proven={proven}", kind.as_str())
        }
        Error::ConnectIo(std::io::ErrorKind::ConnectionRefused) => "reason=connect_refused".into(),
        Error::ConnectIo(std::io::ErrorKind::TimedOut) => "reason=connect_timeout".into(),
        Error::ConnectIo(kind) => format!("reason=connect_io kind={}", io_kind(*kind)),
        Error::Connect => "reason=connect_failed".into(),
        Error::Tls => "reason=tls_handshake".into(),
        Error::Trust => "reason=tls_trust".into(),
        Error::Protocol => "reason=protocol".into(),
        Error::Authentication => "reason=auth_rejected".into(),
        Error::Rejected(code) => format!("reason=http_status code={code}"),
        Error::Credit => "reason=stream_credit".into(),
        Error::Unanswered => "reason=streams_unanswered".into(),
        Error::Io => "reason=io_error".into(),
        Error::Destination => "reason=destination".into(),
        Error::Profile => "reason=profile".into(),
        Error::Unsupported(_) => "reason=unsupported".into(),
        Error::LocalBind => "reason=local_bind".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtrust_engine::{Close, Stall};
    use std::io::ErrorKind;

    fn stop(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> String {
        stopped(&Err(error.into()))
    }

    #[test]
    fn transport_stops_map_to_classes() {
        let cases: Vec<(Box<dyn std::error::Error + Send + Sync>, &str)> = vec![
            (
                Error::Closed(Close::PeerClosed).into(),
                "reason=peer_closed",
            ),
            (
                Error::Closed(Close::GoAway {
                    code: 0,
                    remote: true,
                })
                .into(),
                "reason=goaway code=0 by=peer",
            ),
            (
                Error::Closed(Close::GoAway {
                    code: 1,
                    remote: false,
                })
                .into(),
                "reason=goaway code=1 by=local",
            ),
            (
                Error::Closed(Close::QuicApplication(0x100)).into(),
                "reason=quic_close layer=app code=256 by=peer",
            ),
            (
                Error::Closed(Close::QuicTransport {
                    code: 0xa,
                    remote: true,
                })
                .into(),
                "reason=quic_close layer=transport code=10 by=peer",
            ),
            (
                Error::Closed(Close::QuicTransport {
                    code: 0x12a,
                    remote: true,
                })
                .into(),
                "reason=tls_error alert=42 by=peer",
            ),
            (
                Error::Closed(Close::IdleTimeout).into(),
                "reason=idle_timeout",
            ),
            (
                Error::Closed(Close::StatelessReset).into(),
                "reason=stateless_reset",
            ),
            (Error::Closed(Close::Tls).into(), "reason=tls_error"),
            (
                Error::Closed(Close::Io(ErrorKind::ConnectionReset)).into(),
                "reason=io_error kind=connection_reset",
            ),
            (Error::Closed(Close::Local).into(), "reason=local_stop"),
            (Error::Timeout.into(), "reason=keepalive_timeout"),
            (Error::Protocol.into(), "reason=protocol"),
            (
                Error::Degraded {
                    proven: true,
                    kind: Stall::Quiet,
                }
                .into(),
                "reason=degraded kind=quiet proven=true",
            ),
            (
                std::io::Error::from(ErrorKind::WouldBlock).into(),
                "reason=device_io kind=would_block",
            ),
            ("Transport worker stopped".into(), "reason=worker_stopped"),
        ];
        for (error, expected) in cases {
            assert_eq!(stopped(&Err(error)), expected);
        }
        assert_eq!(stopped(&Ok(())), "reason=ended");
    }

    #[tokio::test]
    async fn device_send_deadline_is_its_own_class() {
        let elapsed = tokio::time::timeout(std::time::Duration::ZERO, std::future::pending::<()>())
            .await
            .unwrap_err();
        assert_eq!(stop(elapsed), "reason=device_timeout");
    }

    #[test]
    fn reconnect_failures_map_to_classes() {
        let cases = [
            (
                Stage::Connect,
                Error::Timeout,
                "stage=connect reason=connect_timeout",
            ),
            (
                Stage::Connect,
                Error::ConnectIo(ErrorKind::ConnectionRefused),
                "stage=connect reason=connect_refused",
            ),
            (
                Stage::Connect,
                Error::ConnectIo(ErrorKind::TimedOut),
                "stage=connect reason=connect_timeout",
            ),
            (
                Stage::Connect,
                Error::ConnectIo(ErrorKind::HostUnreachable),
                "stage=connect reason=connect_io kind=host_unreachable",
            ),
            (
                Stage::Connect,
                Error::ConnectIo(ErrorKind::UnexpectedEof),
                "stage=connect reason=connect_io kind=unexpected_eof",
            ),
            (
                Stage::Connect,
                Error::Tls,
                "stage=connect reason=tls_handshake",
            ),
            (
                Stage::Connect,
                Error::Trust,
                "stage=connect reason=tls_trust",
            ),
            (
                Stage::Connect,
                Error::Connect,
                "stage=connect reason=connect_failed",
            ),
            (
                Stage::Connect,
                Error::Protocol,
                "stage=connect reason=protocol",
            ),
            (
                Stage::Health,
                Error::Authentication,
                "stage=health reason=auth_rejected",
            ),
            (
                Stage::Health,
                Error::Rejected(503),
                "stage=health reason=http_status code=503",
            ),
            (Stage::Health, Error::Timeout, "stage=health reason=timeout"),
            (
                Stage::Health,
                Error::Closed(Close::GoAway {
                    code: 0,
                    remote: true,
                }),
                "stage=health reason=goaway code=0 by=peer",
            ),
            (Stage::Udp, Error::Credit, "stage=udp reason=stream_credit"),
            (
                Stage::Health,
                Error::Unanswered,
                "stage=health reason=streams_unanswered",
            ),
            (
                Stage::Udp,
                Error::Unsupported("x"),
                "stage=udp reason=unsupported",
            ),
        ];
        for (stage, error, expected) in cases {
            assert_eq!(reconnect(stage, &error), expected);
        }
    }

    /// Every token is `key=value` with a lowercase class or a number: no
    /// address, host, port, URL, credential or free text can appear.
    fn assert_redacted(line: &str) {
        for token in line.split(' ') {
            let (key, value) = token.split_once('=').expect(token);
            assert!(
                key.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "{line}"
            );
            assert!(
                value
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{line}"
            );
            assert!(
                !value.contains("example") && !value.contains("synthetic"),
                "{line}"
            );
        }
    }

    #[test]
    fn event_lines_hold_no_addresses_or_free_text() {
        // Synthetic failures whose Display or payload would name an endpoint.
        let named: Box<dyn std::error::Error + Send + Sync> =
            "connect to vpn.example 192.0.2.1:443 as synthetic failed".into();
        let io: Box<dyn std::error::Error + Send + Sync> = Box::new(std::io::Error::new(
            ErrorKind::ConnectionReset,
            "198.51.100.7:443 https://vpn.example/?token=synthetic",
        ));
        for result in [
            Err(named),
            Err(io),
            Err(Error::Closed(Close::PeerClosed).into()),
        ] {
            let reason = stopped(&result);
            let line = stopped_event("VPN transport stopped", &reason, "h3", 61_234);
            let fields = line.strip_prefix("VPN transport stopped ").unwrap();
            assert_redacted(fields);
            for leak in [
                "192.0.2.1",
                "198.51.100.7",
                "vpn.example",
                "token",
                "443",
                "://",
            ] {
                assert!(!line.contains(leak), "{line}");
            }
        }
        for kind in [ErrorKind::ConnectionRefused, ErrorKind::AddrNotAvailable] {
            assert_redacted(&reconnect(Stage::Connect, &Error::ConnectIo(kind)));
        }
        assert_redacted(&reconnect(Stage::Health, &Error::Rejected(407)));
    }
}
