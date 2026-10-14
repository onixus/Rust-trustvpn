//! Terminal client: the shared desktop controller behind a ratatui screen.
mod app;
use app::{App, Command, Outcome, Row, Snapshot, tr};
use ratatui::crossterm::{
    event::{self, DisableBracketedPaste, EnableBracketedPaste, Event},
    execute,
};
use rtrust_desktop::Controller;
use std::{process::ExitCode, sync::Arc, time::Duration};
use tokio::sync::{Mutex, mpsc};
use zeroize::Zeroizing;

type Shared = Arc<Mutex<Controller>>;
/// Lifecycle failure and the session epoch it was measured for.
type Health = Arc<std::sync::Mutex<(u64, Option<String>)>>;

const HELP: &str = "\
rtrust-tui — terminal client for R-TrustTunnel

Usage: rtrust-tui [OPTIONS] [LINK | FILE]

  LINK | FILE          tt:// or hy2:// link, or a profile file, to preview for import
  --no-auto-connect    do not connect the default profile at start
  -h, --help           show this help
  -V, --version        show the version

Profiles are stored encrypted; the key lives in the Secret Service
(GNOME Keyring, KWallet, KeePassXC). TUN and whole-device modes need the
R-TrustTunnel system service; SOCKS mode runs inside this process.
";
const HEALTH_EVERY: Duration = Duration::from_secs(5);
const HEALTH_TIMEOUT: Duration = Duration::from_secs(5);

fn russian() -> bool {
    ["LC_ALL", "LC_MESSAGES", "LANG"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
        .is_some_and(|v| v.starts_with("ru"))
}

fn main() -> ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print!("{HELP}");
        return ExitCode::SUCCESS;
    }
    if args.iter().any(|a| a == "-V" || a == "--version") {
        println!("rtrust-tui {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if let Some(unknown) = args
        .iter()
        .find(|a| a.starts_with('-') && *a != "--no-auto-connect")
    {
        eprintln!("Unknown option {unknown}; see --help");
        return ExitCode::from(2);
    }
    let ru = russian();
    let controller = match Controller::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            if cfg!(target_os = "linux") {
                eprintln!(
                    "{}",
                    tr(
                        ru,
                        "Нужен разблокированный Secret Service в D-Bus-сессии пользователя (GNOME Keyring, KWallet или KeePassXC).",
                        "An unlocked Secret Service is required on the user's D-Bus session (GNOME Keyring, KWallet or KeePassXC)."
                    )
                );
            }
            return ExitCode::FAILURE;
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let auto = !args.iter().any(|a| a == "--no-auto-connect");
    let import = args
        .into_iter()
        .find(|a| !a.starts_with('-'))
        .map(Zeroizing::new);
    runtime.block_on(run(controller, import, auto, ru))
}

async fn run(
    controller: Controller,
    import: Option<Zeroizing<String>>,
    auto: bool,
    ru: bool,
) -> ExitCode {
    let mut app = App::new(ru);
    let mut pending = if let Some(input) = import {
        app.start(Command::Preview(input))
    } else if auto
        && controller.vault.connection.auto_connect
        && !controller.vault.profiles.is_empty()
    {
        app.start(Command::Connect {
            revision: controller.revision,
            index: 0,
        })
    } else {
        None
    };
    let shared: Shared = Arc::new(Mutex::new(controller));
    let health: Health = Default::default();
    tokio::spawn(watch_health(shared.clone(), health.clone()));
    let (done_tx, mut done_rx) = mpsc::channel::<Outcome>(8);
    let (input_tx, mut input_rx) = mpsc::channel::<Event>(64);
    std::thread::spawn(move || {
        loop {
            match event::poll(Duration::from_millis(200)) {
                Ok(true) => match event::read() {
                    Ok(ev) => {
                        if input_tx.blocking_send(ev).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                },
                Ok(false) if !input_tx.is_closed() => {}
                _ => break,
            }
        }
    });
    let (signal_tx, mut signal_rx) = mpsc::channel::<()>(4);
    watch_signals(signal_tx);

    let mut terminal = ratatui::init();
    let _ = execute!(std::io::stdout(), EnableBracketedPaste);
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    let mut input_open = true;
    let mut last_words = None;
    loop {
        if let Some(command) = pending.take() {
            let (shared, done) = (shared.clone(), done_tx.clone());
            tokio::spawn(async move {
                let outcome = execute(command, &shared, ru).await;
                let _ = done.send(outcome).await;
            });
        }
        // Never wait for the controller here: Connect may hold it for seconds.
        if let Ok(c) = shared.try_lock() {
            let (epoch, failure) = health.lock().map(|h| h.clone()).unwrap_or_default();
            let failure = failure.filter(|_| epoch == c.session_epoch);
            app.update(Snapshot::capture(&c, ru, failure));
        }
        if terminal.draw(|f| app.draw(f)).is_err() && input_open {
            input_open = false;
            pending = app.signal();
            continue;
        }
        if app.exit {
            break;
        }
        tokio::select! {
            _ = tick.tick() => app.tick(),
            Some(outcome) = done_rx.recv() => {
                if let Outcome::Exit(Some(error)) = &outcome {
                    last_words = Some(error.clone());
                }
                pending = app.finish(outcome);
            }
            event = input_rx.recv(), if input_open => match event {
                Some(Event::Key(key)) => pending = app.key(key),
                Some(Event::Paste(text)) => app.paste(&Zeroizing::new(text)),
                Some(_) => {}
                None => {
                    input_open = false;
                    pending = app.signal();
                }
            },
            Some(()) = signal_rx.recv() => pending = app.signal(),
        }
    }
    let _ = execute!(std::io::stdout(), DisableBracketedPaste);
    ratatui::restore();
    match last_words {
        Some(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
        None => ExitCode::SUCCESS,
    }
}

async fn execute(command: Command, shared: &Shared, ru: bool) -> Outcome {
    let mut c = shared.lock().await;
    let done = |r: Result<(), String>, text: &'static str| match r {
        Ok(()) => Outcome::Done(text.into()),
        Err(e) => Outcome::Failed(e),
    };
    match command {
        Command::Connect { revision, index } => match c.connect_profile(revision, index).await {
            Ok(()) => Outcome::Done(c.connected_note().into()),
            Err(e) => Outcome::Failed(e),
        },
        Command::Disconnect => done(c.disconnect().await, ""),
        Command::Preview(input) => match preview(&mut c, &input) {
            Ok(row) => Outcome::Previewed {
                revision: c.revision,
                row,
            },
            Err(e) => Outcome::Failed(e),
        },
        Command::Import { revision } => done(
            c.import(revision),
            tr(ru, "Профиль добавлен", "Profile added"),
        ),
        Command::Discard => {
            c.discard_preview();
            Outcome::Done(String::new())
        }
        Command::Edit {
            revision,
            action,
            index,
        } => done(c.edit(revision, action, index), ""),
        Command::Settings { revision, settings } => done(
            c.settings(revision, *settings),
            tr(ru, "Настройки сохранены", "Settings saved"),
        ),
        Command::Recover => {
            if c.session.is_some() {
                return Outcome::Failed(tr(ru, "Сначала отключитесь", "Disconnect first").into());
            }
            drop(c);
            done(
                rtrust_desktop::connection::recover_service(None, ru).await,
                tr(ru, "Блокировка снята", "Block released"),
            )
        }
        Command::Quit { force } => match c.disconnect().await {
            Ok(()) => Outcome::Exit(None),
            Err(e) if force => Outcome::Exit(Some(e)),
            Err(e) => Outcome::Failed(e),
        },
    }
}

/// A link or pasted config is parsed as is; anything else is a file path.
fn preview(c: &mut Controller, input: &str) -> Result<Row, String> {
    let summary = if app::is_inline(input) {
        c.preview(input)?
    } else {
        let path = match input.strip_prefix("~/") {
            Some(rest) => std::env::home_dir().ok_or("HOME is unset")?.join(rest),
            None => input.into(),
        };
        let data = Zeroizing::new(
            rtrust_store::read_bounded(&path, rtrust_profile::MAX_INPUT)
                .map_err(|e| e.to_string())?,
        );
        let text = std::str::from_utf8(&data).map_err(|_| "Profile must be UTF-8")?;
        c.preview(text)?
    };
    Ok(Row {
        name: summary.name,
        hostname: summary.hostname,
        protocol: summary.protocol,
    })
}

/// Records lifecycle failures without holding the controller during the check;
/// a result for an older session epoch is never shown for a newer one.
async fn watch_health(shared: Shared, health: Health) {
    loop {
        tokio::time::sleep(HEALTH_EVERY).await;
        let (session, epoch) = {
            let c = shared.lock().await;
            (c.session.clone(), c.session_epoch)
        };
        let failure = match session {
            None => None,
            Some(s) => match tokio::time::timeout(HEALTH_TIMEOUT, s.lifecycle_health()).await {
                Ok(Ok(())) => None,
                Ok(Err(e)) => Some(e),
                Err(_) => Some("Connection health check timed out".into()),
            },
        };
        if let Ok(mut h) = health.lock() {
            *h = (epoch, failure);
        }
    }
}

#[cfg(unix)]
fn watch_signals(tx: mpsc::Sender<()>) {
    use tokio::signal::unix::{SignalKind, signal};
    for kind in [
        SignalKind::terminate(),
        SignalKind::hangup(),
        SignalKind::interrupt(),
    ] {
        let tx = tx.clone();
        if let Ok(mut stream) = signal(kind) {
            tokio::spawn(async move {
                while stream.recv().await.is_some() {
                    if tx.send(()).await.is_err() {
                        break;
                    }
                }
            });
        }
    }
}
#[cfg(not(unix))]
fn watch_signals(tx: mpsc::Sender<()>) {
    tokio::spawn(async move {
        while tokio::signal::ctrl_c().await.is_ok() {
            if tx.send(()).await.is_err() {
                break;
            }
        }
    });
}
