//! Opt-in, per-user login startup. Never starts or enables the VPN service.
use std::path::{Path, PathBuf};
type Result<T> = std::result::Result<T, String>;
const ARG: &str = "--autostart";
fn executable() -> Result<PathBuf> {
    let path = std::env::current_exe().map_err(|_| "Не удалось определить путь приложения")?;
    let value = path.to_str().ok_or("Путь приложения должен быть UTF-8")?;
    if !path.is_absolute() || value.chars().any(char::is_control) {
        return Err("Недопустимый путь приложения".into());
    }
    #[cfg(target_os = "linux")]
    if value.contains(['=', '%']) {
        return Err("Для автозапуска переместите приложение в каталог без знаков = и %".into());
    }
    #[cfg(target_os = "macos")]
    if value.starts_with("/Volumes/") || value.contains("/AppTranslocation/") {
        return Err("Сначала перенесите приложение в Applications и запустите его оттуда".into());
    }
    Ok(path)
}
pub fn enabled() -> Result<bool> {
    backend::read(&executable()?)
}
pub fn set(enabled: bool) -> Result<bool> {
    #[cfg(target_os = "linux")]
    if std::env::var_os("FLATPAK_ID").is_some() {
        crate::flatpak_startup::request(enabled)?;
    }
    // Disabling must also work after an application move.
    backend::write(enabled, if enabled { Some(executable()?) } else { None })?;
    if enabled { self::enabled() } else { Ok(false) }
}
#[cfg(any(target_os = "windows", test))]
fn windows_command(path: &str) -> Result<String> {
    if path.contains('"') || path.chars().any(char::is_control) {
        return Err("Недопустимый путь приложения".into());
    }
    let command = format!("\"{path}\" {ARG}");
    if command.encode_utf16().count() > 260 {
        return Err("Путь приложения слишком длинный для автозапуска Windows".into());
    }
    Ok(command)
}
#[cfg(any(target_os = "linux", test))]
fn desktop(path: &str) -> String {
    // Exec quoting is followed by Desktop Entry string escaping. No shell.
    let mut quoted = String::new();
    for ch in path.chars() {
        match ch {
            '%' => quoted.push_str("%%"),
            '\\' | '"' | '$' | '`' => {
                quoted.push('\\');
                quoted.push(ch);
            }
            _ => quoted.push(ch),
        }
    }
    let quoted = quoted.replace('\\', "\\\\");
    format!(
        "[Desktop Entry]\nType=Application\nName=R-TrustTunnel\nExec=\"{quoted}\" {ARG}\nTerminal=false\nHidden=false\nX-RTrustTunnel-Autostart=true\n"
    )
}
#[cfg(any(target_os = "macos", test))]
fn launch_agent(path: &str) -> String {
    let escaped = path
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;");
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>org.rtrusttunnel.Native.login</string><key>ProgramArguments</key><array><string>{escaped}</string><string>{ARG}</string></array><key>RunAtLoad</key><true/><key>LimitLoadToSessionType</key><string>Aqua</string></dict></plist>\n"
    )
}
#[cfg(not(target_os = "windows"))]
mod backend {
    use super::*;
    use std::fs;
    fn location() -> Result<PathBuf> {
        let dirs = directories::BaseDirs::new().ok_or("Не найден домашний каталог")?;
        #[cfg(target_os = "linux")]
        let path = if std::env::var_os("FLATPAK_ID").is_some() {
            dirs.config_dir().join("rtrust-portal-autostart")
        } else {
            dirs.config_dir()
                .join("autostart/org.rtrusttunnel.Native.desktop")
        };
        #[cfg(target_os = "macos")]
        let path = dirs
            .home_dir()
            .join("Library/LaunchAgents/org.rtrusttunnel.Native.login.plist");
        Ok(path)
    }
    fn contents(exe: &Path) -> Result<String> {
        let path = exe.to_str().ok_or("Путь приложения должен быть UTF-8")?;
        #[cfg(target_os = "linux")]
        let content = if std::env::var_os("FLATPAK_ID").is_some() {
            "R-TrustTunnel portal autostart granted\n".into()
        } else {
            desktop(path)
        };
        #[cfg(target_os = "macos")]
        let content = launch_agent(path);
        Ok(content)
    }
    fn check(path: &Path) -> Result<bool> {
        match fs::symlink_metadata(path) {
            Ok(m) if m.file_type().is_file() => Ok(true),
            Ok(_) => Err("Запись автозапуска не является обычным файлом".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err("Нет доступа к настройке автозапуска".into()),
        }
    }
    pub(super) fn read_at(path: &Path, exe: &Path) -> Result<bool> {
        if !check(path)? {
            return Ok(false);
        }
        let data = rtrust_store::read_bounded(path, 16 * 1024)
            .map_err(|_| "Не удалось прочитать автозапуск")?;
        let content = std::str::from_utf8(&data).map_err(|_| "Некорректная запись автозапуска")?;
        #[cfg(target_os = "linux")]
        if content.lines().any(|line| line.trim() == "Hidden=true") {
            return Ok(false);
        }
        if content == contents(exe)? {
            Ok(true)
        } else {
            Err("Запись автозапуска изменена или ссылается на другой путь. Включите настройку заново.".into())
        }
    }
    pub(super) fn write_at(path: &Path, exe: Option<&Path>) -> Result<()> {
        let exists = check(path)?;
        if let Some(exe) = exe {
            fs::create_dir_all(path.parent().ok_or("Некорректный путь автозапуска")?)
                .map_err(|_| "Не удалось создать каталог автозапуска")?;
            rtrust_store::write_private(path, contents(exe)?.as_bytes())
                .map_err(|_| "Не удалось сохранить автозапуск")?;
        } else if exists {
            fs::remove_file(path).map_err(|_| "Не удалось отключить автозапуск")?;
        }
        Ok(())
    }
    pub fn read(exe: &Path) -> Result<bool> {
        read_at(&location()?, exe)
    }
    pub fn write(enabled: bool, exe: Option<PathBuf>) -> Result<()> {
        write_at(&location()?, if enabled { exe.as_deref() } else { None })
    }
}
#[cfg(target_os = "windows")]
mod backend {
    use super::*;
    use winreg::{
        RegKey,
        enums::{HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE},
    };
    const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    const NAME: &str = "RTrustTunnel";
    pub(super) fn read_at(key: &RegKey, exe: &Path) -> Result<bool> {
        match key.get_value::<String, _>(NAME) {
            Ok(value) if value == windows_command(exe.to_str().ok_or("Некорректный путь")?)? => {
                Ok(true)
            }
            Ok(_) => Err("Автозапуск ссылается на другой путь. Включите настройку заново.".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err("Не удалось прочитать автозапуск Windows".into()),
        }
    }
    pub(super) fn write_at(key: &RegKey, exe: Option<&Path>) -> Result<()> {
        if let Some(exe) = exe {
            key.set_value(
                NAME,
                &windows_command(exe.to_str().ok_or("Некорректный путь")?)?,
            )
            .map_err(|_| "Не удалось сохранить автозапуск Windows")?;
        } else if let Err(e) = key.delete_value(NAME)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            return Err("Не удалось отключить автозапуск Windows".into());
        }
        Ok(())
    }
    pub fn read(exe: &Path) -> Result<bool> {
        match RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(RUN, KEY_READ) {
            Ok(key) => read_at(&key, exe),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err("Нет доступа к автозапуску Windows".into()),
        }
    }
    pub fn write(enabled: bool, exe: Option<PathBuf>) -> Result<()> {
        let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey_with_flags(RUN, KEY_READ | KEY_SET_VALUE)
            .map_err(|_| "Нет доступа к автозапуску Windows")?;
        write_at(&key, if enabled { exe.as_deref() } else { None })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn commands_quote_paths_without_shell_or_profile_secrets() {
        assert_eq!(
            windows_command(r"C:\Program Files\R-TrustTunnel\R-TrustTunnel.exe").unwrap(),
            r#""C:\Program Files\R-TrustTunnel\R-TrustTunnel.exe" --autostart"#
        );
        assert!(windows_command("bad\"command").is_err());
        assert!(windows_command(&"x".repeat(260)).is_err());
        let entry = desktop("/home/a b/$name%/client");
        assert!(entry.contains(r#"Exec="/home/a b/\\$name%%/client" --autostart"#));
        assert!(!entry.contains("sh -c"));
        let xml = launch_agent("/Applications/A & <B>/client");
        assert!(xml.contains("A &amp; &lt;B&gt;"));
        assert!(!xml.contains("KeepAlive"));
    }
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn isolated_file_enable_repair_disable_and_symlink_rejection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("login/entry");
        let exe = Path::new("/Applications/R Trust/client");
        assert!(!backend::read_at(&path, exe).unwrap());
        backend::write_at(&path, Some(exe)).unwrap();
        assert!(backend::read_at(&path, exe).unwrap());
        #[cfg(target_os = "macos")]
        assert!(
            std::process::Command::new("/usr/bin/plutil")
                .args(["-lint", "--"])
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        assert!(backend::read_at(&path, Path::new("/moved/client")).is_err());
        backend::write_at(&path, None).unwrap();
        backend::write_at(&path, None).unwrap();
        let foreign = dir.path().join("foreign");
        std::fs::write(&foreign, "preserve").unwrap();
        std::os::unix::fs::symlink(&foreign, &path).unwrap();
        assert!(backend::write_at(&path, Some(exe)).is_err());
        assert!(backend::write_at(&path, None).is_err());
        assert_eq!(std::fs::read_to_string(foreign).unwrap(), "preserve");
    }
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires gio desktop launcher"]
    fn desktop_entry_exec_roundtrip() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        // GLib checks the executable before expanding %% in Exec. Reject % in
        // production paths; exercise all other supported quoting characters here.
        let executable = dir.path().join("client space $`\"\\");
        let output = dir.path().join("argv.txt");
        std::fs::write(
            &executable,
            format!("#!/bin/sh\nprintf '%s' \"$1\" > '{}'\n", output.display()),
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let entry = dir.path().join("entry.desktop");
        backend::write_at(&entry, Some(&executable)).unwrap();
        assert!(
            std::process::Command::new("gio")
                .arg("launch")
                .arg(&entry)
                .status()
                .unwrap()
                .success()
        );
        for _ in 0..40 {
            if output.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert_eq!(std::fs::read_to_string(output).unwrap(), ARG);
    }
    #[cfg(target_os = "windows")]
    #[test]
    fn isolated_registry_roundtrip_never_touches_login_run_key() {
        use winreg::{RegKey, enums::HKEY_CURRENT_USER};
        let root = RegKey::predef(HKEY_CURRENT_USER);
        let path = format!(
            r"Software\RTrustTunnel\CI\{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let (key, _) = root.create_subkey(&path).unwrap();
        let result = std::panic::catch_unwind(|| {
            key.set_value("foreign", &"preserve").unwrap();
            let exe = Path::new(r"C:\Program Files\R-TrustTunnel\R-TrustTunnel.exe");
            assert!(!backend::read_at(&key, exe).unwrap());
            backend::write_at(&key, Some(exe)).unwrap();
            assert!(backend::read_at(&key, exe).unwrap());
            backend::write_at(&key, None).unwrap();
            assert!(!backend::read_at(&key, exe).unwrap());
            assert_eq!(key.get_value::<String, _>("foreign").unwrap(), "preserve");
        });
        drop(key);
        root.delete_subkey_all(path).unwrap();
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }
}
