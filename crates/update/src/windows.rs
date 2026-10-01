use rtrust_update::*;
use std::{
    os::windows::{fs::OpenOptionsExt, process::CommandExt},
    path::Path,
    process::Command,
};
const NO_WINDOW: u32 = 0x08000000;
fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}
fn package(folder: &Path, release: &Release) -> Result<std::fs::File, String> {
    let path = artifact_path(folder, release);
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(path)
        .map_err(|_| "Не удалось заблокировать пакет обновления")?;
    verify_file(&mut file, release)?;
    Ok(file)
}
fn setup(folder: &Path, release: &Release, label: &str) -> Result<i32, String> {
    let path = artifact_path(folder, release);
    let path = path.to_str().ok_or("Недопустимый путь пакета")?;
    let log = folder.join(format!("{label}.log"));
    let log = log.to_str().ok_or("Недопустимый путь журнала")?;
    // Only verified fixed-path Setup receives elevation. Manifest supplies no arguments.
    let script = format!(
        "$ErrorActionPreference='Stop'; $account=[Security.Principal.WindowsIdentity]::GetCurrent().Name; $args='/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /ACCOUNT=\"'+$account+'\" /LOG=\"'+{}+'\"'; $p=Start-Process -FilePath {} -ArgumentList $args -Verb RunAs -Wait -PassThru; Write-Output $p.ExitCode",
        quote(log),
        quote(path)
    );
    let out = Command::new("powershell.exe")
        .creation_flags(NO_WINDOW)
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .map_err(|_| "Не удалось запустить установщик")?;
    if !out.status.success() {
        return Err("Запуск установщика отклонён или UAC отменён".into());
    }
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .map_err(|_| "Установщик не вернул результат".into())
}
fn smoke() -> Result<(), String> {
    let exe = std::path::PathBuf::from(std::env::var_os("ProgramFiles").ok_or("Нет ProgramFiles")?)
        .join("R-TrustTunnel/R-TrustTunnel.exe");
    let mut child = Command::new(&exe)
        .arg("--ci-smoke")
        .spawn()
        .map_err(|_| "Новая версия не запускается")?;
    for _ in 0..100 {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| "Не удалось проверить приложение")?
        {
            return if status.success() {
                Ok(())
            } else {
                Err("Проверка приложения завершилась ошибкой".into())
            };
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
    Err("Приложение не завершило проверку".into())
}
fn wait_parent(pid: u32) -> Result<(), String> {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_INVALID_PARAMETER, GetLastError, WAIT_OBJECT_0},
        System::Threading::{OpenProcess, WaitForSingleObject},
    };
    unsafe {
        let handle = OpenProcess(0x00100000, 0, pid);
        if handle.is_null() {
            return if GetLastError() == ERROR_INVALID_PARAMETER {
                Ok(())
            } else {
                Err("Не удалось проверить завершение клиента".into())
            };
        }
        let result = WaitForSingleObject(handle, 30000);
        CloseHandle(handle);
        if result != WAIT_OBJECT_0 {
            return Err("Клиент не завершился; обновление отменено".into());
        }
    }
    Ok(())
}
pub async fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 {
        return Err("Expected transaction directory and parent PID".into());
    }
    let folder = std::fs::canonicalize(&args[0]).map_err(|_| "Каталог обновления недоступен")?;
    let root = std::fs::canonicalize(cache_dir()?).map_err(|_| "Кэш обновлений недоступен")?;
    if folder.parent() != Some(root.as_path()) {
        return Err("Недопустимый каталог транзакции".into());
    }
    let pid = args[1]
        .to_str()
        .and_then(|v| v.parse().ok())
        .ok_or("Некорректный PID")?;
    let result = apply(&folder, pid).await;
    let status = if result.is_ok() {
        "Обновление установлено и проверено."
    } else {
        result.as_ref().err().unwrap()
    };
    rtrust_store::write_private(&folder.join("result.txt"), status.as_bytes())
        .map_err(|_| "Не удалось записать результат обновления")?;
    result
}
async fn apply(folder: &Path, pid: u32) -> Result<(), String> {
    apply_with_health(folder, pid, smoke, true).await
}
async fn apply_with_health(
    folder: &Path,
    pid: u32,
    mut health: impl FnMut() -> Result<(), String>,
    restart: bool,
) -> Result<(), String> {
    let release = verify(
        &rtrust_store::read_bounded(&folder.join("release.json"), 16384)
            .map_err(|_| "Нет манифеста")?,
        &target(),
        now()?,
        CURRENT_SEQUENCE + 1,
    )?;
    let rollback = verify_rollback(
        &rtrust_store::read_bounded(&folder.join("rollback.json"), 16384)
            .map_err(|_| "Нет манифеста отката")?,
    )?;
    let _new_lock = package(folder, &release)?;
    let _old_lock = package(folder, &rollback)?;
    wait_parent(pid)?;
    let permit = rtrust_control::Client::prepare_update().await?;
    let (_, vault) = rtrust_store::snapshot()
        .map_err(|_| "Не удалось проверить и сохранить хранилище перед обновлением")?;
    if let Some(bytes) = vault {
        rtrust_store::write_private(&folder.join("profiles-before.rtrust"), &bytes)
            .map_err(|_| "Не удалось сохранить резервную копию")?;
    }
    let code = setup(folder, &release, "install")?;
    drop(permit);
    let check = if code == 0 {
        health()
    } else {
        Err("Установщик завершился с ошибкой".into())
    };
    if check.is_err() {
        // A new active VPN or retained guard prevents rollback from clearing protection.
        let _permit=rtrust_control::Client::prepare_update().await.map_err(|_|"Обновление не прошло проверку. Автооткат остановлен: служба недоступна, занята или сохраняет защиту. Резервный пакет оставлен в кэше.")?;
        if setup(folder, &rollback, "rollback")? != 0 || health().is_err() {
            return Err("Автооткат не прошёл проверку; пакеты и журналы сохранены".into());
        }
        return Err("Обновление не прошло проверку; предыдущая версия восстановлена".into());
    }
    if !restart {
        return Ok(());
    }
    let exe = std::path::PathBuf::from(std::env::var_os("ProgramFiles").ok_or("Нет ProgramFiles")?)
        .join("R-TrustTunnel/R-TrustTunnel.exe");
    Command::new(exe)
        .spawn()
        .map_err(|_| "Обновление установлено; запустите приложение вручную")?;
    Ok(())
}

pub fn notify_error(error: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
    let message: Vec<u16> = error.encode_utf16().chain(Some(0)).collect();
    let title: Vec<u16> = "R-TrustTunnel: обновление"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            message.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "Requires explicitly authorized Windows installation maintenance and signed real packages"]
    async fn real_signed_upgrade_and_health_failure_rollback() {
        let folder = std::path::PathBuf::from(
            std::env::var_os("RTRUST_UPDATE_TEST_TRANSACTION")
                .expect("prepared signed package transaction required"),
        );
        let mut calls = 0;
        let failed = apply_with_health(
            &folder,
            0,
            || {
                calls += 1;
                if calls == 1 {
                    Err("synthetic health failure".into())
                } else {
                    smoke()
                }
            },
            false,
        )
        .await;
        assert_eq!(calls, 2, "rollback must run its health check");
        assert!(
            failed
                .unwrap_err()
                .contains("предыдущая версия восстановлена")
        );
        apply_with_health(&folder, 0, smoke, false)
            .await
            .expect("real upgrade must succeed after rollback check");
    }
}
