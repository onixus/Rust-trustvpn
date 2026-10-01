//! Ask the desktop portal; never write the host's autostart directory.
use futures_util::StreamExt;
use std::collections::HashMap;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
pub fn request(enabled: bool) -> Result<(), String> {
    tokio::runtime::Runtime::new()
        .map_err(|_| "Не удалось создать запрос автозапуска")?
        .block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(120), async move {
                let bus = zbus::Connection::session()
                    .await
                    .map_err(|_| "Нет доступа к порталу рабочего стола")?;
                let sender = bus
                    .unique_name()
                    .ok_or("Нет идентификатора портала")?
                    .as_str()
                    .trim_start_matches(':')
                    .replace('.', "_");
                let token = format!(
                    "rtrust_{}_{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| "Некорректное время")?
                        .as_nanos()
                );
                let path = format!("/org/freedesktop/portal/desktop/request/{sender}/{token}");
                let request = zbus::Proxy::new(
                    &bus,
                    "org.freedesktop.portal.Desktop",
                    path.as_str(),
                    "org.freedesktop.portal.Request",
                )
                .await
                .map_err(|_| "Портал недоступен")?;
                let mut response = request
                    .receive_signal("Response")
                    .await
                    .map_err(|_| "Нет ответа портала")?;
                let portal = zbus::Proxy::new(
                    &bus,
                    "org.freedesktop.portal.Desktop",
                    "/org/freedesktop/portal/desktop",
                    "org.freedesktop.portal.Background",
                )
                .await
                .map_err(|_| "Портал автозапуска недоступен")?;
                let options: HashMap<&str, Value<'_>> = HashMap::from([
                    ("handle_token", Value::from(token.as_str())),
                    (
                        "reason",
                        Value::from("Запуск R-TrustTunnel при входе в рабочий стол"),
                    ),
                    ("autostart", Value::from(enabled)),
                    (
                        "commandline",
                        Value::from(vec!["rtrust-native", "--autostart"]),
                    ),
                    ("dbus-activatable", Value::from(false)),
                ]);
                let returned: OwnedObjectPath = portal
                    .call("RequestBackground", &("", options))
                    .await
                    .map_err(|_| "Рабочий стол не поддерживает портал автозапуска")?;
                if returned.as_str() != path {
                    return Err("Неожиданный ответ портала".into());
                }
                let message = response.next().await.ok_or("Портал закрыл запрос")?;
                let (code, values): (u32, HashMap<String, OwnedValue>) = message
                    .body()
                    .deserialize()
                    .map_err(|_| "Некорректный ответ портала")?;
                let granted = values.get("autostart").and_then(|v| bool::try_from(v).ok());
                if code != 0 || granted != Some(enabled) {
                    return Err("Изменение автозапуска не разрешено порталом".into());
                }
                Ok(())
            })
            .await
            .map_err(|_| "Время ожидания портала истекло")?
        })
}
