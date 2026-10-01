# Основания проекта

Дата проверки: 2026-09-30, Europe/Istanbul. Инвентаризация read-only. Ниже отделены факты текущего осмотра от проектных решений.

## Подтверждено сейчас

- Рабочий каталог проекта до подготовки документов был пустым каталогом без `.git`, исходников и AGENTS.md.
- Целевой сервер работает на Linux; SSH-адрес и hostname не публикуются.
- Контейнер `trusttunnel-web`, image `trusttunnel-web:dns-20260929`, status `running healthy`.
- Docker publishes TCP/UDP `8443`, web backend `127.0.0.1:18082 -> 8000`.
- GET `http://127.0.0.1:18082/healthz` на сервере вернул `{"status":"ok"}`. Это проверка панели, не доказательство рабочего VPN data plane.
- `/opt/trusttunnel/trusttunnel_endpoint --version` внутри контейнера: `1.1.0`.
- Исходники панели `/opt/trusttunnel-web/app`; production mounts `/data`, `/certs`.
- Хэши пяти файлов на host совпали с `/app/app/*.py` внутри контейнера.

| Файл | SHA-256 |
|---|---|
| client_config.py | d462e713f632a099febd566c7e5d11e6131fa7b5a6f114f567e8935b050a4a8a |
| conninfo.py | 02264e713a46adc9b61f04d2e00682eb59182e2a23ef7cca9468a462f064499f |
| deeplink.py | dccbb0cab2ae5c830bad8c848b245e024b3d201f00d297af037a06864cbb818b |
| routes_device.py | 1b8aa773506a99322b3dfb5988b4c9a72ace6a0fe494c1ebad59109b16f952de |
| routes_client.py | d103391688625f1708a2d8d404ef62c90047578853d194b9598d45aaf1a11234 |

## Выводы из кода панели

Существуют file downloads TOML/JSON/TXT, официальный генератор tt links, пользовательские и admin страницы, email export, `X-Device-Token` API, enrollment QR/code и web loopback callback.

TOML и tt используют разные serializers и источники отдельных defaults. `conninfo.py` использует effective domain/address/SNI, `client_config.py` вручную формирует defaults/CA, а `deeplink.py` запускает endpoint с VPN/hosts config и переданным username. Это подтверждённый риск расхождения, **не доказанное расхождение реального профиля**: production profile contents не читались.

`/connect/approve` возвращает raw device token в query redirect URL. Для нового v2 предложен flow с выдачей token в HTTPS body. В обработчике не видно CSRF-проверки, но глобальная защита целиком не аудитировалась; это пункт обязательной проверки, не утверждение о доказанной эксплуатации.

`webauth.current_user` проверяет active user; device API дополнительно проверяет device revocation. Обработчик `/config/{id}/download` проверяет ownership, но явно не проверяет revoked_at профиля. Новые export APIs должны проверять все уровни. Полный security audit существующей панели в этот проект не входит.

Git commit сервера установить не удалось: `git` на host отсутствует. Поэтому snapshot привязан к image tag и file hashes, не к предположительному commit из старой памяти.

## Проверенные upstream snapshots

Публичные репозитории read-only клонированы во временный каталог, без запуска их кода:

- TrustTunnel: `81eb23995b7d45aac7aeeac286040cc499b945c7`.
- TrustTunnelClient: `105f39092e9ea517b4997541764c6f3b8b87e300`.

Текущий upstream master и deployed endpoint 1.1.0 — разные compatibility targets; совпадение версий форматов нельзя предполагать без fixtures.

Первичные источники:

- [Wire protocol](https://github.com/TrustTunnel/TrustTunnel/blob/81eb23995b7d45aac7aeeac286040cc499b945c7/PROTOCOL.md).
- [tt URI format](https://github.com/TrustTunnel/TrustTunnel/blob/81eb23995b7d45aac7aeeac286040cc499b945c7/DEEP_LINK.md).
- [Rust deeplink decoder](https://github.com/TrustTunnel/TrustTunnel/blob/81eb23995b7d45aac7aeeac286040cc499b945c7/deeplink/src/decode.rs).
- [Endpoint TOML exporter](https://github.com/TrustTunnel/TrustTunnel/blob/81eb23995b7d45aac7aeeac286040cc499b945c7/lib/src/client_config.rs).
- [CLI TOML fields](https://github.com/TrustTunnel/TrustTunnelClient/blob/105f39092e9ea517b4997541764c6f3b8b87e300/trusttunnel/README.md).
- [iced](https://github.com/iced-rs/iced), [smoltcp](https://docs.rs/smoltcp/latest/smoltcp/), [h3](https://docs.rs/h3/latest/h3/).
- [Wintun distribution and signed DLL](https://www.wintun.net/).
- [WFP filter lifetime](https://learn.microsoft.com/en-us/windows/win32/fwp/basic-operation).
- [systemd-resolved D-Bus API](https://www.freedesktop.org/software/systemd/man/247/org.freedesktop.resolve1.html).

## Пока не проверено

- Реальное подключение нового Rust engine — engine не реализован.
- GUI поведение действующего клиента и конкретные пользовательские баги; они не воспроизводились в этой сессии.
- Публичный origin панели, reverse-proxy configuration и фактический сертификат/профили не извлекались.
- Настроенные server admission rules, необходимость client_random и TLS fingerprint в текущей сети.
- Немедленное прекращение активных VPN-сессий после смены credentials.
- Совместимость всех библиотек, производительность, лицензии полного dependency tree, поддержка каждого Linux desktop.

Все новые API, UI states, сроки token, лимиты и схемы таблиц в соседних документах являются предложением, а не установленными настройками сервера.
