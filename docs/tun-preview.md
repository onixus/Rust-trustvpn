# Экспериментальный Linux TUN

`rtrust-tun` — отдельный backend для разработки системного VPN. CLI запускается отдельно; для подключения из desktop UI добавлена [Linux-служба](linux-service.md) с per-UID маршрутами и восстановлением после аварии. Backend читает обычный профиль (TOML, JSON или файл с `tt://`), проверяет transport capabilities и аутентификацию, затем создаёт непостоянный Linux TUN. Официальный CLI не запускается.

```sh
cargo build -p rtrust-tun --locked
# Только внутри подготовленной тестовой сети, с CAP_NET_ADMIN и /dev/net/tun:
target/debug/rtrust-tun profile.json rtrust0 10.77.0.2
```

Готовые локальные debug-сборки backend: `dist/tun-preview-linux/rtrust-tun` (ARM64) и `dist/tun-preview-linux-x64/rtrust-tun` (x86_64). Они не являются установщиками; x86_64 проверен сборкой, runtime-стенд выполнен на ARM64.

Создаётся интерфейс с адресом `/32` и MTU 1500; существующее имя отклоняется. Приложение не назначает default route, DNS или firewall. Маршрут к endpoint должен оставаться вне TUN. Не следует направлять через этот preview весь трафик рабочей машины: IPv6 и kill switch ещё не реализованы. При удалении TUN система может воспользоваться другим существующим маршрутом — backend не обеспечивает защиту от утечки вне тестовой изолированной сети.

## Реализованный data plane

- IPv4 TCP: smoltcp, проверка IP/TCP checksums до выделения flow, повторные SYN не создают новые соединения. 128 flows, по 32 KiB send/receive buffers стека и bounded duplex bridge. Выходная очередь — 256 пакетов, вход — один пакет; переполнение приводит к отбрасыванию и TCP retransmission. Тайм-аут неактивности — 300 секунд.
- IPv4 UDP: `_udp2`, очереди по 64 датаграммы, до 256 source/destination mappings с 60-секундным временем ожидания ответа. Ответ принимается только для активной пары адресов. Максимальный payload — 1472 байта; IP-фрагментация не реализована.
- Принимаются пакеты только с назначенным TUN source IP. Неверные длины, checksum, IP options, fragments, IPv6 и ICMP отбрасываются. Успешные ответы ping не имитируются.
- Сохраняется TCP half-close. Ошибка открытия отдельного TCP tunnel вызывает reset его локального соединения. Ошибка общей session/UDP stream останавливает backend.
- SIGINT/SIGTERM, завершение процесса или ошибка закрывают TUN fd; штатное завершение отменяет TCP/UDP tasks. Интерфейс и связанные с ним маршруты удаляются ядром.

Для HTTP/2 используется [bounded compatibility patch h2](../vendor/h2/RTRUST-PATCH.md): пустые DATA-кадры при backpressure не расходуют невосстановимый лимит всей сессии; полезный трафик восстанавливает ограниченный budget. Защита от пустого flood сохраняется.

Поддержан **только HTTP/2**. При проверке официального endpoint 1.1.0 HTTP/3 передал 512 KiB, но half-close не дошёл до TCP-сервера. Контрольный SOCKS-сценарий воспроизвёл проблему без нового IP-стека. До устранения этой несовместимости helper отклоняет HTTP/3 до создания интерфейса, без автоматической смены транспорта профиля.

Ещё одно ограничение endpoint 1.1.0: одиночная пустая UDP-датаграмма может ждать следующего кадра. Пустой payload сохраняется адаптером; interop проверяет его вместе со следующей датаграммой. Это не гарантия своевременной доставки одиночного пустого пакета.

## Воспроизводимый стенд

Нужны Docker и официальный Linux endpoint 1.1.0 подходящей архитектуры. Скачайте и распакуйте release в отдельный каталог; ниже ARM64-пример. Каталог проекта передаётся read-only, build cache — отдельным Docker volume. Контейнер не использует host networking.

```sh
docker run --rm --cap-add NET_ADMIN --cap-add SYS_ADMIN --device /dev/net/tun \
  -v "$PWD:/work:ro" \
  -v rtrust-linux-target:/work/target \
  -v rtrust-linux-cargo:/usr/local/cargo/registry \
  -v /absolute/path/to/endpoint-directory:/fixture:ro \
  -w /work rust:1-bookworm sh -c '
    apt-get -o Acquire::http::Timeout=15 update -qq &&
    apt-get install -y -qq iproute2 curl python3 libdbus-1-dev &&
    cargo build -p rtrust-tun -p rtrust-inspect --locked &&
    python3 scripts/tun-interop.py /fixture/trusttunnel_endpoint
  '
```

`scripts/tun-interop.py` отказывается работать вне root Docker-контейнера. Он создаёт namespace, veth, синтетический TLS-сертификат и профиль, отдельный официальный endpoint, HTTP/TCP/UDP/DNS-серверы. У клиента нет прямого маршрута к тестовым сервисам; маршрут появляется только через TUN. Namespace получает отдельный `resolv.conf` для проверки обычного `getaddrinfo`; это настройка стенда, не реализация DNS manager в клиенте.

Проверки: HTTP body 512 KiB, 12 загрузок в 4 параллельных потоках, 512 KiB upload + half-close + полный ответ, DNS A lookup, UDP payload 1/512/1472 и пустой с follow-up, удаление интерфейса по SIGTERM, отказ HTTP/3 до создания интерфейса, аварийная остановка endpoint и отсутствие прямого fallback в namespace. Unit tests дополнительно проверяют повторные SYN, лимиты, истечение flows и malformed packets.

Следующий этап: служба с ограниченным IPC, управление маршрутами/DNS/IPv6 и firewall, затем включение системного режима из GUI. Windows Wintun, Android VpnService и macOS Network Extension ещё не подключены.
