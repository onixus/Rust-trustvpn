# Технический долг — волна 3

## W3-HTTP3 — TrustTunnel HTTP/3 для системного VPN

Статус: реализовано, 2026-10-04 ([HTTP/3](http3.md)). Native runtime, always-on и
Android больше не подменяют HTTP/3 на HTTP/2; автоматического fallback нет.

Сделано:
- interop-проблема half-close с endpoint 1.1.0 воспроизведена и найдена в
  endpoint (FIN без DATA не будит читателя потока); клиент шлёт пустой DATA-кадр
  перед FIN и не шлёт GREASE;
- QUIC-сокет помечается (`SO_MARK`) или защищается (`protect`) до первого пакета;
  WFP и PF пропускают UDP к endpoint для HTTP/3-профилей;
- QUIC keepalive 10 с, idle timeout 30 с;
- Linux TUN и full tunnel E2E против endpoint 1.1.0 для HTTP/3, включая потерю
  endpoint, reconnect, аварии GUI/службы, always-on, смену сети и boot guard.

Остаётся проверить HTTP/3: Android VpnService на эмуляторе, системную службу
macOS, сон Windows, боевой сервер и сети с блокировкой/ограничением UDP.
Windows Wintun/full-tunnel E2E запускается параметром Jenkins
`WINDOWS_TRANSPORT=http3`.


## AmneziaWG 3: границы preview

AmneziaWG добавлен отдельным протоколом ([amneziawg.md](amneziawg.md)). Проверен
на уровне движка против официального `amneziawg-go` 3.1 (loopback), в Android
VpnService на эмуляторе (сетевая приёмка `ci/android.py`, третий протокол), в
Linux full-tunnel (`scripts/full-tunnel-interop.py --amneziawg`, в CI) и в Windows
full-tunnel (авторизованный прогон, не в CI).
Остаются:

- системный full-tunnel на macOS с профилем AmneziaWG, физическое
  Android-устройство, боевой сервер, сон Windows;
- без трафика приложение не замечает пропавший сервер: у WireGuard нет
  соединения, обнаружение идёт по четырём неотвеченным handshake;
- Windows: авторизованный прогон `ci/windows_authorized_full.py` с AmneziaWG на
  существующей установке прошёл 3 раза из 4; один сбой — сброс блокировки после
  обрыва GUI вернул не `Idle` — случился до того, как тест начал печатать ответ
  службы, причина не установлена. В обычном Jenkins этот сценарий не запускается;
- ссылки `vpn://` приложения Amnezia; несколько peer; roaming;
- ICMP внутри туннеля;
- cookie-ответы перегруженного сервера не проверены против эталона;
- двойная терминация потоков (стек TUN и стек туннеля): пропускная способность
  не измерялась;
- стадия `ci/amneziawg_interop.py` добавлена только в macOS Jenkins (нужен Go 1.26);
  в Linux-образе Go нет.

## Hysteria 2: границы preview

Hysteria 2 добавлен отдельным протоколом и не закрывает W3-HTTP3.
Port hopping, Gecko, mTLS, `pinSHA256`, bandwidth/Brutal, congestion и QUIC-параметры
реализованы и проверены против официального сервера 2.12.3 (loopback).
Остаются:

- `insecure` (в том числе вместе с `pinSHA256`) по-прежнему отклоняется: пин
  реализован только как дополнительная проверка поверх CA;
- ECH — требует HPKE из aws-lc-rs (новая нативная зависимость на всех платформах);
- Realms, Chrome parroting, mimic, `fastOpen`/`lazy` — не планируются;
- установленный macOS full-tunnel для Hysteria и физические проверки
  hopping/Brutal на реальной сети (сервер без port-range и bandwidth);
- Windows runtime, 30-минутный сон S3 (сеанс и Always-on службы) и Android Doze
  с системным Always-on проверены 3 октября против боевого сервера; cold boot
  пока не проверен;
- Android на MIUI после крэша процесса не перезапускает VPN (утечки нет, трафик
  заблокирован lockdown); проверить с разрешением «Автозапуск» и при
  необходимости восстанавливать подключение из приложения.

Официальный сервер ограничивает UDP-ответы буфером 4096 байт и не сохраняет
TCP half-close; эти сценарии нельзя объявлять полностью поддержанными. Потеря
сервера определяется по QUIC idle timeout (по умолчанию 30 с) плюс опрос
состояния; TUN и блокировка обхода сохраняются во время ожидания.
См. [точный объём и тесты](hysteria2.md).
