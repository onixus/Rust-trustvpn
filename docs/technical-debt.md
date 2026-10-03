# Технический долг — волна 3

## W3-HTTP3 — TrustTunnel HTTP/3 для системного VPN

Статус: отложено в волну 3 по решению пользователя, 2026-09-30.

Область: HTTP/3 в системном packet-tunnel, прежде всего Windows Wintun и Linux TUN/full-tunnel; адаптеры Android/macOS также принимаются отдельно в этой волне после появления их системного VPN. HTTP/3 для SOCKS5 уже
реализован и остаётся в текущей поставке. Сейчас native UI выбирает HTTP/2
для runtime-копии системного подключения, сохраняя исходный профиль без изменений.

Работы и критерии приёмки:
- QUIC transport в системном packet-to-flow пути, корректные TCP half-close и
  backpressure; воспроизвести и устранить interop-проблему с endpoint 1.1.0.
- QUIC endpoint bypass, reconnect, смена адреса endpoint и сети без маршрутизации
  транспорта в собственный TUN и без обхода kill switch.
- TCP/UDP/DNS, долгие потоки, потеря/блокировка UDP, MTU, sleep/resume,
  аварии GUI/службы и восстановление маршрутов/WFP/nftables.
- Реальный E2E на Windows и Linux против официального endpoint, отрицательные
  TLS/auth tests; сохранить действующие HTTP/2 и SOCKS HTTP/3 проверки.
- Убрать принудительный HTTP/2 из native runtime только после этих проверок.
  Политика fallback должна быть явной; TLS verification не ослабляется.

Это отложенная функциональность, а не заявление о поддержке HTTP/3 в TUN.


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
- Windows runtime, 30-минутный сон S3 и Android Doze проверены 3 октября против
  боевого сервера; cold boot и Always-on после сна пока не проверены.

Официальный сервер ограничивает UDP-ответы буфером 4096 байт и не сохраняет
TCP half-close; эти сценарии нельзя объявлять полностью поддержанными. Потеря
сервера определяется по QUIC idle timeout (по умолчанию 30 с) плюс опрос
состояния; TUN и блокировка обхода сохраняются во время ожидания.
См. [точный объём и тесты](hysteria2.md).
