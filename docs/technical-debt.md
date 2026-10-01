# Технический долг — волна 3

## W3-HTTP3 — HTTP/3 для системного VPN

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
