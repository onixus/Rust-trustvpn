# Профили: серверный контракт и интеграция

Этот документ описывает контракт, который используют клиенты R-TrustTunnel.
Серверная реализация и развёртывание находятся в отдельном проекте
[onixus/tunnel](https://github.com/onixus/tunnel). Примеры не содержат production credentials.

## Реализованный контракт

| Маршрут | Назначение |
|---|---|
| GET `/portal/v2/capabilities` | Версия, форматы, метод `one_time_code`, лимит профиля |
| POST `/portal/v2/enrollment-codes` | Код из браузерной сессии + CSRF, TTL 180 секунд |
| POST `/portal/v2/enroll` | `code`, `name`, `platform` → `token`, `device_id`, `expires_in` (30 дней) |
| GET `/portal/v2/devices` | Устройства владельца, браузерная сессия |
| DELETE `/portal/v2/devices/{id}` | Отзыв токена и grants через браузер + CSRF; не ротация VPN-пароля |
| GET `/portal/v2/profiles` | Список разрешённых metadata и revisions |
| POST `/portal/v2/profiles/{id}/export` | `format`, `revision`, `include_secrets`, `accept_losses` |
| POST `/portal/v2/profile-imports/preview` | `content`, `intent=external_stored`; preview TTL 600 секунд |
| POST `/portal/v2/profile-imports/{id}/commit` | Явное `consent`, `create` либо `replace` с проверкой ревизии |
| POST `/portal/v2/profiles/{id}/grants` | `device_id`, `allow` через браузерную сессию + CSRF |
| DELETE `/portal/v2/profiles/{id}` | Отзыв внешнего профиля владельцем с `If-Match` |

Форматы: `profile_json`, `endpoint_toml`, `cli_toml`, `tt`. Native-клиенты
используют Bearer-токен; браузерные изменения защищены CSRF. Права устройства
проверяются на сервере. Android не следует HTTPS redirects и хранит токен в
зашифрованном vault. Реальные пользовательские сценарии и различия платформ
описаны в [инструкции обмена профилями](portal.md).

## Проект дальнейшего API (не полный перечень реализованных возможностей)

Нумерованные разделы ниже сохраняют исходный архитектурный проект. Device-code
polling через `device-authorizations`/`device-tokens`, отдельные preference,
transfer и job endpoints, расширенные scopes/capabilities не следует считать
реализованными только на основании этого проекта. Для текущих интеграций
используйте таблицу выше и серверный код; протокол регистрации сейчас —
одноразовый код из панели, а не предлагаемый ниже OAuth-подобный polling.

API общий для первой волны Windows/Linux и второй Android/macOS. Device registration учитывает `platform=windows|linux|android|macos`, app/core version и capabilities; эти значения не являются доказательством доверия и не дают дополнительных scopes. Сервер предоставляет только опубликованные артефакты соответствующей платформы; несовместимые local policies обрабатывает клиентский preview, а не молчаливое удаление полей сервером.

## 1. Что меняется в существующей панели

Точки интеграции подтверждены на запущенной панели:

| Сейчас | Изменение |
|---|---|
| `app/conninfo.py` собирает параметры и вызывает deeplink exporter | Одна функция `resolve_effective_profile(config, settings)` без форматирования |
| `app/client_config.py` собирает CLI TOML по шаблону | Вызывать общий Rust codec через PyO3 |
| `app/deeplink.py` вызывает endpoint для каждого экспорта | Общая модель → codec; endpoint exporter оставить differential oracle в тестах |
| `app/routes_client.py`: GET `/config/{id}/download?fmt=toml|json|txt` | Сохранить старые контракты; новые форматы выдавать через v2 и UI |
| `app/routes_device.py`: enroll/me/locations/connect | Сохранить v1; новые v2 enrollment, profile/revision APIs |
| `app/routes_admin.py` и templates | Preview/commit импорта, выбор пользователя, права и отчёт потерь при экспорте |
| `app/config_mail.py` | Использовать тот же exporter, сохранить ручную email-доставку |

Ключевой инвариант: `decode(tt)`, `parse(endpoint.toml)`, `parse(client.toml)` и нормализованный JSON совпадают по общему набору endpoint/TLS/credentials/DNS полей. Платформенные поля сравниваются только там, где формат способен их представить. TOML и tt генерируются из одного immutable snapshot профиля и версии настроек сервера; изменение настроек не должно дать два разных профиля в одном письме/экспорте.

При переносе текущих профилей сохранять эффективные значения, даже если безопасные defaults нового клиента отличаются. Например, существующий TOML exporter выставляет `killswitch=false`, `has_ipv6=false`, `anti_dpi=false`, `mtu=1280`; это не повод молча переписать пользовательскую политику. UI предлагает безопасную миграцию отдельно.

## 2. Модель данных

Не переделывать `configs` в хранилище всех произвольных импортов. Сохранить его как источник локальных endpoint credentials и добавить:

| Таблица | Назначение |
|---|---|
| `profile_documents` | id UUID, owner_id, origin, linked_config_id nullable, revision, schema_version, metadata_json, encrypted_document, created/updated/revoked_at |
| `profile_device_grants` | profile_id, device_id, scope; уникальность пары, cascade revoke |
| `profile_import_jobs` | preview_id, owner/session/device binding, hash ввода, sealed payload, parsed report, expiry, base_revision, consumed_at |
| `profile_apply_jobs` | durable apply state: pending/applying/applied/failed, desired revision, previous revision, sanitized error |
| `device_authorizations` | hash(device_code), hash(user_code), expiry, poll interval, approved owner, consumed_at |
| `profile_transfers` | hash(transfer token), owner, target_device, profile revisions, expiry, consumed_at |
| `profile_audit_events` | actor, action, object, revision, result, timestamp; без контента/credentials |

Opaque imported credentials шифруются at rest: encryption key вне БД, отдельный root-only secret/key version; резервная копия БД без ключа недостаточна для восстановления. Это защита от утечки DB/backup, не end-to-end encryption: администратор работающего сервера потенциально имеет доступ. Существующие plaintext credentials переводятся отдельной reversible migration, без обещания мгновенного полного шифрования старой БД.

При создании профиля через device API originating device получает grant только на созданный объект. Остальные устройства владельца получают доступ после явного назначения в кабинете; user cookie видит собственные документы. Удаление профиля сохраняет tombstone без секретного payload, чтобы клиенты увидели отзыв при следующей синхронизации.

`profile_documents.origin`:

- `portal_managed` — локальный endpoint, credentials/TLS/address задаёт сервер, клиент хранит только разрешённые overrides;
- `external_stored` — перенесённый профиль другого endpoint, хранится/выдаётся владельцу, не применяется к нашему endpoint;
- `local` — только клиентское значение; при upload превращается в external_stored либо проходит admin provision.

При импорте переданный `owner_id`, `device_id`, managed flag, ACL, token или server revision не считается авторизацией. Владелец выводится из сессии; администратор выбирает его отдельным параметром разрешённой операции.

## 3. ProfileDocument v1 и семантика версий

Пример тела экспорта нового формата; значения `.example`/TEST-NET специально нерабочие:

```json
{
  "schema_version": 1,
  "name": "Example laptop",
  "endpoint": {
    "hostname": "vpn.example",
    "addresses": ["192.0.2.10:8443"],
    "custom_sni": "",
    "has_ipv6": false,
    "username": "example-user",
    "password": "EXAMPLE-NOT-A-REAL-PASSWORD",
    "certificate": "",
    "skip_verification": false,
    "upstream_protocol": "http2",
    "client_random_prefix": "",
    "anti_dpi": false
  },
  "policy": {
    "mode": "general",
    "kill_switch": "during_session",
    "allow_lan": false,
    "ipv6": "block",
    "dns_upstreams": ["tls://1.1.1.1"],
    "exclusions": [],
    "fallback": "disabled"
  }
}
```

На диске клиента password заменяется vault reference; export document собирается в памяти по явному запросу. UUID/revision/owner возвращаются в API envelope, не являются переносимыми правами внутри документа. Число schema_version относится к JSON, версия в tt TLV — к другому формату.

Для JSON v1 запрещены неизвестные security/policy keys; некритичные расширения допускаются только в `extensions` с namespace. Для неизвестной schema_version возвращается 422, не best-effort execution. Неподдержанные endpoint features отражаются в capabilities report. Эту модель предстоит оформить JSON Schema и OpenAPI при реализации; примеры здесь — проект контракта, не готовый SDK.

## 4. Привязка приложения к панели

Использовать отдельный device authorization flow, чтобы не передавать долговременный token в браузерный URL (как в текущем `/connect/approve`). Новый клиент по умолчанию работает с v2; v1 adapter используется лишь для совместимости и не расширяет права старого token.

1. Пользователь выбирает HTTPS portal origin. Это адрес кабинета, не обязательно адрес VPN и не порт 8443. Адрес обнаруживается/задаётся явно, а не угадывается из IP endpoint.
2. Клиент POST `/portal/v2/device-authorizations` с name/platform. Ответ: high-entropy `device_code`, короткий `user_code`, `verification_uri`, `expires_in=300`, `interval=5`.
3. Открыть системный браузер на проверенном origin; пользователь входит и подтверждает устройство и его scopes. Код и название показаны и в приложении, и на странице. POST approval требует CSRF и активную сессию. Короткий код ограничен rate limits по IP, аккаунту и authorization ID.
4. Клиент POST `/portal/v2/device-tokens` с device_code, соблюдая interval. Pending/slow_down/denied/expired различаются. Код атомарно одноразовый; в БД hashes. Ответ с device token только в HTTPS body, `no-store`.
5. `Authorization: Bearer <device-token>`; opaque случайный token хранится в vault, hash — на сервере. Срок предлагаемого token 30 дней, затем повторная привязка; renewal отдельным ADR. Scopes и grants выдаёт сервер, клиент не может сам расширить их.

`GET /portal/v2/capabilities` до входа возвращает только версии/форматы/enrollment methods, без endpoint settings/профилей. Старые серверы дают 404: UI предлагает файл/tt либо явно доступный legacy enrollment. Не делать hidden downgrade в небезопасный web callback.

Смена hostname, сертификата доверенного портала или origin не унаследует token. API client не следует cross-origin redirects; при любом redirect исключить перенос Authorization. Для частного CA пользователь импортирует CA отдельно в контекст портала; TLS trust VPN и web portal не смешивается.

## 5. HTTP API

Все новые authenticated responses: `Cache-Control: no-store`, `Referrer-Policy: no-referrer`; download дополнительно безопасный `Content-Disposition` и `X-Content-Type-Options: nosniff`. Body с секретами не логируется reverse proxy/APM. Браузер — same-origin cookie + CSRF для mutations; native — scoped Bearer без CORS wildcard. Каждая операция повторно проверяет active user, device revocation, ownership и grant.

| Метод и путь | Вход / результат | Право |
|---|---|---|
| GET `/portal/v2/capabilities` | schema/codec versions, supported formats, limits, enrollment | public, без секретов |
| POST `/portal/v2/device-authorizations` | name/platform → коды/verification_uri/TTL | public + rate limit |
| POST `/portal/v2/device-authorizations/approve` | user_code/decision → подтверждение | user session + CSRF |
| POST `/portal/v2/device-tokens` | device_code → token либо pending/error | proof of device_code |
| GET `/portal/v2/profiles` | курсор, limit≤100 → разрешённые metadata + revisions | profiles:list |
| GET `/portal/v2/profiles/{id}` | metadata/compatibility, без password | profiles:read + grant |
| POST `/portal/v2/profiles/{id}/export` | format + revision + include_secrets → bytes | profiles:export + grant |
| POST `/portal/v2/profile-imports/preview` | format/content/intent/base_revision → preview | profiles:import |
| POST `/portal/v2/profile-imports/{preview_id}/commit` | action/target_id/base_revision → result/job | profiles:import + ownership |
| PATCH `/portal/v2/profiles/{id}/preferences` | разрешённые overrides + If-Match → revision | profiles:preferences + grant |
| DELETE `/portal/v2/profiles/{id}` | If-Match → tombstone | owner для external; admin для managed |
| POST `/portal/v2/profile-transfers` | profile IDs/revisions + target_device → одноразовая ссылка | owner, explicit export |
| POST `/portal/v2/profile-transfers/redeem` | token → snapshot export | bound device + grant |
| POST `/admin/api/v2/profile-imports/preview` | content + owner + intent=provision_local → diff | admin session + CSRF |
| POST `/admin/api/v2/profile-imports/{id}/commit` | approved preview → apply job | admin session + CSRF |
| GET `/portal/v2/profile-jobs/{id}` | pending/applied/failed + revision | creator/owner; без сырого stderr |
| DELETE `/portal/v2/devices/{id}` | revoke token/grants/device credentials | owner либо admin; CSRF для cookie |

Export format enum: `endpoint_toml`, `cli_toml`, `tt`, `profile_json`. MIME: `application/toml`, `text/plain; charset=utf-8`, `application/json` соответственно. Архив `age` шифруется на клиенте; web backup может шифроваться в браузере отдельной проверенной реализацией и не входит в первый server milestone. Экспорт without secrets помечается `redacted=true` и непригоден для Connect; не выдавать его за рабочий профиль.

## 6. Импорт: двухфазный контракт

Native/file picker читает файл локально, определяет формат и показывает credential disclosure перед upload. Браузер может отправить multipart file; canonical API принимает `{format, content, intent}` с ограничением фактического decoded размера 1 MiB. ZIP/архивы и URL fetch на сервере в v1 не поддерживаются. Это исключает zip-slip, decompression bomb и SSRF через «импорт по адресу».

Пример preview:

```json
{
  "preview_id": "4e7687ba-b8d0-4b52-9fe4-f3443d9259a7",
  "expires_in": 600,
  "can_commit": true,
  "target_kind": "external_stored",
  "summary": {"name": "Example laptop", "endpoint": "vpn.example:8443"},
  "secrets_present": true,
  "warnings": [{"code": "LOCAL_POLICY_NOT_IN_TT", "field": "policy"}],
  "conflicts": [],
  "unsupported_features": [],
  "losses": []
}
```

Preview parser ничего не подключает и не применяет. Sealed content хранится ≤10 min, привязан к actor/session/device и hash, удаляется после commit/expiry. Ответ редактирует secrets. Commit не принимает новый произвольный content: применяет только одобренный snapshot. Idempotency-Key + уникальное `(actor, key)` предотвращают дубли при retry. Повтор возвращает тот же результат; повтор с другим body — 409.

Actions: `create`, `replace`, `merge_preferences`. `replace` требует target ownership и совпадения `base_revision`/If-Match; конфликт — 409 с redacted diff, а не last-write-wins. Managed credentials не меняются обычным пользовательским импортом. Все невалидные элементы пакетного импорта блокируют целый batch; никакого частичного создания без отдельного решения пользователя.

### External profile

Сохранить документ владельцу, не писать credentials/rules/hosts локального VPN. Сервер не проверяет пароль соединением на произвольный endpoint. Такая проверка выполняется только локальным клиентом по явному действию. Отзыв копии в панели не отзывает пароль на внешнем сервере — это явно указано в UI.

### Восстановление локального профиля администратором

Нужен отдельный `provision_local` intent. Показать сопоставление address/TLS/server identity с настроенным локальным endpoint; DNS-совпадение само по себе не доказывает принадлежность. Admin выбирает владельца. `username` collision, смена password, отключение TLS и private key upload не проходят молча. Новые credentials создаются только после отдельного diff; адрес, CA, hostname и серверные admission rules берутся из серверного trusted settings, а не из файла.

DB commit и перезагрузка endpoint не атомарны. Поэтому сначала durable pending job + previous snapshot, затем под apply-lock сформировать credentials и выполнить штатный `endpoint.manager.apply_credentials()`. Перед активацией проверить синтаксис; после — подтверждение загрузки/контролируемый probe. Только после подтверждения пометить applied и разрешить export новой ревизии. При сбое сохранить failed/pending state, старый рабочий snapshot и возможность retry/rollback. Crash reconciliation повторяет шаги идемпотентно. Не вернуть «импорт успешно подключён» только потому, что строка записана в SQLite.

## 7. Обновление, отзыв и ссылки передачи

Managed config revision обновляет endpoint-owned поля. Local DNS/routing override сохраняется лишь если разрешён серверной policy; credential, trust или hostname changes всегда показываются в diff. Active revision меняется через controlled reconnect, старая хранится для отката, если не отозвана сервером.

Одноразовая передача: HTTPS `<portal>/import#<random-token>`, TTL 180 s, привязка к владельцу и выбранному устройству. Сам token не URL query и не `tt://` payload. Native обработчик использует отдельную схему `rtrust://import?server=<encoded-origin>#<token>`; она не подменяет стандартный tt. Redemption POST требует device authorization; атомарно consumes token после проверки прав. Нет долгоживущих общедоступных subscription URLs. Browser page без сторонней аналитики; fragment очищается после получения. Для непривязанного устройства сначала enrollment, затем обычная загрузка разрешённых профилей.

Credential-bearing tt и transfer token различаются в UI: первая ссылка остаётся рабочей, пока не сменён VPN password; вторая истекает и одноразовая. Удаление device token не отзывает уже скачанный TOML автоматически. Для managed устройств нужен отдельный VPN username/password на устройство; revoke обновляет endpoint credentials. Проверить, прекращает ли текущий endpoint уже открытые сессии: до доказательства UI обещает запрет новых соединений, а не мгновенный разрыв всех активных потоков.

Ошибки общего envelope: `{error:{code, message, field?, retryable, request_id}}`. Коды: 401 token invalid/expired; 403 scope/user blocked; 404 неизвестный либо чужой profile; 409 revision conflict/apply pending; 410 preview/transfer expired; 413 input too large; 422 malformed/unsupported/insecure config; 429 rate limit с Retry-After; 503 exporter/apply temporarily unavailable. Ошибка не повторяет raw content/URL/password.
