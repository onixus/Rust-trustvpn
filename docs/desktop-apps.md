# Полноценные desktop-приложения и выбор UI

Статус: целевой проект. Native preview уже реализован; его фактические возможности и сборки описаны в [implementation.md](implementation.md). Системные службы Windows/Linux и Windows Native Setup реализованы. Выбор UI в установщике остаётся в плане. Для следующей Linux-поставки пользователь выбрал Flatpak (см. текущий порядок в delivery.md).

Этот документ описывает первую волну Windows/Linux. Во второй волне добавляется macOS с тем же выбором desktop UI и Android с нативным мобильным интерфейсом; системные ограничения и поставка описаны в [android-macos.md](android-macos.md).

## 1. Два типа интерфейса

| Выбор при установке | Реализация | Пользовательский запуск |
|---|---|---|
| **Нативный — по умолчанию** | Rust + iced, собственный desktop renderer | Обычное окно приложения, без браузера/WebView |
| **WebView** | Tauri, Rust host, локальные HTML/CSS/JS assets | Обычное окно приложения с иконкой и tray; браузер открывается только для входа в панель |
| **Оба интерфейса** | Оба frontend + общий launcher/controller | Один основной ярлык, выбранный UI; переключение в настройках |

На Windows оба варианта имеют исполняемые `.exe`; на Linux оба устанавливаются как desktop applications. Серверная веб-панель остаётся отдельным продуктовым интерфейсом. HTML-макет из чата — иллюстрация сценариев, его не поставляем в приложение как готовую реализацию.

Первый runnable milestone — Native для обеих ОС. В поставке, объявленной поддерживающей выбор UI, доступны оба frontend и их одинаковые основные функции; до готовности второго не показывать неработающий выбор в установщике.

## 2. Windows

Поставляемый набор:

- `R-TrustTunnel-Setup.exe` — подписанный графический bootstrapper для установки/изменения/удаления компонентов.
- `R-TrustTunnel.msi` — внутренний/корпоративный installer с теми же component IDs и machine service.
- `R-TrustTunnel.exe` — пользовательский GUI launcher, сборка без консольного окна.
- `rtrust-ui-native.exe` / `rtrust-ui-webview.exe` — установленные frontend binaries.
- `rtrust-service.exe` — Windows Service и один экземпляр network engine на машину.
- Signed `wintun.dll` — поставляемая зависимость нужной архитектуры, фиксированный источник/hash и безопасный DLL search path.

Пользователь запускает Setup двойным щелчком → выбирает UI → видит компоненты/зависимости → подтверждает UAC → запускает приложение из меню «Пуск» или ярлыка. Повторного UAC для обычного Connect/Disconnect нет. Запуск `R-TrustTunnel.exe` при отсутствующей службе показывает «Установить компонент VPN», а не ошибку с требованием открыть терминал.

Native installation не устанавливает WebView runtime. Для WebView bootstrapper проверяет WebView2 и при необходимости предлагает официальный dependency package; offline bundle включает допустимый redistributable. Нельзя скачивать произвольный runtime из непроверенного mirror. [Зависимости Tauri](https://v2.tauri.app/start/prerequisites/).

Setup устанавливает system-wide service и защищённые binaries, но UI запускает обратно от исходного пользователя, не от elevated token. Default UI хранится per-user; installer задаёт только начальный выбор. Корпоративный silent install использует явные MSI properties (`UI_NATIVE`, `UI_WEBVIEW`, `DEFAULT_UI` — проектные имена), без GUI prompts; service обязателен для desktop VPN installation.

Интеграция: Start Menu, optional desktop shortcut, Taskbar app identity, notification area, toast notifications, автозапуск UI по отдельной настройке. Автозапуск приложения и автоподключение системной службы — разные опции. `tt://` и расширение `.rtrust.json` открываются через launcher. Нельзя назначать приложению все `.toml`/`.json` файлы; импорт произвольного TOML доступен в диалоге приложения и через «Открыть с помощью».

MSI содержит независимые Native/WebView features и общий core component. Удаление frontend не удаляет службу, пока нужен другой; полный uninstall останавливает VPN по согласованному recovery flow. Профили удаляются только отдельным отмеченным пользователем действием.

## 3. Linux и KDE Plasma

Native — полноценное окно в Plasma с пунктом меню, иконкой task manager, tray и уведомлениями. KDE integration не требует переписывания всего UI на Qt: Rust/iced сохраняется, системные функции выполняются через desktop interfaces. Точное повторение Breeze widgets не обещается; масштабирование, theme preference, keyboard navigation и доступность обязательны.

Компоненты packaging:

| Пакет | Содержимое |
|---|---|
| `rtrust-service` | systemd service, privileged helper, network engine, ограниченная polkit policy |
| `rtrust-desktop-common` | launcher, controller, desktop entry, icons, AppStream metadata |
| `rtrust-ui-native` | iced frontend без WebKitGTK зависимости |
| `rtrust-ui-webview` | Tauri frontend и declared WebKitGTK runtime dependencies |
| `rtrust-desktop` | удобный metapackage для рекомендуемой Native установки |

Публикуются deb/rpm для выбранных поддерживаемых дистрибутивов. GUI setup — маленькое нативное приложение, запускаемое пользователем из извлечённого подписанного дистрибутива. Оно показывает выбор интерфейса и передаёт package install/изменение package set штатному PackageKit/distro backend с polkit. Не выполнять shell script, полученный по URL. Перед авторизацией показать точный набор пакетов, источник и подпись. Не обещать один универсальный бинарник для любого дистрибутива: runtime/baseline мастерa проверяется на целевой матрице.

Обычная установка через Discover тоже поддерживается: отдельные Native/WebView packages или metapackage. Скрипты deb/rpm не открывают GUI и не задают интерактивных вопросов. Если дистрибутивный package manager уже выбрал вариант, первый запуск показывает установленные UI; дополнительный frontend устанавливается через системный GUI с подтверждением. Для явного выбора **до установки** используется GUI setup с одним экраном компонентов.

Обязательная интеграция KDE:

- `.desktop` entry, `Terminal=false`, `Exec=rtrust %U`, совпадающий Wayland app ID/icon и AppStream ID. Регистрация `x-scheme-handler/tt` только с соблюдением выбранного пользователем default handler.
- Plasma launcher/KRunner и действие «Открыть» из tray запускают одну пользовательскую UI-сессию.
- StatusNotifierItem/DBusMenu: Connect, Disconnect, профиль, открытие окна, выход; при отсутствии tray приложение остаётся доступно через launcher.
- Уведомления через desktop notification service; actions открывают соответствующий экран, не передают credentials.
- File dialogs через desktop portal с KDE backend, drag-and-drop, системная светлая/тёмная тема, fractional scaling и multi-monitor DPI.
- Проверка KWallet/Secret Service availability: если backend недоступен или закрыт, показать разблокировку/парольное хранилище; plaintext fallback запрещён.
- UI работает в пользовательской Wayland session. Root service не получает DISPLAY/WAYLAND socket и не рисует окон.

Пункт меню должен корректно запускать приложение без терминала. Применение `.desktop` и app metadata проверяется по [документации KDE](https://develop.kde.org/docs/features/desktop-file/). AppImage/Flatpak могут быть последующими frontend-пакетами; установка privileged service через них не считается решённой автоматически.

## 4. Экран установщика

```text
R-TrustTunnel — компоненты

Тип интерфейса:
  (●) Нативный — рекомендуемый
      Обычное desktop-приложение без WebView.
  ( ) WebView
      Desktop-приложение с интерфейсом на веб-технологиях.
  ( ) Оба — можно переключать в настройках

Если выбраны оба: основной интерфейс [Нативный ▾]

[✓] VPN-служба и сетевые компоненты  (обязательно)
[ ] Запускать приложение при входе
[ ] Сделать обработчиком tt-ссылок

Зависимости и объём установки: <рассчитаны для выбора>
                                  [Назад] [Установить]
```

Автоподключение VPN не включается установщиком, пока нет профиля и явного выбора пользователя. Linux helper запрашивает права только на пакетную операцию; Windows UAC нужен для machine components. Выбор типа UI сам по себе не меняет networking/security policy.

## 5. Один backend, переключаемые frontend

```text
OS shortcut / tt handler / file open
                ↓
     общий launcher + UI broker
        ↙                   ↘
 Native: iced          WebView: Tauri
        ↘                   ↙
      Rust application controller
    profile store · vault · portal API
                ↓
     authenticated versioned IPC
                ↓
        одна rtrust-service
```

Controller — общий Rust код, запускаемый в активном frontend host. Launcher/broker обеспечивает single-instance per UID/SID и координирует передачу UI ownership. State engine и активная VPN session принадлежат службе. Профили/vault принадлежат пользователю; их schema и path одинаковы у двух UI. Пароли, device tokens и диагностика не копируются при переключении интерфейса.

Настройки → «Интерфейс» → Native/WebView. Новый host проверяет IPC compatibility и получает полный snapshot состояния; затем launcher передаёт ownership и закрывает предыдущий GUI. Нет второго tray icon, двух reconnect timers или смены профиля. При ошибке запуска нового frontend прежний остаётся; VPN продолжает работать. Незавершённый import/edit сначала сохранить/отменить, а не терять при переключении. Если второго UI нет, предложить установить компонент через maintenance UI.

URI/file association всегда принадлежит launcher, а не конкретному frontend. Импорт по двойному щелчку работает с текущим UI и не вызывает Connect автоматически. UI preference меняется атомарно после успешного открытия нового окна, сохраняется при upgrade/rollback.

## 6. Граница WebView

WebView загружает только bundled assets из подписанного приложения, без remote scripts/CDN и без локального HTTP-control server. Все domain operations идут через узкие typed Rust commands. JS не получает unrestricted shell, filesystem, service pipe, vault enumeration или admin token. Раскрытие password возможно только для явного UI действия пользователя и ограниченного payload; нельзя вернуть всё хранилище фронтенду при старте.

CSP, окно-specific capabilities, запрет remote navigation и allowlist команд обязательны. Вход в серверную панель открывается в системном браузере, server HTML не исполняется в привилегированном WebView. [Модель capabilities Tauri](https://v2.tauri.app/security/capabilities/).

View model, validation, import/export, state transitions и network policies общие. Переписывается только представление; security invariants не зависят от frontend. Оба UI должны работать offline с локальными профилями.

## 7. Приёмка установки и desktop UX

1. Чистая Windows VM: Setup.exe → Native → запуск из Start Menu; ни консоли, ни browser window, ни WebView dependency.
2. Windows WebView/Both: dependency install, один ярлык, переключение UI, сохранность профилей и active VPN.
3. Plasma Wayland на поддерживаемых deb/rpm системах: GUI setup/Discover → запуск из меню → tray → import TOML/tt → Connect.
4. Native Linux не подтягивает WebKitGTK. WebView dependencies проверяются на каждом distro baseline; отсутствие runtime показывает repair UI.
5. Все три install choices: modify installation, upgrade, rollback, частичное и полное удаление; отсутствие orphan service/firewall rules.
6. Закрытие/падение UI и переключение frontend не обрывают рабочий туннель и не снимают kill switch.
7. Один UID/SID — один активный controller; одновременный запуск двух frontend не вызывает конкурентную запись profile store.
8. IME, экранный диктор, keyboard-only, 125/150/200% scaling, multiple screens, locked KWallet и отсутствие tray проверяются на реальной ОС.
9. Подмена WebView assets/remote navigation/неразрешённый JS command отклоняются; обычный пользователь не получает machine privilege через installer repair path.

Native и WebView parity в import/export, profiles, Connect/Disconnect, error diagnostics и portal enrollment — release gate. Успех браузерного макета не закрывает ни один пункт реальной desktop-приёмки.
